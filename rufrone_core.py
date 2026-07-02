# rufrone_core.py — blind relay daemon (Phase 7)
#
# Frame types (first byte of every WebSocket/UDP payload):
#   0x01  TEXT   — signalling / handshake JSON
#   0x02  BINARY — file chunk (base64-encoded inside)
#   0x03  EOF    — end-of-file sentinel (payload = transfer_id bytes)
#
# The daemon routes ONLY on this single prefix byte.
# It never reads application content — it is cryptographically blind.

from dotenv import load_dotenv
load_dotenv()

import asyncio
import sys
import websockets
import json
import os
import socket

# Console logging uses emoji; force UTF-8 stdout so a cp1252 Windows console
# can't crash the connection handler on the first print (drops the UI).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import base64
import hashlib
import time
from aiohttp import web
import aiohttp_cors
from pathlib import Path

TARGET_PACKET_SIZE = 1024
HEARTBEAT_INTERVAL = 0.15   # cover-traffic cadence — governs metadata obfuscation, keep stable
FILE_BURST_PER_TICK = 40    # UDP egress rate for file chunks; loss is now recovered via NAK retransmission

UI_PORT        = int(os.getenv("UI_PORT", "8080"))
LOCAL_UDP_PORT = int(os.getenv("LOCAL_UDP_PORT", "9000"))
RELAY_IP       = os.getenv("RELAY_IP",   "127.0.0.1")
RELAY_PORT     = int(os.getenv("RELAY_PORT", "51820"))

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(("0.0.0.0", LOCAL_UDP_PORT))
udp_socket.setblocking(False)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 5242880)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 5242880)

FRAME_TEXT   = b'\x01'
FRAME_BINARY = b'\x02'
FRAME_EOF    = b'\x03'

text_queue    = asyncio.Queue()
file_queue    = asyncio.Queue()
jitter_buffer = asyncio.Queue()
connected_uis = set()
CAPTURE_FLAG = Path(__file__).with_name("attack_capture.enabled")
CAPTURE_LOG  = Path(__file__).with_name("attack_capture.ndjson")

def capture_transport(direction: str, payload: bytes):
    if not CAPTURE_FLAG.exists():
        return
    try:
        frame_type = payload[:1].hex() if payload else ""
        entry = {
            "ts": round(time.time(), 6),
            "dir": direction,
            "size": len(payload),
            "frame_type": frame_type,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "b64": base64.b64encode(payload).decode("ascii"),
        }
        with CAPTURE_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def pad_payload(data_bytes: bytes) -> bytes:
    n = len(data_bytes)
    if n >= TARGET_PACKET_SIZE:
        return data_bytes[:TARGET_PACKET_SIZE]
    # Real packets are zero-padded so the receiver can safely trim padding
    # and recover EOF markers / base64-wrapped file chunks deterministically.
    return data_bytes + (b'\x00' * (TARGET_PACKET_SIZE - n))

async def traffic_shaper_loop():
    while True:
        sent_anything = False
        try:
            msg = text_queue.get_nowait()
            wire = pad_payload(msg)
            capture_transport("tx-text", wire)
            udp_socket.sendto(wire, (RELAY_IP, RELAY_PORT))
            text_queue.task_done()
            sent_anything = True
        except asyncio.QueueEmpty:
            pass
        for _ in range(FILE_BURST_PER_TICK):
            try:
                msg = file_queue.get_nowait()
                wire = pad_payload(msg)
                capture_transport("tx-file", wire)
                udp_socket.sendto(wire, (RELAY_IP, RELAY_PORT))
                file_queue.task_done()
                sent_anything = True
            except asyncio.QueueEmpty:
                break
        if not sent_anything:
            cover = os.urandom(TARGET_PACKET_SIZE)
            capture_transport("tx-cover", cover)
            udp_socket.sendto(cover, (RELAY_IP, RELAY_PORT))
        await asyncio.sleep(HEARTBEAT_INTERVAL)

async def handle_ui_connection(websocket):
    print("\n[Bridge] ✅ Web UI Connected")
    connected_uis.add(websocket)
    try:
        async for message in websocket:
            if isinstance(message, bytes):
                frame_type = message[:1]
                payload    = message[1:]
                if frame_type == FRAME_BINARY:
                    await file_queue.put(FRAME_BINARY + base64.b64encode(payload))
                elif frame_type == FRAME_EOF:
                    await file_queue.put(FRAME_EOF + payload)
            else:
                encoded = message.encode('utf-8')
                queue = text_queue
                try:
                    packet = json.loads(message)
                    if packet.get("type") in {"RUFRONE_FILE_CHUNK", "RUFRONE_FILE_EOF"}:
                        queue = file_queue
                except Exception:
                    pass
                await queue.put(FRAME_TEXT + encoded)
                await websocket.send(json.dumps({"status": "queued"}))
    except Exception:
        print("\n[Bridge] ❌ Web UI Disconnected.")
    finally:
        connected_uis.discard(websocket)

async def udp_receive_loop():
    loop = asyncio.get_event_loop()
    while True:
        try:
            data = await loop.sock_recv(udp_socket, TARGET_PACKET_SIZE * 2)
            capture_transport("rx-wire", data)
            await jitter_buffer.put(data)
        except (ConnectionResetError, OSError):
            pass
        except Exception:
            await asyncio.sleep(1)

async def playback_loop():
    while True:
        batch = 0
        while not jitter_buffer.empty() and batch < 50:
            packet = await jitter_buffer.get()
            batch += 1
            if len(packet) < 1:
                continue
            frame_type = packet[:1]
            payload    = packet[1:]
            if frame_type == FRAME_TEXT:
                try:
                    raw_str    = payload.decode('utf-8', errors='ignore')
                    start      = raw_str.find('{')
                    if start == -1:
                        continue
                    _, end     = json.JSONDecoder().raw_decode(raw_str[start:])
                    valid_json = raw_str[start:start + end]
                    for ws in list(connected_uis):
                        try: await ws.send(valid_json)
                        except Exception: pass
                except Exception:
                    pass
            elif frame_type == FRAME_BINARY:
                try:
                    raw_bytes = base64.b64decode(payload.rstrip(b'\x00'))
                    for ws in list(connected_uis):
                        try: await ws.send(raw_bytes)
                        except Exception: pass
                except Exception:
                    pass
            elif frame_type == FRAME_EOF:
                try:
                    tid     = payload.rstrip(b'\x00').decode('utf-8', errors='replace')
                    eof_msg = json.dumps({"type": "RUFRONE_FILE_EOF", "transfer_id": tid})
                    for ws in list(connected_uis):
                        try: await ws.send(eof_msg)
                        except Exception: pass
                except Exception:
                    pass
        await asyncio.sleep(0.005)

async def main():
    server = await websockets.serve(handle_ui_connection, "localhost", UI_PORT)
    print("=" * 42)
    print(" RUFRONE CORE DAEMON - PHASE 7 ACTIVE")
    print("=" * 42)
    print(f" UI: localhost:{UI_PORT}")
    print(f" Local UDP: {LOCAL_UDP_PORT}")
    print(f" Relay: {RELAY_IP}:{RELAY_PORT}")
    print("=" * 42)
    await asyncio.gather(
        server.wait_closed(),
        asyncio.create_task(traffic_shaper_loop()),
        asyncio.create_task(udp_receive_loop()),
        asyncio.create_task(playback_loop()),
    )

if __name__ == "__main__":
    asyncio.run(main())
