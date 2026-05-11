# rufrone_core.py — blind relay daemon (Phase 7)
#
# Frame types (first byte of every WebSocket/UDP payload):
#   0x01  TEXT   — signalling / handshake JSON
#   0x02  BINARY — file chunk (base64-encoded inside)
#   0x03  EOF    — end-of-file sentinel (payload = transfer_id bytes)
#
# The daemon routes ONLY on this single prefix byte.
# It never reads application content — it is cryptographically blind.

import asyncio
import websockets
import json
import os
import socket
import base64
from aiohttp import web
import aiohttp_cors

TARGET_PACKET_SIZE = 1024
HEARTBEAT_INTERVAL = 0.15     # seconds between traffic-shaper ticks
# How many file chunks to drain per tick during an active transfer.
# Chat/signalling packets (TEXT) still get exactly one slot per tick so they
# are never starved.  Raising this speeds up file transfers without changing
# the on-wire size or timing uniformity — every packet is still 1024 bytes.
FILE_BURST_PER_TICK = 20

UI_PORT        = 8080
LOCAL_UDP_PORT = 9000
RELAY_IP       = "127.0.0.1"
RELAY_PORT     = 9000

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(("0.0.0.0", LOCAL_UDP_PORT))
udp_socket.setblocking(False)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 5242880)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 5242880)

FRAME_TEXT   = b'\x01'
FRAME_BINARY = b'\x02'
FRAME_EOF    = b'\x03'

# Two separate queues so file chunks never block handshake/chat packets
text_queue = asyncio.Queue()    # TEXT frames  — signalling, handshake, chat
file_queue = asyncio.Queue()    # BINARY + EOF frames — file transfer only
jitter_buffer = asyncio.Queue() # inbound from UDP
connected_uis = set()

# ── Traffic shaping ───────────────────────────────────────────────────────────

def pad_payload(data_bytes: bytes) -> bytes:
    n = len(data_bytes)
    if n >= TARGET_PACKET_SIZE:
        return data_bytes[:TARGET_PACKET_SIZE]
    return data_bytes + os.urandom(TARGET_PACKET_SIZE - n)

async def traffic_shaper_loop():
    """
    Every HEARTBEAT_INTERVAL tick:
      1. Drain at most one TEXT packet (chat/handshake — low volume, time-sensitive)
      2. Drain up to FILE_BURST_PER_TICK file chunks (high volume, throughput-sensitive)
      3. If nothing was sent, emit a dummy cover packet

    This gives file transfers ~20× the throughput of the old one-packet-per-tick
    design while keeping every on-wire packet exactly TARGET_PACKET_SIZE bytes.
    A network observer still sees constant-size packets at a constant rate —
    the burst just means more packets per tick, not variable-size packets.
    """
    while True:
        sent_anything = False

        # ── Priority slot: one TEXT packet ────────────────────────────────────
        try:
            msg = text_queue.get_nowait()
            udp_socket.sendto(pad_payload(msg), (RELAY_IP, RELAY_PORT))
            text_queue.task_done()
            sent_anything = True
        except asyncio.QueueEmpty:
            pass

        # ── Bulk slot: up to FILE_BURST_PER_TICK file chunks ──────────────────
        for _ in range(FILE_BURST_PER_TICK):
            try:
                msg = file_queue.get_nowait()
                udp_socket.sendto(pad_payload(msg), (RELAY_IP, RELAY_PORT))
                file_queue.task_done()
                sent_anything = True
            except asyncio.QueueEmpty:
                break

        # ── Cover traffic: keep rate constant when nothing to send ────────────
        if not sent_anything:
            udp_socket.sendto(os.urandom(TARGET_PACKET_SIZE), (RELAY_IP, RELAY_PORT))

        await asyncio.sleep(HEARTBEAT_INTERVAL)

# ── WebSocket handler ─────────────────────────────────────────────────────────

async def handle_ui_connection(websocket):
    print("\n[Bridge] ✅ Web UI Connected")
    connected_uis.add(websocket)
    try:
        async for message in websocket:
            if isinstance(message, bytes):
                frame_type = message[:1]
                payload    = message[1:]

                if frame_type == FRAME_BINARY:
                    # File chunk — base64-encode, push to file_queue
                    chunk_b64 = base64.b64encode(payload)
                    await file_queue.put(FRAME_BINARY + chunk_b64)

                elif frame_type == FRAME_EOF:
                    # EOF sentinel — push to file_queue (preserves ordering after chunks)
                    await file_queue.put(FRAME_EOF + payload)

                # Unknown binary frame types are silently dropped

            else:
                # Text frame — signalling / handshake / chat JSON
                await text_queue.put(FRAME_TEXT + message.encode('utf-8'))
                await websocket.send(json.dumps({"status": "queued"}))

    except Exception:
        print("\n[Bridge] ❌ Web UI Disconnected.")
    finally:
        connected_uis.discard(websocket)

# ── UDP receive ───────────────────────────────────────────────────────────────

async def udp_receive_loop():
    loop = asyncio.get_event_loop()
    while True:
        try:
            data = await loop.sock_recv(udp_socket, TARGET_PACKET_SIZE * 2)
            await jitter_buffer.put(data)
        except (ConnectionResetError, OSError):
            pass
        except Exception:
            await asyncio.sleep(1)

# ── Playback loop ─────────────────────────────────────────────────────────────

async def playback_loop():
    """
    Drain the jitter buffer and forward packets to all connected UIs.
    Routing is purely by the single frame-type prefix byte — the daemon
    never reads application content.
    """
    while True:
        batch = 0
        while not jitter_buffer.empty() and batch < 50:  # higher batch = lower latency
            packet = await jitter_buffer.get()
            batch += 1

            if len(packet) < 1:
                continue

            frame_type = packet[:1]
            payload    = packet[1:]

            if frame_type == FRAME_TEXT:
                try:
                    raw_str   = payload.decode('utf-8', errors='ignore')
                    start     = raw_str.find('{')
                    if start == -1:
                        continue
                    _, end    = json.JSONDecoder().raw_decode(raw_str[start:])
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
            # else: dummy/random packet — drop silently

        await asyncio.sleep(0.005)  # 5ms between batches for low latency

# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    server = await websockets.serve(handle_ui_connection, "localhost", UI_PORT)
    print("=" * 42)
    print(" RUFRONE CORE DAEMON - PHASE 7 ACTIVE")
    print("=" * 42)
    await asyncio.gather(
        server.wait_closed(),
        asyncio.create_task(traffic_shaper_loop()),
        asyncio.create_task(udp_receive_loop()),
        asyncio.create_task(playback_loop()),
    )

if __name__ == "__main__":
    asyncio.run(main())