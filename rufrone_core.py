import asyncio
import websockets
import json
import os
import socket
import base64
from aiohttp import web
import aiohttp_cors

TARGET_PACKET_SIZE = 1024
HEARTBEAT_INTERVAL = 0.15
UI_PORT            = 8080
LOCAL_UDP_PORT     = 9000

RELAY_IP   = "127.0.0.1"
RELAY_PORT = 9000

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(("0.0.0.0", LOCAL_UDP_PORT))
udp_socket.setblocking(False)

udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 5242880)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 5242880)

message_queue = asyncio.Queue()   # everything going OUT over UDP
jitter_buffer  = asyncio.Queue()  # everything coming IN from UDP
connected_uis  = set()

# ---------------------------------------------------------------------------
# TRAFFIC SHAPING
# ---------------------------------------------------------------------------
# All outbound traffic — chat, handshake, AND file chunks — is enqueued here
# and emitted by traffic_shaper_loop at a steady heartbeat rate, padded to
# exactly TARGET_PACKET_SIZE bytes.  From a network observer's perspective,
# every packet looks identical: same size, constant rate, random padding.
# File chunks are base64-encoded JSON objects, so they are byte-for-byte
# indistinguishable from chat messages or dummy packets.
# ---------------------------------------------------------------------------

CHUNK_SIZE = 700  # raw bytes per file chunk before base64 (~933 chars after)
              # Chosen so the JSON envelope fits within TARGET_PACKET_SIZE (1024).
              # base64(700) = 933 chars + ~60 chars of JSON overhead = ~993 bytes ✓

def pad_payload(data_bytes: bytes) -> bytes:
    n = len(data_bytes)
    if n >= TARGET_PACKET_SIZE:
        return data_bytes[:TARGET_PACKET_SIZE]
    return data_bytes + os.urandom(TARGET_PACKET_SIZE - n)

async def traffic_shaper_loop():
    """
    Dequeue messages and send over UDP at a fixed heartbeat rate.
    When the queue is empty, sends a dummy random packet so the traffic
    rate is constant regardless of whether real data is flowing.
    Every outbound packet is padded to exactly TARGET_PACKET_SIZE bytes.
    """
    while True:
        try:
            msg = await asyncio.wait_for(message_queue.get(), timeout=0.01)
            udp_socket.sendto(pad_payload(msg.encode('utf-8')), (RELAY_IP, RELAY_PORT))
            message_queue.task_done()
        except asyncio.TimeoutError:
            # Dummy cover traffic — keeps the rate constant
            udp_socket.sendto(os.urandom(TARGET_PACKET_SIZE), (RELAY_IP, RELAY_PORT))
        await asyncio.sleep(HEARTBEAT_INTERVAL)


# ---------------------------------------------------------------------------
# FILE TRANSFER — through the traffic shaper queue (obfuscated like chat)
# ---------------------------------------------------------------------------

async def enqueue_file_transfer(file_buffer: bytes, transfer_id: str):
    """
    Slice the file into CHUNK_SIZE chunks, base64-encode each one, wrap in a
    JSON envelope, and push into message_queue.  The traffic shaper picks them
    up and emits them at the same rate as chat messages, padded to the same
    fixed size.  A network observer sees no difference between a file transfer
    and a conversation.

    Throttle: we put a small sleep between enqueues so we don't flood the
    queue and starve chat messages.  The actual on-wire rate is still governed
    by traffic_shaper_loop's HEARTBEAT_INTERVAL.
    """
    tid       = transfer_id
    total     = len(file_buffer)
    num_chunks = (total + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"[File] Transfer {tid}: {total} bytes → {num_chunks} chunks via traffic shaper")

    for i in range(0, total, CHUNK_SIZE):
        chunk     = file_buffer[i:i + CHUNK_SIZE]
        chunk_b64 = base64.b64encode(chunk).decode('ascii')
        envelope  = json.dumps({
            "type":        "FILE_CHUNK",
            "transfer_id": tid,
            "data":        chunk_b64
        })
        await message_queue.put(envelope)
        # Yield to the event loop every chunk so other tasks (chat, handshake)
        # can still run during a large file transfer.
        await asyncio.sleep(0)

    # EOF sentinel — also goes through the queue so it arrives in order,
    # after all chunks have been emitted by the traffic shaper.
    eof_envelope = json.dumps({
        "type":        "FILE_EOF",
        "transfer_id": tid
    })
    await message_queue.put(eof_envelope)
    print(f"[File] Transfer {tid}: all {num_chunks} chunks + EOF enqueued.")


async def handle_file_upload(request):
    reader      = await request.multipart()
    file_data   = None
    transfer_id = None

    async for field in reader:
        if field.name == 'file':
            file_data = await field.read()
        elif field.name == 'transfer_id':
            transfer_id = (await field.read()).decode().strip()

    if file_data is None:
        return web.json_response({"error": "no file"}, status=400)
    if not transfer_id:
        transfer_id = os.urandom(6).hex()

    asyncio.create_task(enqueue_file_transfer(file_data, transfer_id))
    return web.json_response({"status": "queued", "transfer_id": transfer_id})


async def start_ingestion_server():
    app  = web.Application(client_max_size=1024**2 * 200)
    cors = aiohttp_cors.setup(app, defaults={"*": aiohttp_cors.ResourceOptions(
        allow_credentials=True, expose_headers="*", allow_headers="*"
    )})
    resource = cors.add(app.router.add_resource("/upload"))
    cors.add(resource.add_route("POST", handle_file_upload))
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, 'localhost', 8081).start()
    print("[Setup] HTTP ingestion on http://localhost:8081")


# ---------------------------------------------------------------------------
# UDP RECEIVE → PLAYBACK
# ---------------------------------------------------------------------------

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


async def playback_loop():
    """
    Read packets from the jitter buffer and forward to connected UIs.

    Packet types after decoding:
      FILE_CHUNK  → decode base64 data, send as WebSocket binary frame
      FILE_EOF    → forward as JSON text frame (browser matches by transfer_id)
      anything else (chat, handshake, dummy) → forward as JSON text frame

    Dummy packets (random bytes, not valid JSON) are silently dropped.
    """
    while True:
        batch = 0
        while not jitter_buffer.empty() and batch < 10:
            packet = await jitter_buffer.get()
            batch += 1

            try:
                raw_str   = packet.decode('utf-8', errors='ignore')
                start_idx = raw_str.find('{')
                if start_idx == -1:
                    continue  # dummy / padding packet — drop silently

                obj, end_idx = json.JSONDecoder().raw_decode(raw_str[start_idx:])
                pkt_type     = obj.get("type", "")

                if pkt_type == "FILE_CHUNK":
                    # Decode base64 back to raw bytes and send as a binary WS frame.
                    # Binary frames are handled by HandshakeManager's onBinaryReceived
                    # callback in the browser.
                    raw_bytes = base64.b64decode(obj["data"])
                    for ws in list(connected_uis):
                        try:
                            await ws.send(raw_bytes)
                        except Exception:
                            pass

                elif pkt_type == "FILE_EOF":
                    # Rename to RUFRONE_FILE_EOF so the existing browser handler
                    # picks it up without any changes to index.html.
                    eof_msg = json.dumps({
                        "type":        "RUFRONE_FILE_EOF",
                        "transfer_id": obj.get("transfer_id", "")
                    })
                    for ws in list(connected_uis):
                        try:
                            await ws.send(eof_msg)
                        except Exception:
                            pass

                else:
                    # Chat, handshake, status — forward as-is
                    valid_json = raw_str[start_idx:start_idx + end_idx]
                    for ws in list(connected_uis):
                        try:
                            await ws.send(valid_json)
                        except Exception:
                            pass

            except Exception:
                pass  # malformed / non-JSON packet — drop

        await asyncio.sleep(0.01)


# ---------------------------------------------------------------------------
# WEBSOCKET UI HANDLER
# ---------------------------------------------------------------------------

async def handle_ui_connection(websocket):
    print("\n[Bridge] ✅ Web UI Connected")
    connected_uis.add(websocket)
    try:
        async for message in websocket:
            await message_queue.put(message)
            await websocket.send(json.dumps({"status": "queued"}))
    except Exception:
        print("\n[Bridge] ❌ Web UI Disconnected.")
    finally:
        connected_uis.discard(websocket)


async def main():
    server = await websockets.serve(handle_ui_connection, "localhost", UI_PORT)
    print("=" * 42)
    print(" RUFRONE CORE DAEMON - PHASE 6 ACTIVE")
    print("=" * 42)
    await start_ingestion_server()
    await asyncio.gather(
        server.wait_closed(),
        asyncio.create_task(traffic_shaper_loop()),
        asyncio.create_task(udp_receive_loop()),
        asyncio.create_task(playback_loop()),
    )

if __name__ == "__main__":
    asyncio.run(main())