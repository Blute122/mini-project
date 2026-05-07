import asyncio
import websockets
import json
import os
import socket
from aiohttp import web
import aiohttp_cors

TARGET_PACKET_SIZE = 1024  
HEARTBEAT_INTERVAL = 0.15   
UI_PORT = 8080             
LOCAL_UDP_PORT = 9000 

# SET TO LOOPBACK FOR LOCAL BROWSER TABS TESTING
RELAY_IP = "127.0.0.1"  
RELAY_PORT = 9000 

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(("0.0.0.0", LOCAL_UDP_PORT))
udp_socket.setblocking(False)

# THE OS BUFFER FIX: 5MB to prevent Windows UDP packet drops
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 5242880)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 5242880)

message_queue = asyncio.Queue()
jitter_buffer = asyncio.Queue()
connected_uis = set()

def pad_payload(data_bytes):
    current_size = len(data_bytes)
    if current_size >= TARGET_PACKET_SIZE: return data_bytes[:TARGET_PACKET_SIZE]
    return data_bytes + os.urandom(TARGET_PACKET_SIZE - current_size)

async def transmit_to_wireguard(packet_bytes, is_dummy=False):
    udp_socket.sendto(packet_bytes, (RELAY_IP, RELAY_PORT))

# PHASE 6: RATE-LIMITED FILE TRANSFER
async def background_file_transfer(file_buffer):
    print(f"\n[File] Starting QoS-throttled transfer of {len(file_buffer)} bytes...")
    
    chunk_size = 1024  
    throttle_delay = 0.02 # 20ms delay is a perfect, steady pace
    marker = b"RUFRONE_FILE:" 

    for i in range(0, len(file_buffer), chunk_size):
        chunk = file_buffer[i:i + chunk_size]
        udp_socket.sendto(marker + chunk, (RELAY_IP, RELAY_PORT))
        await asyncio.sleep(throttle_delay)
        
    print("[File] Complete. Bandwidth returned to idle.")

async def handle_file_upload(request):
    reader = await request.multipart()
    field = await reader.next()
    file_data = await field.read()
    asyncio.create_task(background_file_transfer(file_data))
    return web.json_response({"status": "Transfer queued."})

async def start_ingestion_server():
    app = web.Application(client_max_size=1024**2 * 50)
    cors = aiohttp_cors.setup(app, defaults={"*": aiohttp_cors.ResourceOptions(allow_credentials=True, expose_headers="*", allow_headers="*")})
    resource = cors.add(app.router.add_resource("/upload"))
    cors.add(resource.add_route("POST", handle_file_upload))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8081)
    await site.start()
    print("[Setup] Local HTTP File Ingestion listening on http://localhost:8081")

async def traffic_shaper_loop():
    while True:
        try:
            real_message = await asyncio.wait_for(message_queue.get(), timeout=0.01)
            await transmit_to_wireguard(pad_payload(real_message.encode('utf-8')), False)
            message_queue.task_done()
        except asyncio.TimeoutError:
            await transmit_to_wireguard(os.urandom(TARGET_PACKET_SIZE), True)
        await asyncio.sleep(HEARTBEAT_INTERVAL)

async def udp_receive_loop():
    loop = asyncio.get_event_loop()
    while True:
        try:
            data = await loop.sock_recv(udp_socket, 51200) 
            await jitter_buffer.put(data)
        except (ConnectionResetError, OSError): pass
        except Exception: await asyncio.sleep(1)

async def playback_loop():
    while True:
        # THE WEBSOCKET FLOOD FIX: Only process 10 packets per tick!
        batch_count = 0
        while not jitter_buffer.empty() and batch_count < 10:
            packet = await jitter_buffer.get()
            batch_count += 1
            
            if packet.startswith(b"RUFRONE_FILE:"):
                for ws in list(connected_uis):
                    try: await ws.send(packet[13:]) 
                    except: pass
            else:
                try:
                    raw_str = packet.decode('utf-8', errors='ignore')
                    start_idx = raw_str.find('{')
                    if start_idx != -1:
                        obj, end_idx = json.JSONDecoder().raw_decode(raw_str[start_idx:])
                        valid_json_str = raw_str[start_idx:start_idx+end_idx]
                        for ws in list(connected_uis):
                            try: await ws.send(valid_json_str)
                            except: pass
                except: pass 
                
        # Give the browser 10ms to process the batch before sending more
        await asyncio.sleep(0.01)

async def handle_ui_connection(websocket):
    print("\n[Bridge] ✅ Web UI Connected")
    connected_uis.add(websocket)
    try:
        async for message in websocket:
            await message_queue.put(message)
            await websocket.send(json.dumps({"status": "queued"}))
    except:
        print("\n[Bridge] ❌ Web UI Disconnected.")
    finally:
        connected_uis.discard(websocket)

async def main():
    server = await websockets.serve(handle_ui_connection, "localhost", UI_PORT)
    print("========================================")
    print(" RUFRONE CORE DAEMON - PHASE 6 ACTIVE")
    print("========================================")
    await start_ingestion_server()
    await asyncio.gather(server.wait_closed(), asyncio.create_task(traffic_shaper_loop()), asyncio.create_task(udp_receive_loop()), asyncio.create_task(playback_loop()))

if __name__ == "__main__":
    asyncio.run(main())