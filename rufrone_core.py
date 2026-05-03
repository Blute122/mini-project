import asyncio
import websockets
import json
import os
import time
import socket

# --- CONFIGURATION ---
TARGET_PACKET_SIZE = 1024  # Layer 4: Constant Size
HEARTBEAT_INTERVAL = 0.15   # Layer 5: Constant Rate (10 packets per sec)
UI_PORT = 8080             # Local bridge port

# --- RELAY NODE CONFIGURATION ---
RELAY_IP = os.environ.get("RELAY_IP", "127.0.0.1")  # Your AWS Server IP (Set via environment variable or .env)
RELAY_PORT = int(os.environ.get("RELAY_PORT", 51820)) # The WireGuard listening port

# Set up the UDP network socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
message_queue = asyncio.Queue()

# --- LAYER 4: OBFUSCATION ENGINE (PADDING) ---
def pad_payload(data_bytes):
    """Pads real data with cryptographic noise to reach exactly 1024 bytes."""
    current_size = len(data_bytes)
    if current_size >= TARGET_PACKET_SIZE:
        return data_bytes[:TARGET_PACKET_SIZE]
    padding = os.urandom(TARGET_PACKET_SIZE - current_size)
    return data_bytes + padding

# --- LAYER 1: NETWORK INTERFACE (UDP SOCKET) ---
async def transmit_to_wireguard(packet_bytes, is_dummy=False):
    """Fires the 1024-byte packet over the internet to the AWS Relay."""
    packet_type = "DUMMY" if is_dummy else "REAL "
    
    # This is the line that actually sends the data across the internet!
    udp_socket.sendto(packet_bytes, (RELAY_IP, RELAY_PORT))
    
    print(f"[UDP OUT -> {RELAY_IP}:{RELAY_PORT}] [{packet_type}] Transmitting {len(packet_bytes)} bytes...")

# --- LAYER 5 & 6: CONSTANT BITRATE DAEMON ---
async def traffic_shaper_loop():
    print(f"[Core] Traffic Shaper Started. Target rate: 1 packet / {HEARTBEAT_INTERVAL}s")
    while True:
        try:
            real_message = await asyncio.wait_for(message_queue.get(), timeout=0.01)
            padded_packet = pad_payload(real_message.encode('utf-8'))
            await transmit_to_wireguard(padded_packet, is_dummy=False)
            message_queue.task_done()
        except asyncio.TimeoutError:
            dummy_packet = os.urandom(TARGET_PACKET_SIZE)
            await transmit_to_wireguard(dummy_packet, is_dummy=True)
            
        await asyncio.sleep(HEARTBEAT_INTERVAL)

# --- LOCAL BRIDGE: WEBSOCKET SERVER ---
async def handle_ui_connection(websocket):
    print("\n[Bridge] ✅ Web UI Connected successfully!")
    try:
        async for message in websocket:
            print(f"[Bridge] Received Encrypted Payload from UI: {message}")
            await message_queue.put(message)
            await websocket.send(json.dumps({"status": "queued"}))
    except websockets.exceptions.ConnectionClosed:
        print("\n[Bridge] ❌ Web UI Disconnected.")

# --- MAIN RUNNER ---
async def main():
    print("========================================")
    print(" RUFRONE CORE DAEMON - LIVE NETWORK TEST")
    print("========================================")
    server = await websockets.serve(handle_ui_connection, "localhost", UI_PORT)
    print(f"[Setup] Listening for Web UI on ws://localhost:{UI_PORT}")
    shaper_task = asyncio.create_task(traffic_shaper_loop())
    await asyncio.gather(server.wait_closed(), shaper_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Core] Shutting down Rufrone Core.")