# server.py

import asyncio
import websockets

async def handle_connection(websocket, path):
    print("Client connected")
    try:
        async for message in websocket:
            print(f"Received message: {message}")
    except websockets.ConnectionClosed:
        print("Client disconnected")

async def main():
    async with websockets.serve(handle_connection, "localhost", 8765):
        print("WebSocket server started on ws://localhost:8765")
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())
