# server.py

import asyncio
import websockets
import random

async def handle_connection(websocket):
    print("Client connected")
    try:
        async for message in websocket:
            print(f"Received message: {message}")
            random_number = random.randint(1, 100)
            print(f"Generated random number: {random_number}")
            response = f"{message} | Random number: {random_number}"
            await websocket.send(response)
    except websockets.ConnectionClosed:
        print("Client disconnected")

async def main():
    async with websockets.serve(handle_connection, "localhost", 8765):
        print("WebSocket server started on ws://localhost:8765")
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())
