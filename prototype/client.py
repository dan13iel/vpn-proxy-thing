# client.py

import asyncio
import websockets

async def send_commands():
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as websocket:
        print("Connected to server")
        while True:
            command = input("Enter command/data to send: ")
            await websocket.send(command)
            print(f"Sent: {command}")

if __name__ == "__main__":
    asyncio.run(send_commands())
