# client.py

import json
import asyncio
import websockets

websocketUrl = "ws://localhost:8765"


def package_url(url): # url to json
    data = {
        "method": "GET",
        "url": url
    }

    return json.dumps(data)

async def send_commands():
    async with websockets.connect(websocketUrl) as websocket:
        print("Connected to server")
        while True:
            url = input("Enter URL in 'proto://uri' format:\n>> ")
            jsonData = package_url(url)

            await websocket.send(jsonData)

            print(f"Sent:\n{jsonData}\n")

            response = await websocket.recv()
            print(f"Received from server: {response}")

if __name__ == "__main__":
    asyncio.run(send_commands())
