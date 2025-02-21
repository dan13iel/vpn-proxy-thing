# server.py
# This is not the final code.
# This is a simpilfied version that is going to run to test the UI and to quickly prototype new high level features.

import json
import asyncio
import websockets
import random
import requests

def validateJSON(jsonData):
    try:
        json.loads(jsonData)
    except ValueError as err:
        return False
    return True

def send_request(jsonData):
    if not validateJSON(jsonData):
        return None, "002" # error code, no need for exceptions

    data = json.loads(jsonData)
    # error handling, basically checks if needs for the server are met.
    if not None in [data.get("method"), data.get("url")]:
        # If either method or url does not exist, then it will be none, so if added to a list of can do a 'bulk' AND operation
        method = data.get("method")
        url = data.get("url")
        if not method in ["GET", "POST"]:
            return None, "003" # error code, no need for exceptions
        try:
            responceData =  requests.request(method, url)
        except Exception as e:
            return None, "000-".join(str(e)) # error code



    else: return None, "001" # error code, no need for exceptions

    

def package_res(responce):
    data = {
        "status_code": responce.status_code,
        # TODO: add headers
        "data": responce.text
    }

    return json.dumps(data)

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
