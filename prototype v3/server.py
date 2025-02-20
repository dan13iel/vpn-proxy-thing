# server.py
import asyncio
import websockets
import json
from collect import send_request

async def handle_connection(websocket):
    print("Client connected")
    try:
        async for message in websocket:
            print(f"Received request data of length: {len(message)}")
            try:
                # Parse the JSON request data
                request_data = json.loads(message)
                print(f"Processing request to: {request_data.get('url', 'unknown')}")
                
                # Process the request using the collect module
                response_data = send_request(request_data)
                
                # Send back the response
                await websocket.send(json.dumps(response_data))
                print(f"Sent response with status: {response_data.get('status_code', 'error')}")
            except json.JSONDecodeError:
                error_response = {"error": "Invalid JSON format"}
                await websocket.send(json.dumps(error_response))
            except Exception as e:
                error_response = {"error": str(e)}
                await websocket.send(json.dumps(error_response))
    except websockets.ConnectionClosed:
        print("Client disconnected")

async def main():
    server_host = "0.0.0.0"  # Listen on all interfaces
    server_port = 8765
    async with websockets.serve(handle_connection, server_host, server_port):
        print(f"WebSocket server started on ws://{server_host}:{server_port}")
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())

# client_proxy.py
import asyncio
import websockets
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import socket
import ssl
from io import BytesIO

# Global WebSocket client
ws_client = None
ws_lock = threading.Lock()
connect_event = threading.Event()

# WebSocket client connection function
async def maintain_websocket_connection():
    global ws_client
    server_address = "ws://your-server-address:8765"  # Change to your server address
    
    while True:
        try:
            async with websockets.connect(server_address) as websocket:
                with ws_lock:
                    ws_client = websocket
                    connect_event.set()
                
                print(f"Connected to WebSocket server at {server_address}")
                
                # Keep the connection alive until it's closed
                try:
                    await websocket.wait_closed()
                finally:
                    with ws_lock:
                        ws_client = None
                        connect_event.clear()
                    print("Disconnected from WebSocket server")
        
        except (websockets.exceptions.WebSocketException, 
                ConnectionRefusedError, OSError) as e:
            print(f"WebSocket connection error: {e}")
            # Clear connection status
            with ws_lock:
                ws_client = None
                connect_event.clear()
            
            # Wait before retrying
            await asyncio.sleep(5)

# HTTP Proxy Handler
class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    
    def do_METHOD(self, method):
        # Wait for WebSocket connection
        if not connect_event.is_set():
            self.send_error(503, "WebSocket connection not available")
            return
            
        url = self.path
        if not url.startswith('http'):
            url = f"http://{self.headers['Host']}{url}"
        
        # Read request body if present
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None
        
        # Prepare the request data
        request_data = {
            'url': url,
            'method': method,
            'headers': dict(self.headers),
            'payload': body.decode('utf-8') if body else None
        }
        
        # Remove hop-by-hop headers
        hop_by_hop_headers = ['connection', 'keep-alive', 'proxy-authenticate', 
                              'proxy-authorization', 'te', 'trailers', 
                              'transfer-encoding', 'upgrade']
        for header in hop_by_hop_headers:
            request_data['headers'].pop(header, None)
        
        # Send request through WebSocket
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            response_data = loop.run_until_complete(self._send_ws_request(request_data))
            
            # Process the response
            self.send_response(response_data.get('status_code', 500))
            
            # Send headers
            for header, value in response_data.get('headers', {}).items():
                if header.lower() not in hop_by_hop_headers:
                    self.send_header(header, value)
            self.end_headers()
            
            # Send body
            response_body = response_data.get('text', '')
            if response_body:
                self.wfile.write(response_body.encode('utf-8'))
                
        except Exception as e:
            self.send_error(502, f"Error processing request: {str(e)}")
        finally:
            loop.close()

    async def _send_ws_request(self, request_data):
        global ws_client
        with ws_lock:
            if not ws_client:
                raise ConnectionError("WebSocket connection not available")
            try:
                await ws_client.send(json.dumps(request_data))
                response = await ws_client.recv()
                return json.loads(response)
            except Exception as e:
                raise ConnectionError(f"WebSocket communication error: {str(e)}")

    def do_GET(self):
        self.do_METHOD('GET')

    def do_POST(self):
        self.do_METHOD('POST')

    def do_PUT(self):
        self.do_METHOD('PUT')

    def do_DELETE(self):
        self.do_METHOD('DELETE')

    def do_HEAD(self):
        self.do_METHOD('HEAD')

    def do_OPTIONS(self):
        self.do_METHOD('OPTIONS')

    def do_PATCH(self):
        self.do_METHOD('PATCH')

# Start the proxy server
def start_proxy_server(port=8080):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, ProxyHTTPRequestHandler)
    print(f"Starting proxy server on http://127.0.0.1:{port}")
    httpd.serve_forever()

# Main function to start everything
def main():
    # Start WebSocket client in a separate thread
    loop = asyncio.new_event_loop()
    ws_thread = threading.Thread(
        target=lambda: asyncio.set_event_loop(loop) or 
                      loop.run_until_complete(maintain_websocket_connection()),
        daemon=True
    )
    ws_thread.start()
    
    # Start the HTTP proxy server
    try:
        start_proxy_server()
    except KeyboardInterrupt:
        print("Shutting down proxy server")
    finally:
        # Clean shutdown
        loop.call_soon_threadsafe(loop.stop)
        ws_thread.join(timeout=1)

if __name__ == "__main__":
    main()