#!/usr/bin/env python3
import asyncio
import websockets
import json
import threading
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import base64
import ssl
import sys
import argparse
import time
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('proxy-client')

# Global WebSocket client connection
ws_client = None
ws_lock = threading.Lock()
connect_event = threading.Event()
running = True

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    
    def log_message(self, format, *args):
        if args[1] == '200':
            logger.debug(format % args)
        else:
            logger.info(format % args)
    
    def _read_request_body(self):
        """Read and return the request body based on Content-Length header"""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            return self.rfile.read(content_length)
        return None
    
    def _prepare_request_data(self, method):
        """Prepare the request data to be sent over WebSocket"""
        # Parse the URL
        url = self.path
        if not url.startswith('http'):
            host = self.headers.get('Host')
            if host:
                url = f"http://{host}{url}"
            else:
                self.send_error(400, "Missing Host header for non-absolute URL")
                return None
        
        # Read request body if present
        body = self._read_request_body()
        body_data = None
        
        if body:
            content_type = self.headers.get('Content-Type', '').lower()
            if 'application/json' in content_type:
                try:
                    # Try to parse as JSON for better handling
                    body_data = json.loads(body)
                except json.JSONDecodeError:
                    # If not valid JSON, send as base64 encoded string
                    body_data = base64.b64encode(body).decode('ascii')
            elif any(mime in content_type for mime in ['text/', 'application/xml', 'application/javascript']):
                # Handle text-based content types as strings
                try:
                    body_data = body.decode('utf-8')
                except UnicodeDecodeError:
                    body_data = base64.b64encode(body).decode('ascii')
            else:
                # For binary data, encode as base64
                body_data = base64.b64encode(body).decode('ascii')
        
        # Extract and process headers
        headers = {}
        for key, value in self.headers.items():
            # Skip hop-by-hop headers
            if key.lower() not in [
                'connection', 'keep-alive', 'proxy-authenticate', 
                'proxy-authorization', 'te', 'trailers', 
                'transfer-encoding', 'upgrade'
            ]:
                headers[key] = value
        
        # Construct the request data
        request_data = {
            'url': url,
            'method': method,
            'headers': headers,
            'payload': body_data,
            'is_base64': isinstance(body_data, str) and body and not any(
                mime in self.headers.get('Content-Type', '').lower() 
                for mime in ['application/json', 'text/', 'application/xml', 'application/javascript']
            )
        }
        
        return request_data
    
    async def _send_ws_request(self, request_data):
        """Send the request data through WebSocket and get response"""
        global ws_client
        with ws_lock:
            if not ws_client:
                raise ConnectionError("WebSocket connection not available")
            
            try:
                # Send the request data as JSON
                await ws_client.send(json.dumps(request_data))
                logger.debug(f"Sent request to {request_data['url']}")
                
                # Wait for response
                response_json = await ws_client.recv()
                return json.loads(response_json)
            except (websockets.exceptions.WebSocketException, json.JSONDecodeError) as e:
                logger.error(f"WebSocket communication error: {str(e)}")
                raise ConnectionError(f"WebSocket communication error: {str(e)}")
    
    def _handle_response(self, response_data):
        """Process and send the response back to the client"""
        if 'error' in response_data and 'status_code' not in response_data:
            self.send_error(502, f"Gateway Error: {response_data['error']}")
            return
        
        # Send status code
        status_code = response_data.get('status_code', 500)
        self.send_response(status_code)
        
        # Send headers
        hop_by_hop_headers = [
            'connection', 'keep-alive', 'proxy-authenticate', 
            'proxy-authorization', 'te', 'trailers', 
            'transfer-encoding', 'upgrade'
        ]
        
        for header, value in response_data.get('headers', {}).items():
            if header.lower() not in hop_by_hop_headers:
                self.send_header(header, value)
        
        self.end_headers()
        
        # Send body
        if 'body_base64' in response_data and response_data['body_base64']:
            # Handle base64 encoded binary response
            body_bytes = base64.b64decode(response_data['body_base64'])
            self.wfile.write(body_bytes)
        elif 'text' in response_data and response_data['text']:
            # Handle text response
            text_response = response_data['text']
            if isinstance(text_response, str):
                self.wfile.write(text_response.encode('utf-8'))
            else:
                self.wfile.write(str(text_response).encode('utf-8'))
    
    def do_METHOD(self, method):
        """Generic method handler for all HTTP methods"""
        # Check if WebSocket is connected
        if not connect_event.is_set():
            self.send_error(503, "WebSocket connection to server not available")
            return
        
        # Prepare request data
        request_data = self._prepare_request_data(method)
        if not request_data:
            return
        
        # Process the request through WebSocket
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            response_data = loop.run_until_complete(self._send_ws_request(request_data))
            self._handle_response(response_data)
        except ConnectionError as e:
            self.send_error(502, f"WebSocket gateway error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error handling {method} request: {str(e)}")
            self.send_error(500, f"Internal error: {str(e)}")
        finally:
            loop.close()
    
    # Implement all HTTP methods
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
    
    def do_CONNECT(self):
        """Handle CONNECT method for HTTPS tunneling - simplified implementation"""
        # For a complete implementation, this would establish a tunnel
        # But for simplicity, we'll just report it's not supported
        self.send_error(501, "HTTPS tunneling not yet supported")

async def websocket_client_task(server_url, retry_interval=5):
    """Maintain a persistent WebSocket connection to the server"""
    global ws_client, running
    
    while running:
        try:
            logger.info(f"Connecting to WebSocket server at {server_url}")
            async with websockets.connect(server_url) as websocket:
                # Update global connection
                with ws_lock:
                    ws_client = websocket
                    connect_event.set()
                
                logger.info("Connected to WebSocket server")
                
                # Keep connection alive until closed
                try:
                    while running:
                        # Ping to check connection
                        pong = await websocket.ping()
                        try:
                            await asyncio.wait_for(pong, timeout=10)
                            await asyncio.sleep(30)  # Wait between pings
                        except asyncio.TimeoutError:
                            logger.warning("Ping timeout, reconnecting...")
                            break
                except websockets.exceptions.ConnectionClosed as e:
                    logger.info(f"WebSocket connection closed: {e}")
                finally:
                    with ws_lock:
                        ws_client = None
                        connect_event.clear()
        
        except (websockets.exceptions.WebSocketException, 
                ConnectionRefusedError, OSError) as e:
            logger.error(f"WebSocket connection error: {e}")
            
            # Clear connection status
            with ws_lock:
                ws_client = None
                connect_event.clear()
            
            # Wait before retrying if still running
            if running:
                await asyncio.sleep(retry_interval)
        except Exception as e:
            logger.error(f"Unexpected WebSocket client error: {e}")
            if running:
                await asyncio.sleep(retry_interval)

def run_proxy_server(host, port, server_class=HTTPServer):
    """Run the HTTP proxy server"""
    server_address = (host, port)
    httpd = server_class(server_address, ProxyHTTPRequestHandler)
    logger.info(f"Starting proxy server on http://{host}:{port}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        logger.info("Proxy server stopped")

def signal_handler(sig, frame):
    """Handle termination signals"""
    global running
    logger.info("Shutting down...")
    running = False

def main():
    """Main entry point with command line argument parsing"""
    parser = argparse.ArgumentParser(description='WebSocket-based HTTP Proxy Client')
    parser.add_argument('--proxy-host', default='127.0.0.1', 
                        help='Proxy server host (default: 127.0.0.1)')
    parser.add_argument('--proxy-port', type=int, default=8080, 
                        help='Proxy server port (default: 8080)')
    parser.add_argument('--ws-server', required=True,
                        help='WebSocket server URL (ws://host:port)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Set log level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start WebSocket client in a separate thread
    ws_loop = asyncio.new_event_loop()
    ws_thread = threading.Thread(
        target=lambda: asyncio.set_event_loop(ws_loop) or 
                     ws_loop.run_until_complete(
                         websocket_client_task(args.ws_server)
                     ),
        daemon=True
    )
    ws_thread.start()
    
    # Run HTTP proxy server in main thread
    run_proxy_server(args.proxy_host, args.proxy_port)
    
    # Signal websocket client to stop
    global running
    running = False
    ws_loop.call_soon_threadsafe(ws_loop.stop)
    ws_thread.join(timeout=1)
    
    logger.info("Client shut down successfully")

if __name__ == "__main__":
    main()