#!/usr/bin/env python3
import asyncio
import websockets
import json
import logging
import argparse
import base64
import signal
import requests
from requests.exceptions import RequestException, Timeout, TooManyRedirects
import sys
import time
import uuid
import socket
import ssl
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('proxy-server')

# Global flags and state
running = True
active_tunnels = {}  # Store active tunnels: {tunnel_id: TunnelState}

class TunnelState:
    """Class to manage the state of an active tunnel"""
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.reader = None
        self.writer = None
        self.relay_task = None
        self.lock = asyncio.Lock()
        self.closing = False
    
    async def setup(self):
        """Establish the connection to the target server"""
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port)
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}:{self.port} - {e}")
            return False
    
    async def close(self):
        """Close the tunnel connection cleanly"""
        async with self.lock:
            if self.closing:
                return
            self.closing = True
            
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as e:
                logger.debug(f"Error closing writer: {e}")
        
        # Cancel relay task if active
        if self.relay_task and not self.relay_task.done():
            self.relay_task.cancel()
            try:
                await self.relay_task
            except asyncio.CancelledError:
                pass

async def handle_tunnel_data(websocket, tunnel_id, data_b64):
    """Handle data from client to forward to tunnel target"""
    if tunnel_id not in active_tunnels:
        logger.warning(f"Received data for non-existent tunnel: {tunnel_id}")
        return {'error': 'Tunnel not found', 'tunnel_id': tunnel_id}
    
    tunnel = active_tunnels[tunnel_id]
    try:
        # Decode data
        data = base64.b64decode(data_b64)
        
        # Send to target server
        tunnel.writer.write(data)
        await tunnel.writer.drain()
        return None  # No immediate response needed
    except Exception as e:
        logger.error(f"Error forwarding data to tunnel {tunnel_id}: {e}")
        return {'error': str(e), 'tunnel_id': tunnel_id, 'action': 'close'}

async def start_tunnel_relay(websocket, tunnel_id):
    """Start relay task for server->client direction"""
    if tunnel_id not in active_tunnels:
        return

    tunnel = active_tunnels[tunnel_id]
    
    try:
        buffer_size = 8192
        while True:
            try:
                # Read from target server
                data = await tunnel.reader.read(buffer_size)
                if not data:
                    logger.debug(f"Tunnel {tunnel_id} remote server closed connection")
                    break
                
                # Send to client via WebSocket
                response = {
                    'tunnel_id': tunnel_id,
                    'data': base64.b64encode(data).decode('ascii')
                }
                await websocket.send(json.dumps(response))
            except asyncio.CancelledError:
                logger.debug(f"Tunnel relay {tunnel_id} was cancelled")
                break
            except Exception as e:
                logger.error(f"Error in tunnel relay {tunnel_id}: {e}")
                break
    finally:
        # Close tunnel when relay ends
        await close_tunnel(websocket, tunnel_id)

async def setup_tunnel(websocket, request_data):
    """Set up an HTTPS tunnel"""
    host = request_data.get('tunnel_host')
    port = request_data.get('tunnel_port')
    
    if not host or not port:
        logger.error("Missing tunnel host or port in CONNECT request")
        return {'status': 'error', 'error': 'Missing tunnel host or port'}
    
    # Generate a unique tunnel ID
    tunnel_id = str(uuid.uuid4())
    
    # Create tunnel state
    tunnel = TunnelState(host, port)
    
    # Connect to the target server
    connected = await tunnel.setup()
    if not connected:
        return {'status': 'error', 'error': f"Failed to connect to {host}:{port}"}
    
    # Store the tunnel
    active_tunnels[tunnel_id] = tunnel
    
    # Start relay task for server->client direction
    tunnel.relay_task = asyncio.create_task(start_tunnel_relay(websocket, tunnel_id))
    
    logger.info(f"Tunnel {tunnel_id} established to {host}:{port}")
    return {'status': 'connected', 'tunnel_id': tunnel_id}

async def close_tunnel(websocket, tunnel_id):
    """Close an active tunnel"""
    if tunnel_id in active_tunnels:
        tunnel = active_tunnels[tunnel_id]
        
        # Close the connection
        await tunnel.close()
        
        # Remove from active tunnels
        del active_tunnels[tunnel_id]
        
        # Notify client
        try:
            close_msg = {
                'tunnel_id': tunnel_id,
                'action': 'close'
            }
            await websocket.send(json.dumps(close_msg))
        except Exception as e:
            logger.debug(f"Failed to send tunnel close notification: {e}")
        
        logger.info(f"Tunnel {tunnel_id} closed")

async def handle_request(request_data):
    """Process HTTP request and return response"""
    # Check if this is a CONNECT tunnel request
    if request_data.get('method') == 'CONNECT' and 'tunnel_host' in request_data:
        return None  # Tunnel requests are handled separately
    
    # Extract request parameters
    url = request_data.get('url')
    if not url:
        logger.error("Missing URL in request data")
        return {'error': 'URL is required'}
    
    method = request_data.get('method', 'GET').upper()
    headers = request_data.get('headers', {})
    params = request_data.get('params', {})
    timeout = request_data.get('timeout', 30)  # Default 30 second timeout
    
    # Handle payload - check if it's base64 encoded
    payload = request_data.get('payload')
    is_base64 = request_data.get('is_base64', False)
    
    if payload and is_base64:
        try:
            payload = base64.b64decode(payload)
        except Exception as e:
            logger.error(f"Failed to decode base64 payload: {e}")
            return {'error': f'Base64 decode error: {str(e)}'}
    
    # Prepare request parameters
    request_kwargs = {
        'method': method,
        'url': url,
        'headers': headers,
        'params': params,
        'timeout': timeout,
    }
    
    # Add payload based on content-type
    if payload is not None:
        content_type = headers.get('Content-Type', '').lower()
        
        if isinstance(payload, dict) and 'application/json' in content_type:
            request_kwargs['json'] = payload
        else:
            request_kwargs['data'] = payload
    
    # Execute request
    try:
        logger.info(f"Sending {method} request to {url}")
        start_time = time.time()
        response = await asyncio.get_event_loop().run_in_executor(
            None, lambda: requests.request(**request_kwargs)
        )
        elapsed = time.time() - start_time
        logger.info(f"Received response: {response.status_code} in {elapsed:.2f}s")
        
        # Handle binary responses
        content_type = response.headers.get('Content-Type', '').lower()
        is_binary = not any(text_type in content_type for text_type in [
            'text/', 'application/json', 'application/javascript', 'application/xml'
        ])
        
        # Build response data
        response_data = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'url': response.url,
        }
        
        # Handle response body based on content type
        if is_binary:
            response_data['body_base64'] = base64.b64encode(response.content).decode('ascii')
        else:
            response_data['text'] = response.text
            if 'application/json' in content_type:
                try:
                    response_data['json'] = response.json()
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse JSON response from {url}")
        
        return response_data
        
    except Timeout:
        logger.error(f"Request timed out: {url}")
        return {'error': 'Request timed out', 'status_code': 504}
    
    except TooManyRedirects:
        logger.error(f"Too many redirects: {url}")
        return {'error': 'Too many redirects', 'status_code': 310}
    
    except RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        return {'error': str(e), 'status_code': 502}
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {'error': f'Unexpected error: {str(e)}', 'status_code': 500}

async def handle_client_connection(websocket):
    """Handle WebSocket client connection"""
    client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    logger.info(f"Client connected from {client_info}")
    
    # Track tunnels opened by this client
    client_tunnels = set()
    
    try:
        async for message in websocket:
            try:
                # Parse request data from JSON
                request_data = json.loads(message)
                
                # Check if this is a tunnel message
                if 'tunnel_id' in request_data:
                    tunnel_id = request_data['tunnel_id']
                    
                    # Check for tunnel close request
                    if request_data.get('action') == 'close':
                        await close_tunnel(websocket, tunnel_id)
                        continue
                    
                    # Handle tunnel data forwarding
                    if 'data' in request_data:
                        result = await handle_tunnel_data(
                            websocket, tunnel_id, request_data['data'])
                        if result:
                            await websocket.send(json.dumps(result))
                        continue
                
                # Check if this is a CONNECT tunnel setup request
                if request_data.get('method') == 'CONNECT' and 'tunnel_host' in request_data:
                    result = await setup_tunnel(websocket, request_data)
                    if 'tunnel_id' in result and result['status'] == 'connected':
                        client_tunnels.add(result['tunnel_id'])
                    await websocket.send(json.dumps(result))
                    continue
                
                # Normal HTTP request handling
                url = request_data.get('url', 'unknown')
                method = request_data.get('method', 'GET')
                logger.debug(f"Processing {method} request to: {url}")
                
                # Process the request
                response_data = await handle_request(request_data)
                
                # Send back the response
                await websocket.send(json.dumps(response_data))
                
                # Log completion
                status = response_data.get('status_code', 'unknown')
                logger.debug(f"Completed {method} request to {url} with status {status}")
                
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON received from {client_info}")
                error_response = {"error": "Invalid JSON format"}
                await websocket.send(json.dumps(error_response))
                
            except Exception as e:
                logger.error(f"Error processing request: {str(e)}")
                error_response = {"error": str(e)}
                await websocket.send(json.dumps(error_response))
                
    except websockets.exceptions.ConnectionClosed as e:
        logger.info(f"Client {client_info} disconnected: {e}")
    finally:
        # Close any tunnels opened by this client
        for tunnel_id in list(client_tunnels):
            await close_tunnel(websocket, tunnel_id)

async def health_check(websocket):
    """Simple health check endpoint"""
    await websocket.send(json.dumps({"status": "ok", "timestamp": time.time()}))

async def start_server(host, port, health_check_port=None, ssl_context=None):
    """Start WebSocket server with optional health check endpoint and SSL support"""
    global running
    
    # Main WebSocket server
    main_server = await websockets.serve(
        handle_client_connection, 
        host, 
        port,
        ssl=ssl_context
    )
    
    # Optional health check server
    health_server = None
    if health_check_port:
        try:
            health_path = '/health'
            health_server = await websockets.serve(
                health_check,
                host,
                health_check_port
            )
            logger.info(f"Health check endpoint available at ws://{host}:{health_check_port}{health_path}")
        except Exception as e:
            logger.error(f"Failed to start health check server: {e}")
    
    logger.info(f"WebSocket proxy server started on {'wss' if ssl_context else 'ws'}://{host}:{port}")
    
    # Keep server running
    try:
        while running:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        # Clean shutdown
        main_server.close()
        await main_server.wait_closed()
        
        if health_server:
            health_server.close()
            await health_server.wait_closed()

def signal_handler(sig, frame):
    """Handle termination signals"""
    global running
    logger.info("Shutting down...")
    running = False
    
    # Close all active tunnels
    for tunnel_id in list(active_tunnels.keys()):
        asyncio.run_coroutine_threadsafe(
            close_tunnel(None, tunnel_id),
            asyncio.get_event_loop()
        )

def main():
    """Main entry point with command line argument parsing"""
    parser = argparse.ArgumentParser(description='WebSocket-based HTTP Proxy Server')
    parser.add_argument('--host', default='0.0.0.0', 
                        help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8765, 
                        help='WebSocket server port (default: 8765)')
    parser.add_argument('--health-port', type=int, 
                        help='Health check endpoint port (optional)')
    parser.add_argument('--ssl-cert', 
                        help='SSL certificate file path for HTTPS support')
    parser.add_argument('--ssl-key', 
                        help='SSL private key file path for HTTPS support')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Set log level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Configure SSL if certificate and key are provided
    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        try:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(args.ssl_cert, args.ssl_key)
            logger.info(f"SSL enabled with certificate: {args.ssl_cert}")
        except Exception as e:
            logger.error(f"Failed to load SSL certificates: {e}")
            return 1
    
    # Start the WebSocket server
    try:
        asyncio.run(start_server(
            args.host, 
            args.port, 
            args.health_port,
            ssl_context
        ))
    except KeyboardInterrupt:
        logger.info("Server stopped by keyboard interrupt")
    except Exception as e:
        logger.error(f"Server error: {e}")
        return 1
    
    logger.info("Server shut down successfully")
    return 0

if __name__ == "__main__":
    sys.exit(main())