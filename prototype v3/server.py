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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('proxy-server')

# Global flag for graceful shutdown
running = True

async def handle_request(request_data):
    """Process HTTP request and return response"""
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

async def handle_client_connection(websocket, path):
    """Handle WebSocket client connection"""
    client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    logger.info(f"Client connected from {client_info}")
    
    try:
        async for message in websocket:
            try:
                # Parse request data from JSON
                request_data = json.loads(message)
                
                # Log request info
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

async def health_check(websocket, path):
    """Simple health check endpoint"""
    await websocket.send(json.dumps({"status": "ok", "timestamp": time.time()}))

async def start_server(host, port, health_check_port=None):
    """Start WebSocket server with optional health check endpoint"""
    global running
    
    # Main WebSocket server
    main_server = await websockets.serve(
        handle_client_connection, host, port
    )
    logger.info(f"WebSocket proxy server started on ws://{host}:{port}")
    
    # Optional health check server
    health_server = None
    if health_check_port:
        health_server = await websockets.serve(
            health_check, host, health_check_port
        )
        logger.info(f"Health check endpoint available at ws://{host}:{health_check_port}")
    
    # Keep running until shutdown
    while running:
        await asyncio.sleep(1)
    
    # Graceful shutdown
    logger.info("Shutting down WebSocket servers...")
    main_server.close()
    await main_server.wait_closed()
    
    if health_server:
        health_server.close()
        await health_server.wait_closed()
    
    logger.info("Server shutdown complete")

def signal_handler(sig, frame):
    """Handle termination signals"""
    global running
    logger.info("Received shutdown signal")
    running = False

def main():
    """Main entry point with command line argument parsing"""
    parser = argparse.ArgumentParser(description='WebSocket Proxy Server')
    parser.add_argument('--host', default='0.0.0.0',
                        help='Server host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8765,
                        help='Server port (default: 8765)')
    parser.add_argument('--health-port', type=int,
                        help='Health check endpoint port (optional)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Set log level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the server
    try:
        asyncio.run(start_server(args.host, args.port, args.health_port))
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()