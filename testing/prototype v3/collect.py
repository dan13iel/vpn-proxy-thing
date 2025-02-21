# collect.py
import requests
import json
from requests.exceptions import RequestException, Timeout, TooManyRedirects
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('collect')

def send_request(data):
    """
    Send HTTP/HTTPS requests based on provided data.
    
    Args:
        data (dict): Request details containing:
            - url (str): Target URL
            - method (str): HTTP method (GET, POST, etc.)
            - headers (dict): HTTP headers
            - params (dict): URL parameters
            - payload (dict/str): Request body data
            - timeout (int): Request timeout in seconds
    
    Returns:
        dict: Response information including status code, headers, and body
    """
    # Extract request parameters
    url = data.get('url')
    if not url:
        logger.error("Missing URL in request data")
        return {'error': 'URL is required'}
    
    method = data.get('method', 'GET').upper()
    headers = data.get('headers', {})
    params = data.get('params', {})
    timeout = data.get('timeout', 30)  # Default 30 second timeout
    
    # Handle different payload formats
    payload = data.get('payload')
    files = None
    data_payload = None
    json_payload = None
    
    if payload:
        content_type = headers.get('Content-Type', '').lower()
        if isinstance(payload, str) and content_type.startswith('application/json'):
            try:
                json_payload = json.loads(payload)
            except json.JSONDecodeError:
                json_payload = payload  # Send as raw string if parsing fails
        elif isinstance(payload, dict) and content_type.startswith('application/json'):
            json_payload = payload
        else:
            data_payload = payload

    try:
        # Prepare request kwargs
        request_kwargs = {
            'method': method,
            'url': url,
            'headers': headers,
            'params': params,
            'timeout': timeout,
        }
        
        # Add the appropriate payload
        if json_payload is not None:
            request_kwargs['json'] = json_payload
        elif data_payload is not None:
            request_kwargs['data'] = data_payload
        if files is not None:
            request_kwargs['files'] = files
            
        # Make the request with proper error handling
        logger.info(f"Sending {method} request to {url}")
        response = requests.request(**request_kwargs)
        
        # Handle the response
        logger.info(f"Received response: {response.status_code}")
        
        # Prepare the response data structure
        response_data = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'url': response.url,
            'text': response.text,
        }
        
        # Try to parse JSON if the response appears to be JSON
        if 'application/json' in response.headers.get('Content-Type', '').lower():
            try:
                response_data['json'] = response.json()
            except json.JSONDecodeError:
                # Response claimed to be JSON but wasn't parseable
                logger.warning("Failed to parse JSON response")
                response_data['json'] = None
        
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


if "__main__" == __name__:
    # Example usage with more complex setup
    test_data = {
        'url': 'https://httpbin.org/anything',
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/json',
            'User-Agent': 'WebSocket-Proxy/1.0'
        },
        'params': {'param1': 'value1'},
        'payload': {'title': 'Test Request', 'data': [1, 2, 3]},
        'timeout': 10
    }

    response = send_request(test_data)
    print(json.dumps(response, indent=2))