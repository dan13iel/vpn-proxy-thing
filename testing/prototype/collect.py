import requests

def send_request(data):
    # Extract necessary information from the data
    url = data.get('url')
    method = data.get('method', 'GET').upper()
    headers = data.get('headers', {})
    params = data.get('params', {})
    payload = data.get('payload', {})

    try:
        # Send the request based on the method
        response = requests.request(method, url, headers=headers, params=params, json=payload)

        # Create the response data structure
        response_data = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'url': response.url,
            'text': response.text,
            'json': response.json() if response.headers.get('Content-Type') == 'application/json' else None
        }

        return response_data

    except Exception as e:
        return {'error': str(e)}

if "__main__" == __name__: # stops this part from running if this code is imported

    # Example usage:
    data = {
        'url': 'https://jsonplaceholder.typicode.com/posts',
        'method': 'POST',
        'headers': {'Content-Type': 'application/json'},
        'payload': {'title': 'foo', 'body': 'bar', 'userId': 1}
    }

    response = send_request(data)
    print(response)
