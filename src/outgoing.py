import requests
# send outgoing requests to the url needed

from urllib.parse import urlparse

def url_validity(url):
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        return False
    else:
        return True

def forward_all(destination_url, method='GET', headers={}, data=None, timeout=10):
    request_functions = {
        "GET": requests.get,
        "POST": requests.post,
        "PUT": requests.put,
        "DELETE": requests.delete,
        "PATCH": requests.patch,
        "OPTIONS": requests.options,
        "HEAD": requests.head,
    }

    umethod = method.upper()

    if umethod not in request_functions:
        raise ValueError(f'Invalid Method {umethod}')
    
    req_func = request_functions[umethod]
    if umethod == "GET":
        response = req_func(destination_url, headers=headers, params=data, timeout=timeout)
    else:
        response = req_func(destination_url, headers=headers, data=data, timeout=timeout)
    
    return response

url = 'https://www.example.com'
print(url_validity(url))