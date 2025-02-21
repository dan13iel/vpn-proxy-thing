"""
This is a simple TLS Socket Client, which can be used to communicate with HTTPS websites, and servers like the corresponding server.py.

Usage:

################################
## Simple example.com client: ##
################################
main.py

from internetkit.tlssocks.client import TLSConnection

# Define...
conn = TLSConnection('example.com')

# Setup...
conn.setup()

# Connect!!
conn.connect()
conn.send(b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: Close\r\n\r\n")

gen = conn.loop()
# use conn.maintained_loop() instead to keep the connection open, even when nothing is being transmitted.

while 1:
	try:
		print(next(gen).decode())
	except StopIteration:
		break

####################################
## Simple tlssocks server client: ##
####################################
main.py

from internetkit.tlssocks.client import TLSConnection

# Define...
conn = TLSConnection('example.com', 8080) # both host and port can be specified.

# Setup...
conn.setup()
conn.trust('/path/to/internetkit/tlssock/certs/server.crt')

# Connect!!
conn.connect()
conn.send(b"a random message")

gen = conn.loop()

while 1:
	try:
		print(next(gen).decode())
	except StopIteration:
		break

##################################
## Threaded example.com client: ##
##################################

from internetkit.tlssocks.client import TLSThreadedConnection

# Define...
conn = TLSThreadedConnection('example.com')

# Setup...
conn.setup()

# Connect!!
conn.connect()
conn.send(b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: Close\r\n\r\n")

# THERE ARE TWO OPTIONS HERE
# UNCOMMENT ONE

# A basic threaded loop, works exactly like the normal loop, but instead it automaticly iterates through the generator in a while true loop, parsing the bytes to the provided function.
# conn.loop(...) will automaticly catch any StopIteration errors, and execute the keyword argument whendone(). whendone() should take no arguments, and by default is set to lambda:0. THIS ONLY APPLIES FOR THREADED CONNECTIONS.
#gen = conn.loop(print)

# A more sophisticated threaded loop, which keeps the connection open, and passes any argument to the provided function. Great for streaming live data.
#gen = conn.maintained_loop(print)

########
#### It is possible to apply this to tlssock servers too!!
########


"""

import os
import ssl
import socket
import certifi
import platform
import threading

class DNS:
	def __init__(self):
		self.lookup = socket.gethostbyname
		
class _TLSConnection:
	def __init__(self, host, port=443):
		self.host = host
		self.port = port
		
	def _create_sock(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
	def _connect_sock(self):
		self.sock.connect((self.host, self.port))
		
	def _create_context(self, protocol=ssl.PROTOCOL_TLS_CLIENT):
		self.context = ssl.SSLContext(protocol)
		
	def _configure_context(self):
		self.context.verify_mode = ssl.CERT_REQUIRED
		self.context.check_hostname = True
		self.context.load_default_certs()
		
	def _configure_darwin(self):
		self.context.load_verify_locations(
			cafile=os.path.relpath(certifi.where()),
			capath=None,
			cadata=None
		)
		
	def _check_darwin(self):
		if platform.system().lower() == 'darwin':
			self._configure_darwin()
			
	def _create_wrapper(self):
		self.wrap = self.context.wrap_socket(self.sock, server_side=False, server_hostname=self.host)
		
	def _send(self, bdata):
		self.wrap.sendall(bdata)
		
	def _recv(self, limit=4096):
		return self.wrap.recv(4096)
	
	def _close(self):
		self.wrap.close()
		
	def _setup_sock(self):
		self._create_sock()
		self._connect_sock()
		
	def _setup_context(self):
		self._create_context()
		self._configure_context()
		self._check_darwin()
		
	def _setup_wrapper(self):
		self._create_wrapper()
	
	def _trust(self, path):
		self.context.load_verify_locations(path)
		
		
class TLSConnection(_TLSConnection):
	def __init__(self, host, port=443):
		super().__init__(host, port)
		self.is_setup = False
		
	def setup(self):
		self.is_setup = True
		self._setup_sock()
		self._setup_context()
	
	def connect(self):
		self._setup_wrapper()
		
	def send(self, data):
		self.wrap.sendall(data)
	
	def recv(self, limit=4096):
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		return self._recv(limit).decode()
	
	def recvbytes(self, limit=4096):
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		return self._recv(limit)
		
	def loop(self):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		while True:
			new = self.wrap.recv(4096)
			if not new:
				self.wrap.close()
				break
			yield new
			
	def maintained_loop(self):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		while True:
			new = wrap.recv(4096)
			yield new
	
	def close(self):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		self.wrap.close()
	
	def trust(self, path):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		self._trust(path)
			
class TLSThreadedConnection(_TLSConnection):
	def __init__(self, host, port=443):
		super().__init__(host, port)
		self.is_setup = False
		
	def setup(self):
		self.is_setup = True
		self._setup_sock()
		self._setup_context()
		
	def connect(self):
		self._setup_wrapper()
		
	def send(self, data):
		self.wrap.sendall(data)
	
	def recv(self, limit=4096):
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		return self._recv(limit).decode()
	
	def recvbytes(self, limit=4096):
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		return self._recv(limit)
		
	def _loop(self):
		while True:
			new = wrap.recv(4096)
			if not new:
				wrap.close()
				break
			yield new
			
	def _maintained_loop(self):
		while True:
			new = wrap.recv(4096)
			yield new
			
	def loop(self, func, whendone=lambda:0):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		def _loop_wpct():
			nonlocal func
			while 1: 
				try:
					func(next(self._loop()))
				except StopIteration:
					whendone()
			
		thread = threading.Thread(target=_loop_wrapper)
		thread.start()
		
		return thread
	
	def maintained_loop(self, func):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		def _maintained_loop_wpct():
			nonlocal func
			while 1: 
				func(next(self._maintained_loop()))
			
		thread = threading.Thread(target=_maintained_loop_wrapper)
		thread.start()
		
		return thread
	
	def close(self):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		self.wrap.close()
	
	def trust(self, path):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		self._trust(path)
	
if __name__ == '__main__':
	# Define...
	conn = TLSConnection('localhost', 8080)
	
	# Setup...
	conn.setup()
	conn.trust('./certs/server.crt')
	
	# Connect!!
	conn.connect()
	conn.send(b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: Close\r\n\r\n")
	
	gen = conn.loop()
	
	while 1:
		try:
			print(next(gen).decode())
		except StopIteration:
			break