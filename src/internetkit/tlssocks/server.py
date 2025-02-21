#!/usr/bin/env python3

import socket
import threading
import ssl

class _internal_ThreadedSocketServer:
	def __init__(self, host, port, cert_path, key_path):
		self.host, self.port = host, port
		self.cert_path, self.key_path = cert_path, key_path
	
	# Highly Internal Fucntions
	
	def _create_context(self):
		self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
	
	def _configure_context(self):
		self.context.load_cert_chain(self.cert_path, self.key_path)
	
	def _create_sock(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	
	def _bind_sock(self):
		self.sock.bind((self.host, self.port))
	
	def _listen_sock(self):
		self.sock.listen(5)
	
	def _create_wrap(self):
		self.wrap = self.context.wrap_socket(self.sock, server_side=True)
	
	def _accept_loop(self, target):
		while 1:
			conn, addr = self.wrap.accept()
			threading.Thread(target=lambda: target(conn, addr)).start()
	
	def _wrap_close(self):
		self.wrap.close()
	
	def _sock_close(self):
		self.sock.close()

class _subinternal_ThreadedSocketServer(_internal_ThreadedSocketServer):
	def __init__(self, host, port, cert_path, key_path):
		super().__init__(host, port, cert_path, key_path)
		self.has_setup = False
	
	def _setup_context(self):
		self._create_context()
		self._configure_context()
	
	def _setup_sock(self):
		self._create_sock()
		self._bind_sock()
		self._listen_sock()
	
	def _setup_wrap(self):
		self._create_wrap()
	
	def _setup(self):
		self._setup_context()
		self._setup_sock()
		self._setup_wrap()
		self.has_setup = True
	
	def _close(self):
		self._wrap_close()
		self._sock_close()

class ThreadedSocketServer(_subinternal_ThreadedSocketServer):
	def setup(self):
		self._setup()

	def loop(self, func):
		assert self.has_setup, 'Error!! You have to run [this].setup() first!!'
		self._accept_loop(func)
	
	def configure(self, extension, *a, **kw):
		self.loop(extension.Extension(*a, **kw))

if __name__ == '__main__':
	def handle(conn, addr):
		print('[+]', addr)
		print('[r]', conn.recv(4096))
		print('[s]', 'Sending MSG... ')
		conn.send(b'Hello')
		conn.close()
		print('[-]', addr)
	
	thrd = ThreadedSocketServer('localhost', 8080, './certs/server.crt', './certs/server.key')
	thrd.setup()
	
	thrd.loop(handle)