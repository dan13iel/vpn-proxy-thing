#!/usr/bin/env python3

import socket

class Socket:
	def __init__(self, host, port):
		self.is_setup = False
		self.host = host
		self.port = port
	
	def setup(self):
		self.sock = socket.socket()
		self.is_setup = True
	
	def connect(self):
		self.sock.connect((self.host, self.port))
	
	def send(self, data):
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		self.sock.send(data.encode())
	
	def sendbytes(self, data):
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		self.sock.send(data)
	
	def recv(self, limit=4096):
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		return self.sock.recv(limit).decode()
	
	def recvbytes(self, limit=4096):
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		return self.sock.recv(limit)
	
	def loop(self, limit=4096):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		while True:
			new = self.sock.recv(limit)
			if not new:
				self.sock.close()
				break
			yield new
			
	def maintained_loop(self, limit=4096):
		# Determine if connected yet!!
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		
		while True:
			new = sock.recv(4096)
			yield new
	
	def close(self):
		assert self.is_setup, 'Error!! You have to connect first! (use conn.setup(), then conn.connect()).'
		self.sock.close()