#!/usr/bin/env python3

class Conn:
	def __init__(self, conn):
		self.conn = conn
	
	def send(self, msg):
		self.conn.send(msg.encode())
	
	def recv(self, limit=4096):
		return self.conn.recv(limit).decode()
	
	def sendbytes(self, msg):
		self.conn.send(msg)
	
	def recvbytes(self, limit=4096):
		return self.conn.recv(limit)
	
	def close(self):
		self.conn.close()