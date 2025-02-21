#!/usr/bin/env python3

import asyncio

class Client:
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.loop = asyncio.get_event_loop()
	
	def setup(self, protocol, *proto_args, **proto_kwargs):
		self.coro = loop.create_connection(lambda: protocol(*proto_args, **proto_kwargs), self.host, self.port)
	
	def connect(self):
		self.loop.run_until_complete(self.coro)
		self.loop.run_forever()
	
	def close(self):
		self.loop.close()