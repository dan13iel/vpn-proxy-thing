import asyncio
import threading

class Server:
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.loop = asyncio.get_event_loop()
	
	def setup(self, protocol, *proto_args, **proto_kwargs):
		self.coro = asyncio.create_server(lambda: protocol(*proto_args, **proto_kwargs), self.host, self.port)
	
	def start(self):
		self.server = self.loop.run_until_complete(self.coro)
		threading.Thread(target=self.loop.run_forever).start()
		return self.server.sockets[0].getsockname()
	
	def close(self):
		self.server.close()
		self.loop.run_until_complete(self.server.wait_closed())
		self.loop.close()