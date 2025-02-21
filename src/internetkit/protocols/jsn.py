import json

class JSONProtocol:
	def __init__(self, conn):
		self.conn = conn
	
	def send(self, data):
		jdat = json.dumps(data)
		self.conn.send(jdat)
	
	def recv(self, limit=4096):
		data = self.conn.recv(limit)
		jdat = json.loads(data)
		return jdat