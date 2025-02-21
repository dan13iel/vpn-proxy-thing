import base64

class JSONProtocol:
	def __init__(self, conn):
		self.conn = conn
	
	def send(self, data):
		bdat = base64.b64encode(data.encode())
		self.conn.sendbytes(bdat)
	
	def recv(self, limit=4096):
		data = self.conn.recvbytes(limit)
		bdat = base64.b64decode(data).decode()
		return bdat
	
	def sendbytes(self, data):
		bdat = base64.b64encode(data)
		self.conn.sendbytes(bdat)
	
	def recvbytes(self, limit=4096):
		data = self.conn.recvbytes(limit)
		bdat = base64.b64decode(data)
		return bdat