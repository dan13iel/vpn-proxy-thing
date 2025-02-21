import socket

class Lookup:
	def __init__(self):
		pass
	
	def lookup(self, name):
		return socket.gethostbyname(name)
	
	@property
	def name(self):
		return socket.gethostname()
	

