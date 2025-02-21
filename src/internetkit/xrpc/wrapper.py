import pyexpat

def register(server, name=None):
	def registerwrap(func):
		def registerinner(*args, **kwargs):
			res = func(*args, **kwargs)
			return res
		server.register_function(registerinner, name)
		return registerinner
	return registerwrap

EXPAT_VERSION = pyexpat.EXPAT_VERSION