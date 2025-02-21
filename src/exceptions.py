class ServerSideException(Exception):
    pass

class InvalidResponse(ServerSideException):
    pass

class ClientRespondedError(ServerSideException):
    pass