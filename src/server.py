# THIS IS THE SERVER RUNNING **ON** THE VPS

# ------ HOW ------
# host server that client.py connects to
# > when client.py connects, await requests from client
# > when client.py sends url request, initiate an https connection with the intended destination, with the intended payload.
# > when https request is recieved from the external website, forward the response to client.py (the client).
# all communication between client.py and server.py should be encrypted
# ------ END ------

# -------------- for copy
# ---------------------------- IMPORTS ----------------------------

from internetkit.sockets.server import SockServer
from utils import Logger, config_log
import exceptions
import functools
import logging
import defer
import time
import sys

# ---------------------------- CONSTANTS ----------------------------
# ** TRUE MEANS ACTIVE, FALSE MEANS INACTIVE **
TEST = True #               host server on localhost:8080, rather than 0.0.0.0:457 (the default production port).
DEBUG = True #              enable debug and info log levels. behavior can be adjusted in the LOGGING section of this file.
RAISE_EXCEPTIONS = True #   raise exceptions when errors occour, as well as logging them. do not enable in production.
ALLOW_ECHO = True #         allow the ECHO command for testing.

if TEST:
    HOST = '127.0.0.1'
    PORT = 8080
elif not TEST:
    HOST = '0.0.0.0'
    PORT = 467

def raise_exp(given_exception, /, *a, **k):
    if RAISE_EXCEPTIONS:
        raise given_exception(*a, **k)
    else:
        _server_logger.debug(f'silenced exception {str(a)}')

VALIDCMDS = [
    'URL'
]

if ALLOW_ECHO:
    VALIDCMDS.append('ECHO')

# ---------------------------- LOGGING ----------------------------

# CREATE LOGGER
_server_logger = Logger('server')
config_log('server.log', level=(logging.DEBUG if DEBUG else logging.WARNING))

# DEBUG MESSAGE
_server_logger.debug('If this message is logged, DEBUG is active. Turn this off in production use.')

# ---------------------------- HANDLE CLIENT ----------------------------

@defer.defers_collector
def handle_io(conn, addr, parts):
    pass # todo: process request and return appropriate content to client.

@defer.defers_collector
def handle_client(conn, addr):
    defer.defer(conn.close)
    adinfo = f'CLIENT[{addr[0]}]@[{addr[1]}]: '

    defer.defer(
        functools.partial(
            _server_logger.info,
            adinfo + '(attempt) connection termin now.'
        )
    )

    # ready for urls
    conn.send('COMMAND:READY')
    _server_logger.info(adinfo + 'sent ready to client')

    while 1:
        recvd = conn.recv()

        if recvd == "FINISH":
            _server_logger.info(adinfo + f'client terminated')
            break

        parts = recvd.split(':')
        if len(parts) != 2:
            _server_logger.error(adinfo + 'client response - invalid formatting')
            raise_exp(exceptions.InvalidResponse, 'The client failed to respond with valid formatting.')
            break
        else:
            if parts[0] == 'ERROR':
                _server_logger.error(adinfo + f'client response - error given to server {parts[1]}')
                raise_exp(exceptions.ClientRespondedError, 'The client responded with error')
                break
            elif not (parts[0] in VALIDCMDS):
                _server_logger.error(adinfo + f'invalid command - given command was {parts[0]}, given args was {parts[1]}')
                raise_exp(exceptions.InvalidCommand, f'The client gave an invalid command {parts[0]}, with {parts[1]} as args')
                break
            else:
                _server_logger.debug(adinfo + f'excpected and recieved command {parts[0]} with args {parts[1]}')
                if parts[0] == 'URL':
                    handle_io(conn, addr, parts) # pass to io handling
                elif (parts[0] == 'ECHO') and (ALLOW_ECHO):
                    _server_logger.debug(adinfo + f'echo command given with text {parts[1]}')
                    conn.send(parts[1])
    
    return

# ---------------------------- MAIN ----------------------------

@defer.defers_collector
def main():
    _server_logger.debug(f'-- START EXE TIME {time.time()} --')

    defer.defer(
        functools.partial(
            _server_logger.debug, 
            f'-- END EXE TIME {time.time()} --'
        )
    )

    server = SockServer(HOST, PORT)
    defer.defer(server.close)
    server.setup()
    server.start()
    server.loop(handle_client)

    while 1:
        pass # mainloop. do whatever you want here, the servers are threaded.

# ---------------------------- RUN ----------------------------

if __name__ == "__main__":
    main()

    # do not add stuff here!