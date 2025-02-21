# THIS IS THE SERVER RUNNING **ON** THE VPS

# ------ HOW ------
# host server that client.py connects to
# > when client.py connects, await requests from client
# > when client.py sends url request, initiate an https connection with the intended destination, with the intended payload.
# > when https request is recieved from the external website, forward the response to client.py (the client).
# all communication between client.py and server.py should be encrypted
# ------ END ------

from internetkit.sockets.server import SockServer
from utils import Logger, config_log
import functools
import logging
import defer
import time
import sys

# TRUE MEANS ACTIVE
TEST = True
DEBUG = True

if TEST:
    HOST = '127.0.0.1'
    PORT = 8080
elif not TEST:
    HOST = '0.0.0.0'
    PORT = 467

# CREATE LOGGER
_server_logger = Logger('server')
config_log('server.log', level=(logging.DEBUG if DEBUG else logging.WARNING))

# DEBUG MESSAGE
_server_logger.debug('If this message is logged, DEBUG is active. Turn this off in production use.')

@defer.defers_collector
def main():
    _server_logger.debug(f'-- START EXE TIME {time.time()} --')

    defer.defer(
        functools.partial(
            _server_logger.debug, 
            f'-- END EXE TIME {time.time()} --'
        )
    )

    #assert 3 == 4;

if __name__ == "__main__":
    main()