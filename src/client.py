import multiprocessing as mproc
import functools
import logging
import socket
import libmem
import defer
import utils
import time
import csoc

DEBUG = True # enable debug and info log levels.
ADDR = '127.0.0.1'
PORT = 8080
NTHREADS = 20

_client_logger = utils.Logger('clientsideproxy')
utils.config_log('client.log', level=(logging.DEBUG if DEBUG else logging.WARNING))

@defer.defers_collector
def dpatch(sock):
    # i love socks
    sock.listen(0) # no limit to the listening for me, thanks

    act_threads = [False for i in range(NTHREADS)] # 20 concurrent connections are possible
    all_threads = []

    for i in range(NTHREADS):
        act_threads[i] = True
        notif_done = lambda: act_threads[i] = False


@defer.defers_collector
def main():
    _client_logger.debug(f'-- START EXE TIME {time.time()} --')

    sock = csoc.gensock()
    defer.defer(sock.close)
    sock.bind((ADDR, PORT))

    dpatch(sock) # dispatch sockets

    defer.defer(
        functools.partial(
            _client_logger.debug, 
            f'-- END EXE TIME {time.time()} --'
        )
    )

if __name__ == "__main__":
    main()