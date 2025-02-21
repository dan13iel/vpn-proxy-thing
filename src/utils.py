from contextlib import ExitStack
from functools import partial
import defer
import logging

# ------------ LOGGING ------------

def config_log(fn, /, level=logging.INFO):
    logging.basicConfig(filename=fn, level=level)

class Logger:
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        self.log = self.logger.log
        self.info = self.logger.info
        self.debug = self.logger.debug
        self.warning = self.logger.warning
        self.error = self.logger.error
        self.critical = self.logger.critical
        self.exception = self.logger.exception
        self.disabled = self.logger.disabled

# ------------ EMBED DEFER ------------

## A different deferal version
def allow_embed_defer():
    return ExitStack() # for changing at a later date

def embed_defer(stack, f, /, *a, **k):
    stack.callback(partial(f, *a, **k))

## use with

'''
with allow_embed_defer() as stack:
    embed_defer(stack,
        print,
        "Hello, world!"
    )'''