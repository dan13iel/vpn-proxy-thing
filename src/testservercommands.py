# CLIENT means on the USER's computer

# currently this is for initiating a test connection to the server, this will be changed later.

from internetkit.sockets.client import Socket
import threading
import time

host = 'localhost'
port = 8080

conn = Socket(host, port)
conn.setup()
conn.connect()

print('Received Message:', conn.recv())

GLOB_tstop = False

def threadedwait():
    global conn
    while 1:
        if GLOB_tstop:
            break
        
        d =  conn.recv()
        if d.strip():
            print('\n', ' r ', d, '\ncommand > ', sep='', end='')

threading.Thread(target=threadedwait).start()

inp = ''
while inp != 'break':
    inp = input('command > ')
    conn.send(inp)

conn.send('FINISH')
conn.close()