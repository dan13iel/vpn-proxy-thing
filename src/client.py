# CLIENT means on the USER's computer

# currently this is for initiating a test connection to the server, this will be changed later.

from internetkit.sockets.client import Socket
import time

host = 'localhost'
port = 8080

conn = Socket(host, port)
conn.setup()
conn.connect()

print('Received Message:', conn.recv())

time.sleep(10)

conn.send('FINISH')
conn.close()