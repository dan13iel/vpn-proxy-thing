# InternetKit
	██╗███╗░░██╗████████╗███████╗██████╗░███╗░░██╗███████╗████████╗██╗░░██╗██╗████████╗
	██║████╗░██║╚══██╔══╝██╔════╝██╔══██╗████╗░██║██╔════╝╚══██╔══╝██║░██╔╝██║╚══██╔══╝
	██║██╔██╗██║░░░██║░░░█████╗░░██████╔╝██╔██╗██║█████╗░░░░░██║░░░█████═╝░██║░░░██║░░░
	██║██║╚████║░░░██║░░░██╔══╝░░██╔══██╗██║╚████║██╔══╝░░░░░██║░░░██╔═██╗░██║░░░██║░░░
	██║██║░╚███║░░░██║░░░███████╗██║░░██║██║░╚███║███████╗░░░██║░░░██║░╚██╗██║░░░██║░░░
	╚═╝╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝╚═╝░░╚══╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░░╚═╝░░░

	//--// A python toolkit for interacting with the internet with ease. //--//

## About InternetKit
InternetKit is designed to make your life simple. You can connect to servers, host servers, and use common protocols all at ease with a fluid object-oriented design. You can do it all - in one place. If you like using some librarys already - this will make *those* easier to use as well.\
\
InternetKit is mainly based around sockets. This allows you to use existing protocols, but also create your own. It allows for simple socket creation and managment, aand allows you to send raw bytes across the entire internet, just like a traditional socket. However, it offers a simple and clutter-free interface with python's builtin socket library, making your life a whole lot simpler, as you don't have to deal with a messy API. \
\
InternetKit also brings security with it's sockets. It allows you to use SSL to secuerly transfer data over a simple pipeline, which you still control. The SSL is done securely via the builtin SSL module, but it does not clutter anything at all - you only need to make a few modifications to your already-existing app, and it is working! \
\
InternetKit also builds threading right into it's usage. Allow your server to handle multiple clients symultainously, rather then the traditional one-at-a time set-out socket framework. \
\
With all these features, InternetKit is a good server ***and*** client framework for all your internet needs.

## Installation
Currently, this is not on PyPi. Just download as a zip and move to the site-packages folder. Sorry for the inconvinience. This is just because this is being rapidly updated.

## Basic Usage
Where do we start? Well, first of all, lets take a look at a simple socket example: 

##### server.py
	# Import the socket server part of InternetKit:
	from internetkit.sockets.server import SockServer
	
	host = 'localhost' # The ip address to host on.
	port = 8000 # The port number to host on.
	
	server = SockServer(host, port) # Create the server object.
	server.setup() # Set it up.
	server.start() # Start listening for clients.
	
	# Create a function to handle each individual client.
	# This function will be called every time a client connects.
	# The function is to take two arguments:
	#    1. conn. This is the connection object. It offers 
	#        basic io in both plain text and bytes, and can close 
	#        the connection with the client.
	#    2. addr. This is a tuple with two parts; ip of the client, 
	#        and the port that is being used for comms.

	def deal_with_client(conn, addr):
		# Display the connection data:
		print('Connection from', addr[0], 'on port', addr[1])

		# Send a message: 
		conn.send('Hello')

		# Wait until a message is received:
		print(conn.recv())

		# Close the connection with the client.
		conn.close()
		

	# Start the loop. Every client that connects to the server will be
	# accepted, and then dealt with by the deal_with_client(...) function.
	server.loop(deal_with_client)
	
	# The loop created above is threaded. Your server can continue doing
	# meaningful things, all whilst dealing with connecting clients.

	print('Do something meaningful in the mean time. ')
	print('When you want to shut down, run server.close()')

##### client.py
	# Import the sockets submodule of InternetKit
	from internetkit.sockets.client import Socket
	
	host = 'localhost' # The target host.
	port = 8000 # The port the server is hosting on.
	
	# Create the connection object.
	conn = Socket(host, port)
	
	conn.setup() # Setup the socket.
	conn.connect() # Connect to the server.
	print('Connected!!')
	
	# Receive a message from the server.
	print('Received Message:', conn.recv())
	
	# Send a message back.
	message = input('Message to send back: ')
	conn.send(message)
	
	# Close the connection.
	conn.close()
	print('Closed conn.')

And there we have it!! A working client / server pair. But - one other thing. The server can automatically handle many, many clients! Try it! Try one client and then another afterwards, and then try connecting simultaniously. If all goes well, boom! You have two simultanious connections.

## Features

### Current

> This project is incredibly new, but it is sure to be expanded as time passes, so expect way more features in the near future. Anyway, the current features include:

- Simple sockets, as demonstrated by the example.
- SSL Sockets, protected by encryption.
- Pre-provided freely usable certificates. See the README.md in /tlssocks/certs/
- JSON Data Transfer Handler
- Base64 Data Transfer Handler
- An XMLRPC function register wrapper, with builtin monkey patch from Diffused XML.
- AsyncIO Servers and Clients for async functionality.
- Rentry API Support (file storage).

### Future

> These features are not implemented yet, but (hopefully) will be added in the future.

- More protocol support
- Other data types for transfer
- More docs
- More sub-modules

### Old

> These are deprecated features, soon to be removed. 

- Nothing here, this thing is VERY NEW.

## Credits

The credits for InternetKit go to Pigeon Nation.
Copyright (c) 2023 Pigeon Nation, MIT Licensed.
This is free, open-source software.
You may use this as according to the provided license.
Thank you!!
