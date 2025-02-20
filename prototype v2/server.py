import socket
import os
import sys
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Simple AES encryption/decryption
def encrypt(data, key):
    # Pad the data to ensure it's a multiple of AES block size (16 bytes)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ct_bytes  # prepend iv for decryption

def decrypt(encrypted_data, key):
    iv = encrypted_data[:16]  # Extract the IV (first 16 bytes)
    ct = encrypted_data[16:]  # The rest is the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()  # Unpad after decrypting

# Simple VPN Server Class
class SimpleVPNServer:
    def __init__(self, host='0.0.0.0', port=9999, key=b'Sixteen byte key'):
        self.host = host
        self.port = port
        self.key = key
        self.server_socket = None

    def start_server(self):
        """Starts the VPN server and listens for incoming client connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"VPN server started on {self.host}:{self.port}...")

        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Connection from {client_address}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        """Handles communication with an individual client."""
        try:
            # Perform a basic handshake, you can replace it with any authentication method
            client_socket.send("WELCOME_TO_VPN_SERVER".encode())

            while True:
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    break

                # Decrypt and process data
                decrypted_data = decrypt(encrypted_data, self.key)
                print(f"Received decrypted data: {decrypted_data}")

                # Process data here (e.g., route, forward packets, etc.)

                # Encrypt response and send back to client
                response = f"Server received: {decrypted_data}"
                encrypted_response = encrypt(response, self.key)
                client_socket.send(encrypted_response)

        except Exception as e:
            print(f"Error with client: {e}")
        finally:
            client_socket.close()

# Running the server
if __name__ == "__main__":
    vpn_server = SimpleVPNServer()
    vpn_server.start_server()
