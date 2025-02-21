import socket
import ssl
import os
import sys
import threading
import time
import struct
import logging
import random
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('OpenVPNServer')

# OpenVPN constants
OPENVPN_HMAC_SIZE = 16
OPENVPN_PACKET_ID_ARRAY_SIZE = 8

# OpenVPN packet opcodes
P_CONTROL_HARD_RESET_CLIENT_V1 = 1
P_CONTROL_HARD_RESET_SERVER_V1 = 2
P_CONTROL_SOFT_RESET_V1 = 3
P_CONTROL_V1 = 4
P_ACK_V1 = 5
P_DATA_V1 = 6
P_CONTROL_HARD_RESET_CLIENT_V2 = 7
P_CONTROL_HARD_RESET_SERVER_V2 = 8
P_DATA_V2 = 9

class OpenVPNServer:
    def __init__(self, host='0.0.0.0', port=1194, cert_file='server.crt', key_file='server.key'):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.server_socket = None
        self.clients = {}
        self.tun_device = None
        self.session_key = get_random_bytes(16)  # For encryption
        self.packet_id = 1
        
    def create_ssl_context(self):
        """Create SSL context for OpenVPN server."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        # For demonstration, we're setting verify mode to CERT_NONE
        # In production, you should use CERT_REQUIRED and properly validate client certs
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers('AES256-GCM-SHA384:AES128-GCM-SHA256')
        return context
        
    def create_tun_interface(self):
        """Create a TUN interface for routing VPN traffic."""
        # This is platform specific and would require additional code
        # For Linux, you'd use something like:
        # import fcntl
        # TUNSETIFF = 0x400454ca
        # IFF_TUN = 0x0001
        # IFF_NO_PI = 0x1000
        # tun = open('/dev/net/tun', 'rb+')
        # ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
        # fcntl.ioctl(tun, TUNSETIFF, ifr)
        # return tun
        logger.info("TUN interface creation would happen here (platform specific)")
        return None
    
    def parse_openvpn_packet(self, data):
        """Parse OpenVPN packet header."""
        if len(data) < 2:
            return None
            
        # First byte contains opcode and key_id
        opcode = (data[0] >> 3) & 0x1F
        key_id = data[0] & 0x07
        
        # For more detailed parsing based on packet type
        payload = data[1:]
        parsed_data = {
            'opcode': opcode,
            'key_id': key_id,
            'raw_data': data
        }
        
        # Handle specific packet types with more detailed parsing
        if opcode in [P_CONTROL_HARD_RESET_CLIENT_V1, P_CONTROL_HARD_RESET_CLIENT_V2]:
            if len(payload) >= 8:
                parsed_data['session_id'] = payload[:8]
                parsed_data['payload'] = payload[8:]
        elif opcode == P_CONTROL_V1:
            if len(payload) >= 8:
                # Control packets have session ID and packet ID
                parsed_data['session_id'] = payload[:8]
                if len(payload) >= 12:
                    parsed_data['packet_id'] = struct.unpack('>I', payload[8:12])[0]
                    parsed_data['payload'] = payload[12:]
        
        return parsed_data
        
    def build_config_packet(self):
        """Build the OpenVPN configuration packet with options."""
        # Format the configuration options
        options = []
        
        # Example options (would be customized for your VPN)
        options.append(b"push \"route 10.8.0.0 255.255.255.0\"")
        options.append(b"push \"dhcp-option DNS 8.8.8.8\"")
        options.append(b"push \"redirect-gateway def1 bypass-dhcp\"")
        options.append(b"ifconfig 10.8.0.2 10.8.0.1")
        options.append(b"keepalive 10 120")
        
        # Build the packet
        opcode_byte = (P_CONTROL_V1 << 3) & 0xF8  # Use key_id 0
        packet = bytearray([opcode_byte])
        
        # Add session ID (random for this example)
        packet.extend(get_random_bytes(8))
        
        # Add packet ID
        packet_id_bytes = struct.pack('>I', self.packet_id)
        self.packet_id += 1
        packet.extend(packet_id_bytes)
        
        # Add option payload
        payload = b"\n".join(options)
        packet.extend(payload)
        
        return packet
    
    def handle_control_packet(self, client_socket, client_address, packet):
        """Handle OpenVPN control packets."""
        logger.info(f"Processing control packet from {client_address}")
        
        # In a full implementation, we would:
        # 1. Parse the TLV (Type-Length-Value) items in the payload
        # 2. Handle authentication if present
        # 3. Process configuration requests
        # 4. Send appropriate responses
        
        # For now, we acknowledge the packet
        ack_packet = self.build_ack_packet(packet)
        
        try:
            client_socket.send(ack_packet)
            logger.info(f"Sent ACK to {client_address}")
            return True
        except Exception as e:
            logger.error(f"Failed to send ACK: {e}")
            return False
    
    def build_ack_packet(self, received_packet):
        """Build an ACK packet in response to a control packet."""
        if 'session_id' not in received_packet or 'packet_id' not in received_packet:
            # If we can't parse the original packet properly, create a generic ACK
            ack = bytearray([(P_ACK_V1 << 3) & 0xF8])
            ack.extend(get_random_bytes(8))  # Session ID
            ack.extend(struct.pack('>I', 1))  # Packet ID to ACK
            return ack
            
        # Create ACK for the specific packet ID
        ack = bytearray([(P_ACK_V1 << 3) & 0xF8])
        ack.extend(received_packet['session_id'])
        ack.extend(struct.pack('>I', received_packet['packet_id']))
        
        return ack
    
    def handle_data_packet(self, client_socket, client_address, packet):
        """Handle OpenVPN data packets."""
        logger.info(f"Processing data packet from {client_address}")
        
        # In a full implementation, we would:
        # 1. Decrypt the payload
        # 2. Forward to the TUN interface
        # 3. Process any return packets from the TUN interface
        
        # For now, we just acknowledge receipt
        # Note: In actual OpenVPN, data packets aren't ACKed like control packets
        logger.info(f"Processed data packet from {client_address} (would route to TUN)")
        
    def handle_client_reset(self, client_socket, client_address, packet):
        """Handle OpenVPN client reset packets."""
        logger.info(f"Handling client reset from {client_address}")
        
        # In a full implementation, this would:
        # 1. Parse client capabilities
        # 2. Setup encryption
        # 3. Send server reset response
        # 4. Begin key negotiation
        
        # Generate server session ID
        server_session_id = get_random_bytes(8)
        
        # Build the reset response packet
        opcode_byte = (P_CONTROL_HARD_RESET_SERVER_V2 << 3) & 0xF8  # Key ID 0
        response = bytearray([opcode_byte])
        response.extend(server_session_id)
        
        # Add packet ID (start with 1)
        response.extend(struct.pack('>I', 1))
        
        # Add HMAC placeholder (would be real HMAC in full implementation)
        response.extend(get_random_bytes(OPENVPN_HMAC_SIZE))
        
        try:
            client_socket.send(response)
            logger.info(f"Sent reset response to {client_address}")
            
            # Follow up with a config packet
            time.sleep(0.1)  # Small delay
            config_packet = self.build_config_packet()
            client_socket.send(config_packet)
            logger.info(f"Sent config options to {client_address}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to send reset response: {e}")
            return False
    
    def generate_session_id(self):
        """Generate a random session ID for OpenVPN handshake."""
        return get_random_bytes(8)
        
    def handle_client(self, client_socket, client_address):
        """Handle OpenVPN client connection."""
        logger.info(f"New client connected: {client_address}")
        
        # For UDP mode, we would skip SSL and handle the OpenVPN protocol directly
        # For TCP mode (which Windows client can use), we proceed with SSL first
        
        try:
            # For TCP mode, handle the initial TCP connection
            # Send initial server handshake packet before SSL handshake
            # This is what Windows VPN client expects
            
            # Generate session ID
            session_id = self.generate_session_id()
            
            # Build OpenVPN initial handshake packet (P_CONTROL_HARD_RESET_SERVER_V2)
            # Format: [opcode+key_id][session_id][packet_id][hmac]
            opcode_byte = (P_CONTROL_HARD_RESET_SERVER_V2 << 3) & 0xF8  # Use key_id 0
            packet_id = struct.pack('>I', 1)  # Start with packet ID 1
            
            # Build initial packet
            initial_packet = bytearray([opcode_byte])
            initial_packet.extend(session_id)
            initial_packet.extend(packet_id)
            initial_packet.extend(get_random_bytes(OPENVPN_HMAC_SIZE))  # Dummy HMAC for now
            
            # Send initial packet
            client_socket.send(initial_packet)
            logger.info(f"Sent initial handshake to {client_address}")
            
            # Now proceed with SSL handshake
            context = self.create_ssl_context()
            ssl_socket = context.wrap_socket(client_socket, server_side=True)
            logger.info(f"SSL handshake completed with {client_address}")
            
            # After SSL handshake, send OpenVPN config options
            config_packet = self.build_config_packet()
            ssl_socket.send(config_packet)
            logger.info(f"Sent config packet to {client_address}")
        except ssl.SSLError as e:
            logger.error(f"SSL handshake failed: {e}")
            client_socket.close()
            return
        except Exception as e:
            logger.error(f"Initial handshake failed: {e}")
            client_socket.close()
            return
            
        client_id = f"{client_address[0]}:{client_address[1]}"
        self.clients[client_id] = {
            'socket': ssl_socket,
            'address': client_address,
            'last_seen': time.time(),
            'authenticated': False,
            'session_id': session_id
        }
        
        try:
            while True:
                data = ssl_socket.recv(4096)
                if not data:
                    logger.info(f"Client {client_address} disconnected")
                    break
                
                # Log raw packet for debugging
                logger.info(f"Received raw data: {binascii.hexlify(data)}")
                    
                packet = self.parse_openvpn_packet(data)
                if not packet:
                    logger.warning(f"Received invalid packet from {client_address}")
                    continue
                    
                # Handle different packet types
                if packet['opcode'] == P_CONTROL_HARD_RESET_CLIENT_V2:
                    logger.info(f"Received client reset V2 from {client_address}")
                    success = self.handle_client_reset(ssl_socket, client_address, packet)
                    if not success:
                        break
                elif packet['opcode'] == P_CONTROL_HARD_RESET_CLIENT_V1:
                    logger.info(f"Received client reset V1 from {client_address}")
                    success = self.handle_client_reset(ssl_socket, client_address, packet)
                    if not success:
                        break
                elif packet['opcode'] == P_CONTROL_V1:
                    # Handle control messages (authentication, configuration, etc.)
                    logger.info(f"Received control packet from {client_address}")
                    self.handle_control_packet(ssl_socket, client_address, packet)
                elif packet['opcode'] == P_DATA_V1 or packet['opcode'] == P_DATA_V2:
                    # Handle encrypted data packets
                    logger.info(f"Received data packet from {client_address}")
                    self.handle_data_packet(ssl_socket, client_address, packet)
                else:
                    logger.warning(f"Received unknown packet type {packet['opcode']} from {client_address}")
                    
        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
            ssl_socket.close()
            
    def start_server(self):
        """Start the OpenVPN server."""
        # Create TUN interface
        self.tun_device = self.create_tun_interface()
        
        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            logger.info(f"OpenVPN server started on {self.host}:{self.port}")
            
            while True:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            logger.info("Server stopped")
            
def generate_self_signed_cert(cert_file='server.crt', key_file='server.key'):
    """Generate self-signed certificate for testing."""
    if os.path.exists(cert_file) and os.path.exists(key_file):
        logger.info(f"Using existing certificate: {cert_file} and key: {key_file}")
        return
        
    logger.info("Generating self-signed certificate...")
    from OpenSSL import crypto
    
    # Create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().OU = "Organizational Unit"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    # Write cert and key to files
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    logger.info(f"Certificate generated: {cert_file} and key: {key_file}")

if __name__ == "__main__":
    try:
        # First generate certificates if they don't exist
        generate_self_signed_cert()
        
        # Start OpenVPN server
        server = OpenVPNServer()
        server.start_server()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Error: {e}")