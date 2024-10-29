import socket
import threading
from message import Message
from user_auth import UserAuth
from crypto_utils import CryptoUtils
import base64
import json
from cryptography.hazmat.primitives import serialization

class ChatServer:
    def __init__(self, host='localhost', port=1234):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        
        self.clients = {}  # {client_socket: username}
        self.public_keys = {}  # {username: public_key}
        self.symmetric_key = CryptoUtils.generate_symmetric_key()
        self.user_auth = UserAuth()
        
        print(f"Server started on {host}:{port}")

    def broadcast(self, message, exclude_client=None):
        for client in self.clients:
            if client != exclude_client:
                try:
                    client.send(message.encode('utf-8'))
                except:
                    self.remove_client(client)

    def handle_client(self, client_socket, address):
        try:
            # Receive authentication data
            auth_data = client_socket.recv(1024).decode('utf-8')
            auth_data = json.loads(auth_data)
            
            username = auth_data['username']
            password = auth_data['password']
            action = auth_data['action']
            
            # Convert received public key back to key object
            public_key_bytes = auth_data['public_key'].encode()
            public_key = serialization.load_pem_public_key(public_key_bytes)
            
            response_data = {
                'success': False,
                'message': '',
                'symmetric_key': ''
            }
            
            try:
                if action == 'register':
                    success = self.user_auth.register_user(username, password)
                    response_data['message'] = "Registration successful"
                else:  # login
                    success = self.user_auth.authenticate_user(username, password)
                    response_data['message'] = "Login successful"
                    
                if success:
                    response_data['success'] = True
                    response_data['symmetric_key'] = base64.b64encode(self.symmetric_key).decode()
                    self.public_keys[username] = public_key
                    self.clients[client_socket] = username
                    
            except ValueError as e:
                response_data['message'] = str(e)
            
            # Send response to client
            client_socket.send(json.dumps(response_data).encode('utf-8'))
            
            # If authentication was successful, start handling messages
            if response_data['success']:
                # Broadcast join message
                join_message = Message("Server", f"{username} joined the chat")
                self.broadcast(join_message.to_json())
                
                while True:
                    message_data = client_socket.recv(1024).decode('utf-8')
                    if message_data:
                        self.broadcast(message_data, client_socket)
                        
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            self.remove_client(client_socket)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            username = self.clients[client_socket]
            del self.clients[client_socket]
            del self.public_keys[username]
            client_socket.close()
            
            # Broadcast leave message
            leave_message = Message("Server", f"{username} left the chat")
            self.broadcast(leave_message.to_json())

    def start(self):
        while True:
            client_socket, address = self.server_socket.accept()
            thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, address)
            )
            thread.start()

if __name__ == "__main__":
    server = ChatServer()
    server.start()
