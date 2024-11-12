import os
import socket
import random
import traceback 
import threading
import tkinter as tk
from base64 import b64encode, b64decode
from tkinter import messagebox, Listbox, scrolledtext
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as symmetric_padding 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class WiMAXClient:
    def __init__(self, broadcast_port=54321):
        self.servers = []
        self.broadcast_port = broadcast_port
        self.conn = None
        self.selected_server = None
        self.client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.client_public_key = self.client_private_key.public_key()

    def listen_for_servers(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.bind(('', self.broadcast_port))
            while True:
                data, addr = udp_socket.recvfrom(1024)
                message = data.decode()
                if message.startswith("WiMAXServer:"):
                    _, host, port = message.split(':')
                    server_info = (host, int(port))
                    if server_info not in self.servers:
                        self.servers.append(server_info)
                        self.update_server_listbox()

    def update_server_listbox(self):
        server_listbox.delete(0, tk.END)
        for server in self.servers:
            server_listbox.insert(tk.END, f"{server[0]}:{server[1]}")

    def connect(self, server):
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect(server)
            self.selected_server = server
            print("\n" + "="*50)
            print("Connected to the server.")
            print("="*50 + "\n")
            return True
        except Exception as e:
            print("\n" + "="*50)
            print(f"Failed to connect to the server: {e}")
            print("="*50 + "\n")
            return False

    def authenticate(self):
        if not self.conn and not self.connect(self.selected_server):
            return "Connection Failed"
        try:
            print("\n" + "="*50)
            print("Starting Mutual Authentication Process")
            print("="*50 + "\n")

            print("Step 1: Receiving server's public key")
            server_public_key_pem = self.conn.recv(1024)
            server_public_key = serialization.load_pem_public_key(server_public_key_pem, backend=default_backend())
            print("Received server's public key:")
            print(server_public_key_pem.decode())
            print("-"*50)

            print("\nStep 2: Sending client's public key to server")
            client_public_key_pem = self.client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.conn.sendall(client_public_key_pem)
            print("Sent client's public key to server:")
            print(client_public_key_pem.decode())
            print("-"*50)

            print("\nStep 3: Receiving encrypted challenge from server")
            encrypted_challenge = self.conn.recv(1024)
            if not encrypted_challenge:
                raise Exception("No challenge received from server")
            print(f"Received encrypted challenge: {encrypted_challenge.hex()}")
            print("-"*50)

            print("\nStep 4: Decrypting server's challenge")
            server_challenge = self.client_private_key.decrypt(
                encrypted_challenge,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Decrypted challenge: {server_challenge.decode()}")
            print("-"*50)

            print("\nStep 5: Encrypting and sending response to server")
            encrypted_response = server_public_key.encrypt(
                server_challenge,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            self.conn.sendall(encrypted_response)
            print(f"Sent encrypted response to server: {encrypted_response.hex()}")
            print("-"*50)

            print("\nStep 6: Receiving authentication result")
            auth_result = self.conn.recv(1024).decode()
            print(f"Authentication result: {auth_result}")
            print("="*50 + "\n")

            if auth_result != "Authentication Successful":
                print("Authentication failed. Closing connection.")
                self.conn.close()
            else:
                # Receive and decrypt session key
                encrypted_session_key = self.conn.recv(1024)
                self.session_key = self.client_private_key.decrypt(
                    encrypted_session_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                                algorithm=hashes.SHA256(), 
                                label=None)
                )
            return auth_result
        except Exception as e:
            print(f"\nError during authentication: {e}")
            traceback.print_exc()  # Add this for detailed error tracking
            self.close_connection()
            return "Authentication Error"

    def encrypt_message(self, message):
        try:
            # Convert the message to bytes if it's a string
            if isinstance(message, str):
                message = message.encode()
            
            # Add padding
            padder = symmetric_padding.PKCS7(128).padder()
            padded_data = padder.update(message) + padder.finalize()
            
            # Generate IV and encrypt
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data and encode to base64
            combined_data = iv + encrypted_data
            return b64encode(combined_data).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            raise

    def decrypt_message(self, encrypted_message):
        try:
            # Decode from base64
            combined_data = b64decode(encrypted_message)
            
            # Split IV and encrypted data
            iv = combined_data[:16]
            encrypted_data = combined_data[16:]
            
            # Decrypt
            cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            unpadder = symmetric_padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            return data.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            raise

    def send_message(self, message):
        if message.lower() == "disconnect":
            self.update_message_display("Disconnecting from server...")
            self.close_connection()
            root.after(1000, root.destroy)  # Close the client window after 1 second
            return "Disconnecting"
        
        if not self.conn or not self.session_key:
            print("Not connected or no session key. Please authenticate first.")
            return "Not Authenticated"
        try:
            encrypted_message = self.encrypt_message(message)
            self.conn.sendall(encrypted_message.encode())
            print(f"\nOriginal message: {message}")
            print(f"Sent encrypted message: {encrypted_message}")
            self.update_message_display(f"You: {message}")
            return "Message sent"
        except Exception as e:
            print(f"\nError sending message: {e}")
            self.close_connection()
            return "Send Error"

    def receive_messages(self):
        while self.conn and self.session_key:
            try:
                data = self.conn.recv(1024)
                if not data:
                    break
                
                encrypted_message = data.decode('utf-8')
                print(f"\nReceived encrypted message: {encrypted_message}")
                
                decrypted_message = self.decrypt_message(encrypted_message)
                print(f"Decrypted message: {decrypted_message}")
                
                if decrypted_message == "Server is shutting down":
                    self.update_message_display("Server is shutting down. Closing connection...")
                    self.close_connection()
                    root.after(1000, root.destroy)  # Close the client window after 1 second
                    break
                
                self.update_message_display(f"Server: {decrypted_message}")
            except Exception as e:
                print(f"\nError receiving message: {e}")
                break
        self.close_connection()

    def close_connection(self):
        if self.conn:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.conn.close()
            self.conn = None
            self.session_key = None
            print("\nConnection closed.")

    def update_message_display(self, message):
        message_display.insert(tk.END, message + "\n")
        message_display.see(tk.END)

# GUI Setup
def authenticate_and_connect():
    selection = server_listbox.curselection()
    if selection:
        index = selection[0]
        client.selected_server = client.servers[index]
        result = client.authenticate()
        if result == "Authentication Successful":
            threading.Thread(target=client.receive_messages, daemon=True).start()
        messagebox.showinfo("Authentication Result", result)

def send_message():
    message = message_entry.get()
    result = client.send_message(message)
    message_entry.delete(0, tk.END)

# Initialize the client object
client = WiMAXClient()
threading.Thread(target=client.listen_for_servers, daemon=True).start()

# GUI Setup
root = tk.Tk()
root.title("WiMAX Client")
root.geometry("500x600")

# Server Selection Section
tk.Label(root, text="Available Servers:").pack(pady=5)
server_listbox = Listbox(root, width=50)
server_listbox.pack(pady=5)
select_button = tk.Button(root, text="Select Server and Authenticate", command=authenticate_and_connect)
select_button.pack(pady=5)

# Message Display
message_display = scrolledtext.ScrolledText(root, height=20, width=60)
message_display.pack(pady=5)

# Message Entry
message_entry = tk.Entry(root, width=50)
message_entry.pack(pady=5)
send_button = tk.Button(root, text="Send Message", command=send_message)
send_button.pack(pady=5)

root.mainloop()
