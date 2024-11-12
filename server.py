import socket
import threading
import random
import time
import tkinter as tk
from tkinter import scrolledtext
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class WiMAXServer:
    def __init__(self, host='localhost', port=12345, broadcast_port=54321):
        self.host = host
        self.port = port
        self.broadcast_port = broadcast_port
        self.server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.server_public_key = self.server_private_key.public_key()
        self.clients = {}  # Store client connections

    def handle_client(self, conn, addr):
        try:
            print("\n" + "="*50)
            print(f"Connected by {addr}")
            print("="*50 + "\n")
            self.update_message_display(f"Connected by {addr}")

            print("\n" + "="*50)
            print("Starting Mutual Authentication Process")
            print("="*50 + "\n")

            print("Step 1: Sending server's public key")
            server_public_key_pem = self.server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(server_public_key_pem)
            print("Sent server's public key:")
            print(server_public_key_pem.decode())
            print("-"*50)

            print("\nStep 2: Receiving client's public key")
            client_public_key_pem = conn.recv(1024)
            client_public_key = serialization.load_pem_public_key(client_public_key_pem, backend=default_backend())
            print("Received client's public key:")
            print(client_public_key_pem.decode())
            print("-"*50)

            print("\nStep 3: Generating and encrypting challenge")
            server_challenge = str(random.randint(1000, 9999)).encode()
            encrypted_challenge = client_public_key.encrypt(
                server_challenge,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            conn.sendall(encrypted_challenge)
            print(f"Generated challenge: {server_challenge.decode()}")
            print(f"Encrypted challenge: {encrypted_challenge.hex()}")
            print("Sent encrypted challenge to client.")
            print("-"*50)

            print("\nStep 4: Receiving client's response")
            client_response = conn.recv(1024)
            print(f"Received encrypted response from client: {client_response.hex()}")
            print("-"*50)

            print("\nStep 5: Decrypting and verifying client's response")
            decrypted_response = self.server_private_key.decrypt(
                client_response,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"Decrypted response: {decrypted_response.decode()}")
            print("-"*50)

            print("\nStep 6: Sending authentication result")
            if decrypted_response == server_challenge:
                conn.sendall("Authentication Successful".encode())
                print("Authentication successful.")
                self.update_message_display(f"Client {addr} authenticated successfully.")
                self.clients[addr] = conn
            else:
                conn.sendall("Authentication Failed".encode())
                print("Authentication failed.")
                self.update_message_display(f"Authentication failed for {addr}.")
                conn.close()
                return
            print("="*50 + "\n")

            while True:
                message = conn.recv(1024)
                if not message:
                    break  # Client disconnected

                decrypted_message = message.decode()
                print(f"\nReceived from {addr}: {decrypted_message}")
                self.update_message_display(f"Received from {addr}: {decrypted_message}")

                response = f"Server received: {decrypted_message}"
                conn.sendall(response.encode())
                print(f"Sent to {addr}: {response}")

        except Exception as e:
            print(f"\nError with client {addr}: {e}")
        finally:
            if addr in self.clients:
                del self.clients[addr]
            conn.close()
            print(f"\nConnection with {addr} closed.")
            self.update_message_display(f"Connection with {addr} closed.")

    def run_tcp_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"\nServer listening on {self.host}:{self.port}")
            self.update_message_display(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def broadcast_presence(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while True:
                message = f"WiMAXServer:{self.host}:{self.port}"
                udp_socket.sendto(message.encode(), ('<broadcast>', self.broadcast_port))
                print(f"\nBroadcasting presence: {message}")
                time.sleep(5)

    def run(self):
        threading.Thread(target=self.run_tcp_server, daemon=True).start()
        threading.Thread(target=self.broadcast_presence, daemon=True).start()

    def send_message_to_all(self, message):
        for client_addr, client_conn in self.clients.items():
            try:
                client_conn.sendall(message.encode())
                print(f"\nSent to {client_addr}: {message}")
                self.update_message_display(f"Sent to {client_addr}: {message}")
            except Exception as e:
                print(f"\nError sending message to {client_addr}: {e}")

    def update_message_display(self, message):
        message_display.insert(tk.END, message + "\n")
        message_display.see(tk.END)

# GUI Setup
def send_message():
    message = message_entry.get()
    server.send_message_to_all(message)
    message_entry.delete(0, tk.END)

# Initialize the server object
server = WiMAXServer()

# GUI Setup
root = tk.Tk()
root.title("WiMAX Server")
root.geometry("500x600")

# Message Display
message_display = scrolledtext.ScrolledText(root, height=25, width=60)
message_display.pack(pady=10)

# Message Entry
message_entry = tk.Entry(root, width=50)
message_entry.pack(pady=5)
send_button = tk.Button(root, text="Send Message to All Clients", command=send_message)
send_button.pack(pady=5)

# Start server threads
server.run()

root.mainloop()
