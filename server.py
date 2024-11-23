import os
import time
import socket
import random
import threading
import traceback
import tkinter as tk
from tkinter import scrolledtext, Listbox, messagebox
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding

# Add these at the top level of the file, before any functions
root = None
message_display = None
message_entry = None
clients_listbox = None
server = None

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
        self.client_sessions = {}  # Store session keys for each client

    def encrypt_message(self, message, session_key):
        try:
            # Convert the message to bytes if it's a string
            if isinstance(message, str):
                message = message.encode()
            
            # Add padding
            padder = symmetric_padding.PKCS7(128).padder()
            padded_data = padder.update(message) + padder.finalize()
            
            # Generate IV and encrypt
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data and encode to base64
            combined_data = iv + encrypted_data
            return b64encode(combined_data).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            raise

    def decrypt_message(self, encrypted_message, session_key):
        try:
            # Decode from base64
            combined_data = b64decode(encrypted_message)
            
            # Split IV and encrypted data
            iv = combined_data[:16]
            encrypted_data = combined_data[16:]
            
            # Decrypt
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            unpadder = symmetric_padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            return data.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            raise

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
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
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
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Decrypted response: {decrypted_response.decode()}")
            print("-"*50)

            print("\nStep 6: Sending authentication result")
            if decrypted_response == server_challenge:
                conn.sendall("Authentication Successful".encode())
                print("Authentication successful.")
                self.update_message_display(f"Client {addr} authenticated successfully.")
                self.clients[addr] = conn
                # Generate and send session key
                session_key = os.urandom(32)
                self.client_sessions[addr] = session_key
                
                encrypted_session_key = client_public_key.encrypt(
                    session_key,
                    asymmetric_padding.OAEP(
                        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                conn.sendall(encrypted_session_key)
            else:
                conn.sendall("Authentication Failed".encode())
                print("Authentication failed.")
                self.update_message_display(f"Authentication failed for {addr}.")
                conn.close()
                return
            print("="*50 + "\n")

            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    
                    encrypted_message = data.decode('utf-8')
                    print(f"\nReceived encrypted message from {addr}: {encrypted_message}")
                    
                    decrypted_message = self.decrypt_message(encrypted_message, self.client_sessions[addr])
                    print(f"Decrypted message: {decrypted_message}")
                    self.update_message_display(f"Message from {addr}: {decrypted_message}")

                    # Send encrypted response
                    response = f"Server received: {decrypted_message}"
                    encrypted_response = self.encrypt_message(response, self.client_sessions[addr])
                    conn.sendall(encrypted_response.encode())
                    print(f"\nOriginal response: {response}")
                    print(f"Sent encrypted response: {encrypted_response}")

                except Exception as e:
                    print(f"Error processing message: {e}")
                    traceback.print_exc()  # Add stack trace for debugging
                    break

        except Exception as e:
            print(f"\nError with client {addr}: {e}")
            traceback.print_exc()
        finally:
            if addr in self.clients:
                del self.clients[addr]
            if addr in self.client_sessions:
                del self.client_sessions[addr]  # Clean up session key
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
            # Set socket options for Windows
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # For Windows, use specific broadcast address
            broadcast_address = '255.255.255.255'
            
            while True:
                try:
                    message = f"WiMAXServer:{self.host}:{self.port}"
                    udp_socket.sendto(message.encode(), (broadcast_address, self.broadcast_port))
                    print(f"Broadcasting presence: {message} to port {self.broadcast_port}")
                    time.sleep(5)  # Broadcast every 5 seconds
                except Exception as e:
                    print(f"Broadcast error: {e}")
                    time.sleep(1)

    def run(self):
        threading.Thread(target=self.run_tcp_server, daemon=True).start()
        threading.Thread(target=self.broadcast_presence, daemon=True).start()

    def send_message_to_all(self, message):
        if message.lower() == "close":
            self.update_message_display("Shutting down server...")
            self.shutdown_server()
            root.after(1000, root.destroy)  # Close the server window after 1 second
            return

        for client_addr, client_conn in self.clients.items():
            try:
                # Encrypt the message using the client's session key
                encrypted_message = self.encrypt_message(message, self.client_sessions[client_addr])
                client_conn.sendall(encrypted_message.encode())
                print(f"\nOriginal message to {client_addr}: {message}")
                print(f"Sent encrypted message: {encrypted_message}")
                self.update_message_display(f"Sent to {client_addr}: {message}")
            except Exception as e:
                print(f"\nError sending message to {client_addr}: {e}")

    def shutdown_server(self):
        print("\nShutting down server...")
        # Notify all clients
        shutdown_message = "Server is shutting down"
        for client_addr, client_conn in self.clients.items():
            try:
                encrypted_message = self.encrypt_message(shutdown_message, self.client_sessions[client_addr])
                client_conn.sendall(encrypted_message.encode())
            except:
                pass
        
        # Close all connections
        for client_conn in self.clients.values():
            try:
                client_conn.close()
            except:
                pass
        
        self.clients.clear()
        self.client_sessions.clear()

    def update_message_display(self, message):
        if message_display:
            message_display.insert(tk.END, message + "\n")
            message_display.see(tk.END)

    def close_connection(self, addr):
        if addr in self.clients:
            try:
                self.clients[addr].shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.clients[addr].close()
            del self.clients[addr]
            if addr in self.client_sessions:
                del self.client_sessions[addr]
            print(f"\nConnection with {addr} closed.")
            self.update_message_display(f"Connection with {addr} closed.")

    def send_direct_message(self, target_addr, message):
        """Send a message to a specific client"""
        if target_addr in self.clients:
            try:
                # Add a prefix to indicate this is a direct message
                prefixed_message = f"[Direct Message] {message}"
                encrypted_message = self.encrypt_message(prefixed_message, self.client_sessions[target_addr])
                self.clients[target_addr].sendall(encrypted_message.encode())
                print(f"\nSent direct message to {target_addr}: {message}")
                self.update_message_display(f"Direct message to {target_addr}: {message}")
                return True
            except Exception as e:
                print(f"\nError sending direct message to {target_addr}: {e}")
                return False
        else:
            print(f"\nClient {target_addr} not found")
            return False

    def get_connected_clients(self):
        """Return list of connected client addresses"""
        return list(self.clients.keys())

def setup_gui():
    global root, message_display, message_entry, clients_listbox, server

    root = tk.Tk()
    root.title("WiMAX Server")
    root.geometry("700x600")

    # Left frame for client list
    left_frame = tk.Frame(root)
    left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

    tk.Label(left_frame, text="Connected Clients:").pack()
    clients_listbox = Listbox(left_frame, width=30, height=15, selectmode=tk.SINGLE)
    clients_listbox.pack(pady=5)

    # Add scrollbar for client list
    scrollbar = tk.Scrollbar(left_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    clients_listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=clients_listbox.yview)

    # Right frame for messages
    right_frame = tk.Frame(root)
    right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Message Display
    message_display = scrolledtext.ScrolledText(right_frame, height=25, width=60)
    message_display.pack(pady=10)

    # Message Entry
    message_entry = tk.Entry(right_frame, width=50)
    message_entry.pack(pady=5)
    message_entry.bind('<Return>', lambda e: send_message_to_all())

    # Buttons frame
    buttons_frame = tk.Frame(right_frame)
    buttons_frame.pack(pady=5)

    send_all_button = tk.Button(buttons_frame, text="Send to All", command=send_message_to_all)
    send_all_button.pack(side=tk.LEFT, padx=5)

    send_direct_button = tk.Button(buttons_frame, text="Send to Selected", command=send_direct_message)
    send_direct_button.pack(side=tk.LEFT, padx=5)

    # Initialize server
    server = WiMAXServer()
    server.run()

    # Start updating client list
    update_client_list()

def update_client_list():
    """Update the list of connected clients in the GUI"""
    if clients_listbox is None:
        return

    # Store current selection
    current_selection = clients_listbox.curselection()
    selected_item = None
    if current_selection:
        selected_item = clients_listbox.get(current_selection[0])
    
    # Clear and update the list
    clients_listbox.delete(0, tk.END)
    for client_addr in server.get_connected_clients():
        item_text = f"{client_addr[0]}:{client_addr[1]}"
        clients_listbox.insert(tk.END, item_text)
        
        # Restore selection if it still exists
        if selected_item and selected_item == item_text:
            clients_listbox.selection_set(clients_listbox.size() - 1)
    
    # Schedule next update
    if root:
        root.after(1000, update_client_list)

def send_direct_message():
    """Send a message to the selected client"""
    selection = clients_listbox.curselection()
    if not selection:
        messagebox.showwarning("Warning", "Please select a client first!")
        return
    
    message = message_entry.get()
    if not message:
        messagebox.showwarning("Warning", "Please enter a message!")
        return

    try:
        # Parse the selected client address
        client_str = clients_listbox.get(selection[0])
        host, port = client_str.split(':')
        target_addr = (host, int(port))

        if server.send_direct_message(target_addr, message):
            message_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Failed to send direct message")
    except Exception as e:
        messagebox.showerror("Error", f"Error sending message: {str(e)}")

def send_message_to_all():
    """Broadcast message functionality"""
    message = message_entry.get()
    if not message:
        messagebox.showwarning("Warning", "Please enter a message!")
        return
    server.send_message_to_all(message)
    message_entry.delete(0, tk.END)

if __name__ == "__main__":
    setup_gui()
    root.mainloop()
