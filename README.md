# Secure WiMAX Communication Implementation

## Overview
This project implements a secure WiMAX (Worldwide Interoperability for Microwave Access) communication system using Python, featuring a client-server architecture with robust security measures. The implementation includes mutual authentication, session key management, and encrypted communication channels.

## Features

### Security Features
- **RSA Public-Key Infrastructure**
  - 2048-bit RSA key pairs for both client and server
  - Secure key exchange and mutual authentication
- **AES Symmetric Encryption**
  - Secure session key generation
  - CBC mode encryption for message confidentiality
  - PKCS7 padding for block alignment
- **Mutual Authentication Protocol**
  - Challenge-response mechanism
  - Server-client identity verification
  - Protection against man-in-the-middle attacks

### Communication Features
- **Server Broadcasting**
  - UDP broadcast for server discovery
  - Automatic server listing on client side
- **Reliable Communication**
  - TCP-based connection for reliable data transfer
  - Multi-threaded message handling
  - Graceful connection termination

### User Interface
- **Server GUI**
  - Message display panel
  - Broadcast status monitoring
  - Message broadcasting to all clients
  - Connection status tracking
- **Client GUI**
  - Available server discovery and listing
  - Server selection and authentication
  - Message sending/receiving interface
  - Connection status display

## Requirements
- Python 3.x
- Required packages:
  ```
  cryptography
  tkinter (usually comes with Python)
  ```


## Installation

1. Clone the repository:
```bash
git clone https://github.com/Jeevan-2406/Security-in-WiMAX-implementation.git
cd Security-in-WiMAX-implementation
```

2. Install required packages:
```bash
pip install cryptography
```

3. Run the server:
```bash
python wimax_server.py
```

4. Run the client (in a separate terminal):
```bash
python wimax_client.py
```

Note: Make sure to run the server first before starting any clients.

## Quick Start Guide

1. **Starting the Server**
   - Run wimax_server.py
   - The server window will appear showing "Server listening on localhost:12345"
   - Server is now ready to accept client connections

2. **Starting a Client**
   - Run wimax_client.py
   - Wait for the server to appear in the "Available Servers" list
   - Click "Select Server and Authenticate"
   - Once authenticated, you can start sending messages
