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

3. **Testing the Connection**
   - Type a message in the client's message box and click "Send Message"
   - The message will be encrypted, sent to the server, and you'll receive an encrypted response
   - You can run multiple clients simultaneously to test the broadcast functionality

4. **Shutting Down**
   - To close a client, type "disconnect" in the message box and send
   - To shut down the server, type "close" in the server's message box and send

## Troubleshooting Common Issues

1. **Server Not Appearing in Client List**
   - Check if the server is running
   - Verify that both server and client are on the same network
   - Check if any firewall is blocking the broadcast port (54321)

2. **Authentication Failed**
   - Restart both server and client
   - Ensure no network interruptions during authentication

3. **Connection Errors**
   - Verify that the default ports (12345 and 54321) are not in use
   - Check network connectivity
   - Ensure Python has necessary permissions

## Security Protocol Flow

1. **Initial Connection**
   - Server broadcasts its presence on the network
   - Client discovers available servers

2. **Authentication Process**
   ```
   Client                                Server
     |                                    |
     |<---- Server's Public Key ---------|
     |                                    |
     |------ Client's Public Key ------->|
     |                                    |
     |<---- Encrypted Challenge ---------|
     |                                    |
     |------ Encrypted Response -------->|
     |                                    |
     |<---- Authentication Result -------|
     |                                    |
     |<---- Encrypted Session Key -------|
   ```

3. **Secure Communication**
   - All messages are encrypted using AES-CBC with the session key
   - Each message includes:
     - Random IV (Initialization Vector)
     - Encrypted payload
     - PKCS7 padding

## Message Encryption Process

1. **Message Preparation**
   - Convert message to bytes
   - Apply PKCS7 padding

2. **Encryption**
   - Generate random IV
   - Use AES-CBC with session key
   - Combine IV and encrypted data
   - Encode in base64

3. **Decryption**
   - Decode from base64
   - Extract IV and encrypted data
   - Decrypt using session key
   - Remove padding
   - Convert to string

## Error Handling
- Connection failures
- Authentication errors
- Encryption/decryption errors
- Network disconnections
- Graceful shutdown procedures

## Limitations and Considerations
- This is a basic implementation for educational purposes
- Not suitable for production use without additional security measures
- Limited to local network communication
- Does not implement full WiMAX protocol specifications
- No certificate authority implementation

## Contributing
Feel free to submit issues and enhancement requests to the [GitHub repository](https://github.com/Jeevan-2406/Security-in-WiMAX-implementation)!

## Acknowledgments
- Built using Python's cryptography library
- Implements basic WiMAX communication concepts
- Uses Tkinter for GUI implementation
