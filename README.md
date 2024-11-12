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
