## Overview

This project implements a JWKS server in C++.

The server listens on port 8080 and uses `cpp-httplib` for HTTP handling and `jwt-cpp` for JWT token generation.

## Prerequisites
To run this project, you will need the following dependencies:

- **OpenSSL**: For RSA key generation and management.
- **cpp-httplib**: A lightweight HTTP server library in C++.
- **jwt-cpp**: A library to create and verify JWTs.

## Installation/Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/SoraLightStryker/Project1-Gavin-s-JWKS-Server.git
   cd jwks-server

2. Install dependencies:
   - Install OpenSSL
   - Install cpp-httplib
   - Install jwt-cpp
  
3. Compile the project:
   ```bash
   g++ -o jwks_server jwks_server.cpp -lssl -lcrypto -pthread

4. Run the server:
   ```bash
   ./jwks-server

