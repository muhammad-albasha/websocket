
# WebSocket Secure Server with JWT Authentication

This repository contains a Node.js project for creating an HTTPS and WebSocket server with JWT (JSON Web Token) authentication. It supports two WebSocket endpoints (`/ws/ws1` and `/ws/ws2`) that use token verification for secure communication.

## Features

- **HTTPS Server**: The server runs on HTTPS with SSL/TLS.
- **JWT Authentication**: Token verification is applied to WebSocket connections for added security.
- **WebSocket Support**: Two WebSocket endpoints `/ws/ws1` and `/ws/ws2` to handle real-time bidirectional communication.
- **Broadcasting**: The server supports broadcasting messages to all connected clients within each WebSocket endpoint.

## Prerequisites

- **Node.js** (version 14+ recommended)
- SSL/TLS certificates:
  - Certificate (`.cert`)
  - Private key (`.key`)
  - Fullchain file (`.fullchain`)

## Setup

1. Install the necessary dependencies by running:

   ```bash
   npm install express ws https path fs jwt
   ```

2. Ensure your SSL certificates are placed in the appropriate paths defined in `options`:

   ```javascript
   const options = {
       cert: fs.readFileSync('/etc/acme-bu/public/.cert'),
       key: fs.readFileSync('/etc/acme-bu/private/.key'),
       ca: fs.readFileSync('/etc/acme-bu/public/.fullchain')
   };
   ```

3. Set a secret key in the code for JWT verification.

   ```javascript
   const secretKey = 'secure_key'; // Replace with your own secure key
   ```

4. Start the server by running:

   ```bash
   node <filename>.js
   ```

## Usage

- Access `https://localhost:<port>/test` to check if the HTTPS server is running correctly.
- Use WebSocket client connections to `/ws/ws1` or `/ws/ws2` with a valid JWT in the query string for authentication.

## Structure

- **HTTPS Server**: Serves static files and handles HTTPS requests.
- **WebSocket Servers**: Two WebSocket instances (`wss1` and `wss2`) handle WebSocket connections.
- **JWT Verification**: Middleware function `verifyJWT` authenticates WebSocket connections based on JWT tokens.

## Example JWT Authentication

Generate a JWT token with:

```javascript
const jwt = require('jsonwebtoken');
const token = jwt.sign({ data: 'yourData' }, 'secure_key', { expiresIn: '1h' });
```

## License

This project is open-source.
