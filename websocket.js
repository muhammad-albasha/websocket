const express = require('express');
const WebSocket = require('ws');
const https = require('https');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5300;

// SSL certificate and key paths
const options = {
    cert: fs.readFileSync('/etc/acme-bu/public/.cert'),
    key: fs.readFileSync('/etc/acme-bu/private/.key'),
    ca: fs.readFileSync('/etc/acme-bu/public/.fullchain')
};

// HTTPS server
const server = https.createServer(options, app);

app.use(express.static(path.join(__dirname, 'public')));

// Simple route for testing HTTPS
app.get('/test', (req, res) => {
    res.send("HTTPS is working!");
});

server.listen(port, () => {
    console.log(`Server started on https://localhost:${port}`);
});

// Secret key for JWT
const secretKey = 'secure_key'; // Must be at least 32 characters long

// Middleware function to verify JWT from the query string with clock tolerance
function verifyJWT(request, socket) {
    const url = new URL(request.url, `https://${request.headers.host}`);
    const token = url.searchParams.get('token');

    if (!token) {
        console.error('JWT is missing');
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return false;
    }

    try {
        // Verify the token with a clock tolerance of 60 seconds
        jwt.verify(token, secretKey, { clockTolerance: 60 }); // 60 seconds tolerance
        return true;
    } catch (error) {
        console.error('Invalid JWT:', error);
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return false;
    }
}

// WebSocket server instances for /ws/ws1 and /ws/ws2
const wss1 = new WebSocket.Server({ noServer: true });
const wss2 = new WebSocket.Server({ noServer: true });

// Broadcast function to send a message to all connected clients
function broadcastMessage(server, message) {
    server.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    });
}

// Handle connections to /ws/ws1
wss1.on('connection', (ws) => {
    console.log('New client connected to /ws/ws1');

    ws.on('message', (data) => {
        const isBinary = data instanceof Buffer;
        console.log('Data received on ws1:', isBinary ? 'Binary data' : data);

        // Broadcast the message to all clients connected to wss1
        wss1.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(data, { binary: isBinary });
            }
        });
    });

    ws.on('close', () => {
        console.log('Client disconnected from /ws/ws1');
    });

    ws.on('error', (error) => {
        console.error('WebSocket error on ws1:', error);
    });
});

// Handle connections to /ws/ws2
wss2.on('connection', (ws) => {
    console.log('New client connected to /ws/ws2');

    ws.on('message', (data) => {
        const isBinary = data instanceof Buffer;
        console.log('Data received on ws2:', isBinary ? 'Binary data' : data);

        // Broadcast the message to all clients connected to wss2
        wss2.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(data, { binary: isBinary });
            }
        });
    });

    ws.on('close', () => {
        console.log('Client disconnected from /ws/ws2');
    });

    ws.on('error', (error) => {
        console.error('WebSocket error on ws2:', error);
    });
});

// Handle WebSocket upgrades for /ws/ws1 and /ws/ws2
server.on('upgrade', (request, socket, head) => {
    console.log(`Upgrade request received: URL = ${request.url}`);

    // Verify the JWT before upgrading the connection
    if (!verifyJWT(request, socket)) {
        return; // End the connection if JWT verification fails
    }

    if (request.url.startsWith('/ws/ws1')) {
        console.log("Matching WebSocket route /ws/ws1 - proceeding with upgrade.");
        wss1.handleUpgrade(request, socket, head, (ws) => {
            wss1.emit('connection', ws, request);
        });
    } else if (request.url.startsWith('/ws/ws2')) {
        console.log("Matching WebSocket route /ws/ws2 - proceeding with upgrade.");
        wss2.handleUpgrade(request, socket, head, (ws) => {
            wss2.emit('connection', ws, request);
        });
    } else {
        console.log(`Invalid WebSocket route: ${request.url} - sending 404 response.`);
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
        socket.destroy();
    }
});
