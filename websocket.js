require('dotenv').config();

const express = require('express');
const WebSocket = require('ws');
const https = require('https');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5300;

// SSL certificate and key paths from .env
const options = {
    cert: fs.readFileSync(process.env.SSL_CERT_PATH),
    key: fs.readFileSync(process.env.SSL_KEY_PATH),
    ca: fs.readFileSync(process.env.SSL_CA_PATH),
};

// HTTPS server
const server = https.createServer(options, app);

app.use(express.static(path.join(__dirname, 'public')));

// Read the maximum WebSocket servers from .env (defaults to 17 if not set)
const maxWebSocketServers = parseInt(process.env.MAX_WEBSOCKET_SERVERS, 10) || 17;

// Logs for WebSocket data
let wsLogs = {};

// Initialize log storage dynamically for 0..40
for (let i = 0; i <= 40; i++) {
    wsLogs[`ws${i}`] = [];
}

// WebSocket server map (for the main /ws routes)
const wsServers = {};

// Create a separate log server for `/test-logs`
const logServer = new WebSocket.Server({ noServer: true });

// Broadcast all logs to every connected client
function broadcastLogs() {
    const logs = JSON.stringify(wsLogs);

    // Broadcast to every WS server route
    Object.values(wsServers).forEach((server) => {
        server.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(logs);
            }
        });
    });

    // Also broadcast to the /test-logs server
    logServer.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(logs);
        }
    });
}

// Serve the test HTML page
// This file (test.html) should exist in the "public" folder
app.get('/test', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'test.html'));
});

server.listen(port, () => {
    console.log(`Server started on https://localhost:${port}`);
});

// Secret key for JWT (must be at least 32 characters long)
const secretKey = process.env.JWT_SECRET_KEY;

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
        jwt.verify(token, secretKey, { clockTolerance: 60 }); // 60 seconds tolerance
        return true;
    } catch (error) {
        console.error('Invalid JWT:', error);
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return false;
    }
}

// Create WebSocket servers dynamically for /ws/ws0..wsX
for (let i = 0; i <= maxWebSocketServers; i++) {
    const route = `ws${i}`;
    const wss = new WebSocket.Server({ noServer: true });
    wsServers[route] = wss;

    wss.on('connection', (ws) => {
        console.log(`New client connected to /ws/${route}`);

        ws.on('message', (data) => {
            const isBinary = data instanceof Buffer;
            const message = isBinary ? 'Binary data' : data.toString();
            console.log(`Data received on ${route}:`, message);

            // Save "received" data to logs
            wsLogs[route].push({ type: 'received', data: message });
            if (wsLogs[route].length > 50) wsLogs[route].shift(); // keep logs small

            // Broadcast this message to everyone on the same route
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(data, { binary: isBinary });
                }
            });

            // Save "broadcast" event to logs
            wsLogs[route].push({ type: 'broadcast', data: message });

            // Now broadcast updated logs to all watchers
            broadcastLogs();
        });

        ws.on('close', () => {
            console.log(`Client disconnected from /ws/${route}`);
        });

        ws.on('error', (error) => {
            console.error(`WebSocket error on ${route}:`, error);
        });
    });
}

// Listen for connections to /test-logs
logServer.on('connection', (ws) => {
    console.log('New client connected to /test-logs');
    // Immediately send the current logs upon connection
    ws.send(JSON.stringify(wsLogs));
});

// Handle WebSocket upgrades
server.on('upgrade', (request, socket, head) => {
    const url = request.url.split('?')[0];

    if (url === '/test-logs') {
        // Upgrade to the logServer
        logServer.handleUpgrade(request, socket, head, (ws) => {
            logServer.emit('connection', ws, request);
        });
    } else {
        // Check if the upgrade is for /ws/wsX
        const match = url.match(/^\/ws\/(ws[0-9]+)$/);
        if (match) {
            const route = match[1];
            if (wsServers[route]) {
                // Secure connection with JWT
                if (!verifyJWT(request, socket)) return;
                wsServers[route].handleUpgrade(request, socket, head, (ws) => {
                    wsServers[route].emit('connection', ws, request);
                });
            } else {
                socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
                socket.destroy();
            }
        } else {
            socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
            socket.destroy();
        }
    }
});