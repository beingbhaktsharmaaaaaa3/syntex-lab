'use strict';

// ── WebSocket Support Chat — Vulnerable Module ────────────────────
// Vulnerabilities:
//   1. No authentication on connection (anyone can connect)
//   2. IDOR on room_id — join any room by changing the parameter
//   3. Stored XSS — messages rendered as raw HTML on client
//   4. User impersonation — can set any username/user_id in message
//   5. Message history exposure — /api/v1/chat/:roomId returns all history
//
// Tools: wscat, websocat, Burp Suite WebSocket tab
// Connect: wscat -c "ws://localhost:3000/ws/chat?room=1"

const WebSocket = require('ws');
const db        = require('../database/db');

// In-memory rooms (also persisted to DB)
const rooms = {};

function setupWebSocket(server) {
    const wss = new WebSocket.Server({ server, path: '/ws/chat' });

    wss.on('connection', async (ws, req) => {
        const url    = new URL(req.url, 'http://localhost');
        const roomId = url.searchParams.get('room') || '1';
        // VULNERABILITY: No auth check — userId from query param, fully attacker-controlled
        const userId   = url.searchParams.get('user_id') || null;
        const username = url.searchParams.get('username') || 'Anonymous';

        if (!rooms[roomId]) rooms[roomId] = [];
        rooms[roomId].push(ws);

        // Send message history (VULNERABILITY: history exposed to any unauthenticated user)
        try {
            const history = await db.query(
                `SELECT * FROM chat_messages WHERE room_id=$1 ORDER BY created_at ASC LIMIT 50`,
                [roomId]
            );
            ws.send(JSON.stringify({ type: 'history', messages: history.rows }));
        } catch (_) {
            ws.send(JSON.stringify({ type: 'history', messages: [] }));
        }

        // Send join notification
        const joinMsg = {
            type: 'system',
            content: `${username} joined the chat`,
            timestamp: new Date().toISOString(),
        };
        broadcast(roomId, joinMsg, ws);

        ws.on('message', async (data) => {
            try {
                const parsed = JSON.parse(data.toString());
                const msg = {
                    type:      'message',
                    room_id:   roomId,
                    // VULNERABILITY: User can claim any username/user_id
                    user_id:   parsed.user_id   || userId,
                    username:  parsed.username  || username,
                    // VULNERABILITY: No sanitization — stored XSS
                    // Payload: {"content":"<script>alert(document.cookie)</script>","username":"attacker"}
                    content:   parsed.content   || '',
                    timestamp: new Date().toISOString(),
                };

                // Persist to DB (stored XSS — rendered by client without encoding)
                await db.query(
                    `INSERT INTO chat_messages (room_id, user_id, username, content)
                     VALUES ($1,$2,$3,$4)`,
                    [msg.room_id, msg.user_id || null, msg.username, msg.content]
                );

                broadcast(roomId, msg);
            } catch (err) {
                ws.send(JSON.stringify({ type: 'error', message: err.message }));
            }
        });

        ws.on('close', () => {
            rooms[roomId] = (rooms[roomId] || []).filter(c => c !== ws);
            broadcast(roomId, {
                type: 'system',
                content: `${username} left the chat`,
                timestamp: new Date().toISOString(),
            });
        });

        ws.on('error', console.error);
    });

    return wss;
}

function broadcast(roomId, message, exclude = null) {
    const clients = rooms[roomId] || [];
    const payload = JSON.stringify(message);
    clients.forEach(c => {
        if (c !== exclude && c.readyState === WebSocket.OPEN) {
            c.send(payload);
        }
    });
}

// REST API for chat history (VULNERABILITY: no auth, returns any room's history)
function chatApiRouter(req, res) {
    const express = require('express');
    const router  = express.Router();

    router.get('/rooms', async (req, res) => {
        // VULNERABILITY: Lists all rooms including private support tickets
        const r = await db.query(
            `SELECT room_id, COUNT(*) as message_count, MAX(created_at) as last_activity
             FROM chat_messages GROUP BY room_id ORDER BY last_activity DESC`
        );
        res.json({ rooms: r.rows });
    });

    // VULNERABILITY: IDOR — any room's full history
    router.get('/:roomId', async (req, res) => {
        const r = await db.query(
            `SELECT * FROM chat_messages WHERE room_id=$1 ORDER BY created_at ASC`,
            [req.params.roomId]
        );
        res.json({ room_id: req.params.roomId, messages: r.rows });
    });

    return router;
}

module.exports = { setupWebSocket, chatApiRouter };
