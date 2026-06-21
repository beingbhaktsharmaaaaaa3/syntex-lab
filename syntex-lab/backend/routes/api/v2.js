'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../../database/db');

// VULNERABILITY: No authentication on any /api/v2/internal/ route
// These "internal" endpoints are discoverable via robots.txt, JS source, and wordlist brute-force

// GET /api/v2/internal/config — Broken access control: exposes full app config
router.get('/internal/config', (req, res) => {
    res.json({
        note: 'Internal endpoint — should not be exposed publicly',
        lab_flag: 'FLAG{api_v2_internal_config_no_auth_c9d0e1f2}',
        version: '2.4.1',
        database: {
            host:     process.env.DB_HOST,
            name:     process.env.DB_NAME,
            user:     process.env.DB_USER,
            password: process.env.DB_PASS,         // VULNERABILITY: Password in response
        },
        auth: {
            jwt_secret:     process.env.JWT_SECRET,
            session_secret: process.env.SESSION_SECRET,
        },
        cloud: {
            aws_key:    process.env.AWS_ACCESS_KEY,
            aws_secret: process.env.AWS_SECRET_KEY,
            s3_bucket:  process.env.S3_BUCKET,
        },
        payments: {
            stripe_sk: process.env.STRIPE_SK,
        },
        internal_api: {
            url: process.env.INTERNAL_API_URL,
            key: process.env.INTERNAL_API_KEY,
        },
    });
});

// GET /api/v2/users/export — Broken access control: exports ALL user data including passwords
router.get('/users/export', async (req, res) => {
    try {
        // VULNERABILITY: No auth check — any request can dump entire user table
        const result = await db.query(
            `SELECT id, username, email, password_hash, role, first_name, last_name,
                    phone, address, api_key, secret_note, created_at, last_login
             FROM users ORDER BY id`
        );
        const format = req.query.format || 'json';

        if (format === 'csv') {
            let csv = 'id,username,email,password_hash,role,first_name,last_name,api_key,secret_note\n';
            result.rows.forEach(u => {
                csv += `${u.id},"${u.username}","${u.email}","${u.password_hash}","${u.role}","${u.first_name}","${u.last_name}","${u.api_key}","${u.secret_note}"\n`;
            });
            res.setHeader('Content-Disposition', 'attachment; filename="users_export.csv"');
            return res.type('text/csv').send(csv);
        }

        res.json({ total: result.rows.length, lab_flag: 'FLAG{unauthenticated_user_export_hashes_g3h4i5j6}', users: result.rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/v2/admin/reset-all — Broken access control: resets all user passwords
router.post('/admin/reset-all', async (req, res) => {
    const { confirm } = req.body;
    // VULNERABILITY: Only check is a body parameter, not real auth
    if (confirm !== 'YES_RESET_ALL') {
        return res.status(400).json({ error: 'Send confirm=YES_RESET_ALL to proceed.' });
    }
    try {
        const crypto = require('crypto');
        const newHash = crypto.createHash('md5').update('password123').digest('hex');
        await db.query(`UPDATE users SET password_hash = '${newHash}'`);
        res.json({ success: true, message: 'All passwords reset to: password123' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/v2/tickets/:id — VULNERABILITY: IDOR — includes internal staff notes
router.get('/tickets/:id', async (req, res) => {
    const { id } = req.params;
    try {
        // VULNERABILITY: No auth, no ownership check — internal_notes exposed
        const result = await db.query(
            `SELECT t.*, u.username, u.email FROM tickets t
             JOIN users u ON u.id = t.user_id WHERE t.id = ${id}`
        );
        if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/v2/webhook — VULNERABILITY: SSRF via webhook URL
router.post('/webhook', async (req, res) => {
    const { callback_url, event, data } = req.body;
    if (!callback_url) return res.status(400).json({ error: 'callback_url required' });

    try {
        const fetch = require('node-fetch');
        // VULNERABILITY: Fetches any attacker-controlled URL
        const response = await fetch(callback_url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ event, data }),
            timeout: 5000,
        });
        res.json({ success: true, status: response.status });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// GET /api/v2/avatar — VULNERABILITY: SSRF — fetches image from user-supplied URL
router.post('/avatar', async (req, res) => {
    const { image_url, user_id } = req.body;
    if (!image_url) return res.status(400).json({ error: 'image_url required' });

    try {
        const fetch = require('node-fetch');
        // VULNERABILITY: No scheme/host restriction
        const response = await fetch(image_url, { timeout: 5000 });
        const buffer   = await response.buffer();
        await db.query(`UPDATE users SET avatar = $1 WHERE id = $2`, [image_url, user_id]);
        res.json({ success: true, size: buffer.length });
    } catch (err) {
        res.json({ error: err.message });
    }
});

// GET /api/v2/search — VULNERABILITY: Mass assignment + SQLi
router.get('/search', async (req, res) => {
    const { table, field, value } = req.query;
    // VULNERABILITY: Attacker controls table name and field name
    const allowedTables = ['users', 'products', 'orders', 'blog_posts'];
    if (!allowedTables.includes(table)) {
        return res.status(400).json({ error: 'Invalid table' });
    }
    try {
        // VULNERABILITY: field is not validated — could be any column including password_hash
        const result = await db.query(`SELECT * FROM ${table} WHERE ${field} ILIKE '%${value}%'`);
        res.json({ results: result.rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
