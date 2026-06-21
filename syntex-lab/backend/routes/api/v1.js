'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../../database/db');
const { verifyJWT } = require('../../middleware/auth');
const fetch   = require('node-fetch');

// VULNERABILITY: All /api/v1 endpoints have CORS misconfiguration (handled in cors middleware)

// ─── USERS ───────────────────────────────────────────────────────────────────

// GET /api/v1/users — VULNERABILITY: No auth required, returns sensitive fields
router.get('/users', async (req, res) => {
    const { username, email, role } = req.query;
    let q = `SELECT id, username, email, role, first_name, last_name,
                    phone, department, job_title, api_key, bio, created_at, last_login
             FROM users WHERE 1=1`;
    // VULNERABILITY: SQLi
    if (username) q += ` AND username ILIKE '%${username}%'`;
    if (email)    q += ` AND email ILIKE '%${email}%'`;
    if (role)     q += ` AND role = '${role}'`;

    try {
        const result = await db.query(q);
        // VULNERABILITY: Returns api_key for every user — no auth required
        res.json({ count: result.rows.length, users: result.rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/v1/users/me — requires JWT
router.get('/users/me', verifyJWT, async (req, res) => {
    try {
        const result = await db.query(`SELECT * FROM users WHERE id = $1`, [req.jwtUser.id]);
        res.json(result.rows[0] || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/v1/users/:id — VULNERABILITY: IDOR, returns secret_note
router.get('/users/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await db.query(
            // VULNERABILITY: Returns secret_note, api_key — no auth check
            `SELECT id, username, email, role, first_name, last_name,
                    phone, address, department, job_title, api_key, secret_note, bio
             FROM users WHERE id = ${id}`
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// PUT /api/v1/users/:id — VULNERABILITY: IDOR, no CSRF token needed for API calls
router.put('/users/:id', verifyJWT, async (req, res) => {
    const { id } = req.params;
    const { first_name, last_name, email, bio, phone, role } = req.body;
    // VULNERABILITY: No ownership check — any authenticated user can update any user
    try {
        await db.query(
            `UPDATE users SET first_name='${first_name}', last_name='${last_name}',
             email='${email}', bio='${bio}', phone='${phone}',
             role='${role}', updated_at=NOW() WHERE id=${id}`
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── PRODUCTS ────────────────────────────────────────────────────────────────

router.get('/products', async (req, res) => {
    const { category, min_price, max_price } = req.query;
    let q = `SELECT * FROM products WHERE is_active = true`;
    if (category)  q += ` AND category = '${category}'`;
    if (min_price) q += ` AND price >= ${min_price}`;
    if (max_price) q += ` AND price <= ${max_price}`;

    try {
        const result = await db.query(q);
        res.json({ products: result.rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.get('/products/:id', async (req, res) => {
    try {
        const result = await db.query(`SELECT * FROM products WHERE id = ${req.params.id}`);
        if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── ORDERS ──────────────────────────────────────────────────────────────────

// GET /api/v1/orders — VULNERABILITY: Returns ALL orders, not just own
router.get('/orders', verifyJWT, async (req, res) => {
    try {
        // VULNERABILITY: Ignores req.jwtUser.id — returns all orders
        const result = await db.query(
            `SELECT o.*, u.username, u.email, p.name as product_name
             FROM orders o JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id
             ORDER BY o.created_at DESC`
        );
        res.json({ orders: result.rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/v1/orders/:id — VULNERABILITY: IDOR
router.get('/orders/:id', verifyJWT, async (req, res) => {
    const { id } = req.params;
    try {
        // VULNERABILITY: No ownership check
        const result = await db.query(
            `SELECT o.*, u.username, u.email, u.phone, u.address,
                    p.name as product_name, p.sku
             FROM orders o JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id
             WHERE o.id = ${id}`
        );
        if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── JWT TOKEN GENERATION ─────────────────────────────────────────────────────

// POST /api/v1/token — Issues JWT with VULNERABILITY: weak secret, accepts any alg
router.post('/token', async (req, res) => {
    const { username, password } = req.body;
    const crypto = require('crypto');
    const jwt    = require('jsonwebtoken');
    const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');

    try {
        const result = await db.query(
            `SELECT id, username, email, role FROM users
             WHERE username='${username}' AND password_hash='${md5(password)}'`
        );
        if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

        const user  = result.rows[0];
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role, email: user.email },
            process.env.JWT_SECRET || 'secret123', // VULNERABILITY: Weak secret
            { expiresIn: '30d' }                   // VULNERABILITY: Very long expiry
        );
        res.json({ token, user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── SSRF / FETCH PROXY ───────────────────────────────────────────────────────

// POST /api/v1/fetch — VULNERABILITY: SSRF — server fetches any URL
router.post('/fetch', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });

    try {
        // VULNERABILITY: No allowlist — probe internal Docker network, cloud metadata, etc.
        const response = await fetch(url, { timeout: 5000 });
        const body     = await response.text();
        res.json({ status: response.status, headers: Object.fromEntries(response.headers), body: body.slice(0, 4096) });
    } catch (err) {
        res.json({ error: err.message }); // VULNERABILITY: Internal network errors exposed
    }
});

// ─── DEBUG ENDPOINT ───────────────────────────────────────────────────────────

// GET /api/v1/debug/env — VULNERABILITY: Exposes all env vars via API
router.get('/debug/env', (req, res) => {
    res.json({ env: process.env, cwd: process.cwd(), pid: process.pid });
});

// GET /api/v1/docs — Swagger-style endpoint listing (no auth required)
router.get('/docs', (req, res) => {
    res.json({
        openapi: '3.0.0',
        info: { title: 'Syntex API v1', version: '1.0.0' },
        servers: [{ url: '/api/v1' }],
        note: 'Internal API — authentication required for most endpoints',
        internal_key: process.env.INTERNAL_API_KEY,
        endpoints: [
            'GET  /users',          'GET  /users/me',       'GET  /users/:id',
            'PUT  /users/:id',      'GET  /products',       'GET  /products/:id',
            'GET  /orders',         'GET  /orders/:id',     'POST /token',
            'POST /fetch',          'GET  /debug/env',
        ],
    });
});

module.exports = router;
