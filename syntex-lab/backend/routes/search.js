'use strict';

// ─── SEARCH ─────────────────────────────────────────────────────────────────
const express  = require('express');
const router   = express.Router();
const db       = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// GET /search — VULNERABILITY: Reflected XSS + SQLi
router.get('/', async (req, res) => {
    const { q, type } = req.query;
    if (!q) {
        return res.render('search-results', {
            title: 'Search — Syntex Solutions',
            query: '', type: type || 'all',
            results: [], user: req.session.user || null,
        });
    }

    try {
        let products = [], posts = [], users = [];

        if (!type || type === 'all' || type === 'products') {
            // VULNERABILITY: SQLi via q parameter in LIKE clause
            const r = await db.query(
                `SELECT 'product' as result_type, id, name as title, short_desc as excerpt, '/products/'||id as url
                 FROM products WHERE is_active=true AND (name ILIKE '%${q}%' OR description ILIKE '%${q}%')`
            );
            products = r.rows;
        }

        if (!type || type === 'all' || type === 'posts') {
            const r = await db.query(
                `SELECT 'post' as result_type, id, title, excerpt, '/blog/'||slug as url
                 FROM blog_posts WHERE status='published' AND (title ILIKE '%${q}%' OR content ILIKE '%${q}%')`
            );
            posts = r.rows;
        }

        // VULNERABILITY: Admin/developer can search users — no role check
        if (type === 'users') {
            const r = await db.query(
                `SELECT 'user' as result_type, id, username as title, email as excerpt, '/profile/'||id as url
                 FROM users WHERE username ILIKE '%${q}%' OR email ILIKE '%${q}%'`
            );
            users = r.rows;
        }

        res.render('search-results', {
            title: `Search: ${q} — Syntex Solutions`,
            query: q, // VULNERABILITY: Reflected in template with <%- %> (XSS)
            type: type || 'all',
            results: [...products, ...posts, ...users],
            user: req.session.user || null,
        });
    } catch (err) {
        // VULNERABILITY: Raw DB error exposed
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user || null });
    }
});

module.exports = router;
