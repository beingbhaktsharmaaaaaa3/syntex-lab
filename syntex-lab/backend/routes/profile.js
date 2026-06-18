'use strict';

const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// GET /profile — redirect to own profile
router.get('/', requireAuth, (req, res) => {
    res.redirect(`/profile/${req.session.userId}`);
});

// GET /profile/:id — VULNERABILITY: IDOR — any auth'd user can view any profile
router.get('/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    try {
        // VULNERABILITY: No ownership check — user can view any profile by changing :id
        // VULNERABILITY: SQL injection in id parameter
        const result = await db.query(
            `SELECT id, username, email, first_name, last_name, phone, address,
                    department, job_title, avatar, bio, api_key, secret_note,
                    role, created_at, last_login
             FROM users WHERE id = ${id}`
        );

        if (result.rows.length === 0) {
            return res.status(404).render('404', { title: '404 Not Found', user: req.session.user });
        }

        const profile = result.rows[0];

        // VULNERABILITY: api_key and secret_note exposed to any authenticated user
        const ordersResult = await db.query(
            `SELECT o.id, o.invoice_number, o.total_price, o.status, o.created_at,
                    p.name as product_name
             FROM orders o JOIN products p ON p.id = o.product_id
             WHERE o.user_id = ${id} ORDER BY o.created_at DESC LIMIT 5`
        );

        res.render('profile', {
            title: `${profile.first_name || profile.username}'s Profile — Syntex`,
            profile,
            recentOrders: ordersResult.rows,
            isOwner: parseInt(id) === req.session.userId,
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// GET /profile/:id/edit — VULNERABILITY: IDOR — can edit any user's profile
router.get('/:id/edit', requireAuth, async (req, res) => {
    const { id } = req.params;
    try {
        // VULNERABILITY: No ownership check
        const result = await db.query(`SELECT * FROM users WHERE id = ${id}`);
        if (result.rows.length === 0) {
            return res.status(404).render('404', { title: '404 Not Found', user: req.session.user });
        }
        res.render('profile-edit', {
            title: 'Edit Profile — Syntex',
            profile: result.rows[0],
            error: null,
            success: null,
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// POST /profile/:id/edit
// VULNERABILITY: CSRF — no CSRF token
// VULNERABILITY: IDOR — no ownership check
// VULNERABILITY: Stored XSS — bio/username not sanitized
router.post('/:id/edit', requireAuth, async (req, res) => {
    const { id } = req.params;
    const { first_name, last_name, phone, address, department, job_title, bio } = req.body;

    try {
        // VULNERABILITY: No ownership check — any user can update any profile
        // VULNERABILITY: No sanitization of bio field (stored XSS)
        await db.query(
            `UPDATE users SET
                first_name = '${first_name}',
                last_name  = '${last_name}',
                phone      = '${phone}',
                address    = '${address}',
                department = '${department}',
                job_title  = '${job_title}',
                bio        = '${bio}',
                updated_at = NOW()
             WHERE id = ${id}`
        );

        // Update session if editing own profile
        if (parseInt(id) === req.session.userId) {
            req.session.user.first_name = first_name;
            req.session.user.last_name  = last_name;
        }

        const result = await db.query(`SELECT * FROM users WHERE id = ${id}`);
        res.render('profile-edit', {
            title: 'Edit Profile — Syntex',
            profile: result.rows[0],
            error: null,
            success: 'Profile updated successfully.',
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// POST /profile/:id/change-email
// VULNERABILITY: CSRF — no token; IDOR — no ownership check
router.post('/:id/change-email', requireAuth, async (req, res) => {
    const { id } = req.params;
    const { new_email } = req.body;

    try {
        await db.query(`UPDATE users SET email = '${new_email}', updated_at = NOW() WHERE id = ${id}`);
        res.json({ success: true, message: 'Email updated.' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// POST /profile/:id/change-password
// VULNERABILITY: CSRF — no token; IDOR — no ownership check; old password not verified
router.post('/:id/change-password', requireAuth, async (req, res) => {
    const crypto = require('crypto');
    const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
    const { id } = req.params;
    const { new_password } = req.body;

    try {
        // VULNERABILITY: Does not verify old password
        const hash = md5(new_password);
        await db.query(`UPDATE users SET password_hash = '${hash}', updated_at = NOW() WHERE id = ${id}`);
        res.json({ success: true, message: 'Password changed.' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

module.exports = router;
