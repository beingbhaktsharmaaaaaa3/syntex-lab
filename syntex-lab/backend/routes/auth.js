'use strict';

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../database/db');
const { rateLimit } = require('../middleware/auth');

const md5 = (str) => crypto.createHash('md5').update(str).digest('hex');

// GET /login
router.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.render('login', {
        title: 'Sign In — Syntex Solutions',
        error: req.query.error || null,
        redirect: req.query.redirect || '/dashboard',
        user: null,
    });
});

// POST /login — VULNERABILITY: SQL injection, open redirect, weak hashing, no rate limiting
router.post('/login', rateLimit, async (req, res) => {
    const { username, password } = req.body;
    const redirect = req.query.redirect || req.body.redirect || '/dashboard';

    if (!username || !password) {
        return res.render('login', { title: 'Sign In', error: 'Username and password are required.', redirect, user: null });
    }

    try {
        const hashedPassword = md5(password);

        // VULNERABILITY: SQL injection via string concatenation
        const query = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${hashedPassword}' AND is_active = true`;
        const result = await db.query(query);

        if (result.rows.length === 0) {
            // VULNERABILITY: Different error message reveals user existence
            const checkUser = await db.query(`SELECT id FROM users WHERE username = '${username}'`);
            const msg = checkUser.rows.length > 0
                ? 'Incorrect password. Please try again.'
                : 'No account found with that username.';
            return res.render('login', { title: 'Sign In', error: msg, redirect, user: null });
        }

        const user = result.rows[0];

        // Set session — VULNERABILITY: httpOnly: false allows JS access
        req.session.userId   = user.id;
        req.session.username = user.username;
        req.session.role     = user.role;
        req.session.email    = user.email;
        req.session.user     = {
            id: user.id, username: user.username, email: user.email,
            role: user.role, first_name: user.first_name, last_name: user.last_name,
            avatar: user.avatar, api_key: user.api_key,
        };

        // Update last login
        await db.query(`UPDATE users SET last_login = NOW() WHERE id = $1`, [user.id]);

        // VULNERABILITY: Open redirect — no validation on redirect parameter
        return res.redirect(redirect);

    } catch (err) {
        // VULNERABILITY: Expose raw DB error to client
        console.error('[AUTH] Login error:', err);
        return res.render('error', {
            title: 'Server Error',
            message: 'A database error occurred: ' + err.message,
            status: 500,
            user: null,
        });
    }
});

// GET /register
router.get('/register', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.render('register', { title: 'Create Account — Syntex Solutions', error: null, user: null });
});

// POST /register
router.post('/register', async (req, res) => {
    const { username, email, password, confirm_password, first_name, last_name } = req.body;

    if (password !== confirm_password) {
        return res.render('register', { title: 'Create Account', error: 'Passwords do not match.', user: null });
    }

    // VULNERABILITY: No password strength requirements
    if (password.length < 4) {
        return res.render('register', { title: 'Create Account', error: 'Password must be at least 4 characters.', user: null });
    }

    try {
        // VULNERABILITY: No email validation
        const hashedPassword = md5(password);
        const apiKey = 'sk_live_' + crypto.randomBytes(16).toString('hex');

        // VULNERABILITY: SQL injection possible in registration
        const insertQ = `INSERT INTO users (username, email, password_hash, first_name, last_name, api_key)
                         VALUES ('${username}', '${email}', '${hashedPassword}', '${first_name}', '${last_name}', '${apiKey}')
                         RETURNING id, username, role`;
        const result = await db.query(insertQ);
        const user = result.rows[0];

        req.session.userId   = user.id;
        req.session.username = user.username;
        req.session.role     = user.role;
        req.session.user     = { id: user.id, username: user.username, role: user.role, first_name, last_name };

        res.redirect('/dashboard');

    } catch (err) {
        let error = 'Registration failed. Please try again.';
        // VULNERABILITY: DB error info leak
        if (err.message.includes('duplicate key')) {
            error = `Account already exists: ${err.detail || err.message}`;
        } else {
            error = 'Database error: ' + err.message;
        }
        return res.render('register', { title: 'Create Account', error, user: null });
    }
});

// GET /logout
router.get('/logout', (req, res) => {
    // VULNERABILITY: Session not fully invalidated server-side; session ID reuse possible
    req.session.destroy(() => {
        // VULNERABILITY: Open redirect via ?redirect= after logout
        const redirect = req.query.redirect || '/';
        res.clearCookie('connect.sid');
        res.redirect(redirect);
    });
});

// GET /forgot-password
router.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { title: 'Reset Password — Syntex Solutions', message: null, error: null, user: null });
});

// POST /forgot-password — VULNERABILITY: No rate limiting, predictable token, user enumeration
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const result = await db.query(`SELECT id, username FROM users WHERE email = '${email}'`);

        if (result.rows.length === 0) {
            // VULNERABILITY: Different response reveals whether email exists
            return res.render('forgot-password', {
                title: 'Reset Password',
                error: 'No account found with that email address.',
                message: null, user: null,
            });
        }

        const user = result.rows[0];

        // VULNERABILITY: Predictable reset token — MD5 of username + timestamp rounded to hour
        const tokenBase = `${user.username}_${Math.floor(Date.now() / 3600000)}`;
        const token = `reset_${user.username}_${md5(tokenBase)}`;

        await db.query(
            `INSERT INTO password_resets (user_id, token, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '24 hours')`,
            [user.id, token]
        );

        // In real app this would email the link — we just show it (lab convenience)
        return res.render('forgot-password', {
            title: 'Reset Password',
            message: `Password reset link generated. In production this would be emailed. For this lab: /reset-password?token=${token}`,
            error: null, user: null,
        });

    } catch (err) {
        return res.render('error', { title: 'Error', message: err.message, status: 500, user: null });
    }
});

// GET /reset-password
router.get('/reset-password', async (req, res) => {
    const { token } = req.query;

    try {
        // VULNERABILITY: SQL injection in token lookup
        const result = await db.query(
            `SELECT pr.*, u.username FROM password_resets pr
             JOIN users u ON u.id = pr.user_id
             WHERE pr.token = '${token}' AND pr.used = false AND pr.expires_at > NOW()`
        );

        if (result.rows.length === 0) {
            return res.render('reset-password', { title: 'Reset Password', error: 'Invalid or expired reset token.', token: '', user: null });
        }

        res.render('reset-password', { title: 'Set New Password', error: null, token, user: null });

    } catch (err) {
        return res.render('error', { title: 'Error', message: err.message, status: 500, user: null });
    }
});

// POST /reset-password
router.post('/reset-password', async (req, res) => {
    const { token, password, confirm_password } = req.body;

    if (password !== confirm_password) {
        return res.render('reset-password', { title: 'Reset Password', error: 'Passwords do not match.', token, user: null });
    }

    try {
        const result = await db.query(
            `SELECT pr.*, u.id as uid FROM password_resets pr
             JOIN users u ON u.id = pr.user_id
             WHERE pr.token = '${token}' AND pr.used = false AND pr.expires_at > NOW()`
        );

        if (result.rows.length === 0) {
            return res.render('reset-password', { title: 'Reset Password', error: 'Invalid or expired token.', token, user: null });
        }

        const reset = result.rows[0];
        const newHash = md5(password);

        await db.query(`UPDATE users SET password_hash = '${newHash}' WHERE id = ${reset.uid}`);
        await db.query(`UPDATE password_resets SET used = true WHERE token = '${token}'`);

        res.redirect('/login?message=Password+updated+successfully');

    } catch (err) {
        return res.render('error', { title: 'Error', message: err.message, status: 500, user: null });
    }
});

module.exports = router;
