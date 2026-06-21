'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { exec } = require('child_process');
const { requireAdmin } = require('../middleware/auth');

// All admin routes protected by requireAdmin
// VULNERABILITY: requireAdmin only checks req.session.role OR req.cookies.role
// Bypass: set cookie role=admin in browser dev tools
router.use(requireAdmin);

// GET /admin
router.get('/', async (req, res) => {
    try {
        const stats = await db.query(`
            SELECT
                (SELECT COUNT(*) FROM users)    AS total_users,
                (SELECT COUNT(*) FROM orders)   AS total_orders,
                (SELECT COUNT(*) FROM tickets WHERE status='open') AS open_tickets,
                (SELECT COALESCE(SUM(total_price),0) FROM orders WHERE status='active') AS total_revenue
        `);

        const recentUsers = await db.query(
            `SELECT id, username, email, role, created_at, last_login
             FROM users ORDER BY created_at DESC LIMIT 8`
        );
        const recentOrders = await db.query(
            `SELECT o.id, o.invoice_number, o.total_price, o.status, o.created_at,
                    u.username, p.name as product_name
             FROM orders o JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id
             ORDER BY o.created_at DESC LIMIT 8`
        );

        res.render('admin/index', {
            title: 'Admin Dashboard — Syntex Solutions',
            stats: stats.rows[0],
            recentUsers: recentUsers.rows,
            recentOrders: recentOrders.rows,
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// GET /admin/users
router.get('/users', async (req, res) => {
    const { search, role } = req.query;
    let query = `SELECT id, username, email, role, first_name, last_name,
                        is_active, created_at, last_login, api_key
                 FROM users WHERE 1=1`;
    // VULNERABILITY: SQLi in admin user search
    if (search) query += ` AND (username ILIKE '%${search}%' OR email ILIKE '%${search}%')`;
    if (role)   query += ` AND role = '${role}'`;
    query += ` ORDER BY id`;

    try {
        const result = await db.query(query);
        res.render('admin/users', {
            title: 'User Management — Admin',
            users: result.rows,
            filters: { search, role },
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// POST /admin/users/:id/update — VULNERABILITY: Mass assignment, no input validation
router.post('/users/:id/update', async (req, res) => {
    const { id } = req.params;
    const { role, is_active, email } = req.body;
    try {
        await db.query(
            `UPDATE users SET role='${role}', is_active=${is_active}, email='${email}', updated_at=NOW() WHERE id=${id}`
        );
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// POST /admin/users/:id/delete
router.post('/users/:id/delete', async (req, res) => {
    const { id } = req.params;
    // VULNERABILITY: Can delete any user including self/admin
    try {
        await db.query(`DELETE FROM users WHERE id = ${id}`);
        res.redirect('/admin/users');
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// GET /admin/settings
router.get('/settings', (req, res) => {
    // VULNERABILITY: Exposes all env vars to admin (excessive info disclosure)
    const config = {
        db_host:          process.env.DB_HOST,
        db_name:          process.env.DB_NAME,
        db_user:          process.env.DB_USER,
        db_pass:          process.env.DB_PASS,        // password exposed
        jwt_secret:       process.env.JWT_SECRET,     // JWT secret exposed
        session_secret:   process.env.SESSION_SECRET,
        aws_access_key:   process.env.AWS_ACCESS_KEY,
        aws_secret_key:   process.env.AWS_SECRET_KEY, // AWS secret exposed
        stripe_sk:        process.env.STRIPE_SK,
        internal_api_key: process.env.INTERNAL_API_KEY,
        smtp_pass:        process.env.SMTP_PASS,
    };

    res.render('admin/settings', {
        title: 'System Settings — Admin',
        config,
        user: req.session.user,
        success: req.query.saved ? 'Settings saved.' : null,
    });
});

// GET /admin/logs
router.get('/logs', async (req, res) => {
    try {
        const logs = await db.query(
            `SELECT al.*, u.username FROM audit_logs al
             LEFT JOIN users u ON u.id = al.user_id
             ORDER BY al.created_at DESC LIMIT 100`
        );
        res.render('admin/logs', {
            title: 'Audit Logs — Admin',
            logs: logs.rows,
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// POST /admin/ping — VULNERABILITY: Command injection in network utility
// EDUCATIONAL NOTE: Classic OS command injection via unsanitized network tool input.
router.post('/ping', (req, res) => {
    const { host } = req.body;
    if (!host) return res.json({ error: 'Host required' });

    // VULNERABILITY: No sanitization — command injection
    // Payload: host = "127.0.0.1; id"  or  "127.0.0.1 && cat /etc/passwd"
    const cmd = `ping -c 2 ${host}`;

    exec(cmd, { timeout: 8000 }, (err, stdout, stderr) => {
        res.json({
            command: cmd,
            stdout: stdout || '',
            stderr: stderr || '',
            exit_code: err ? err.code : 0,
        });
    });
});

// POST /admin/execute — Hidden endpoint (broken access control — listed in admin panel but no extra auth)
// VULNERABILITY: Arbitrary command execution endpoint
router.post('/execute', (req, res) => {
    const { cmd } = req.body;
    if (!cmd) return res.json({ error: 'Command required' });

    exec(cmd, { timeout: 10000 }, (err, stdout, stderr) => {
        res.json({
            command: cmd,
            output: stdout || stderr || '',
            error: err ? err.message : null,
        });
    });
});

module.exports = router;
