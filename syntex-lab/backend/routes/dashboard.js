'use strict';

const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { requireAuth } = require('../middleware/auth');

router.get('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    try {
        const [ordersR, ticketsR, notifR, postsR] = await Promise.all([
            db.query(`SELECT o.id, o.invoice_number, o.total_price, o.status, o.created_at, p.name as product_name
                      FROM orders o JOIN products p ON p.id = o.product_id WHERE o.user_id = $1 ORDER BY o.created_at DESC LIMIT 5`, [uid]),
            db.query(`SELECT id, subject, status, priority, created_at FROM tickets WHERE user_id = $1 ORDER BY created_at DESC LIMIT 5`, [uid]),
            db.query(`SELECT id, title, message, type, is_read, link, created_at FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10`, [uid]),
            db.query(`SELECT bp.id, bp.title, bp.slug, bp.excerpt, bp.created_at, u.username as author
                      FROM blog_posts bp JOIN users u ON u.id = bp.author_id WHERE bp.status = 'published' ORDER BY bp.created_at DESC LIMIT 3`),
        ]);

        const statsR = await db.query(
            `SELECT
               (SELECT COUNT(*) FROM orders WHERE user_id = $1) as total_orders,
               (SELECT COALESCE(SUM(total_price),0) FROM orders WHERE user_id = $1 AND status = 'active') as total_spent,
               (SELECT COUNT(*) FROM tickets WHERE user_id = $1 AND status = 'open') as open_tickets,
               (SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false) as unread_notifs`, [uid]
        );

        res.render('dashboard', {
            title: 'Dashboard — Syntex Solutions',
            user: req.session.user,
            stats: statsR.rows[0],
            recentOrders: ordersR.rows,
            recentTickets: ticketsR.rows,
            notifications: notifR.rows,
            recentPosts: postsR.rows,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

module.exports = router;
