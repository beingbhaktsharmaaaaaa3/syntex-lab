'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { requireAuth } = require('../middleware/auth');

router.get('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    try {
        const result = await db.query(
            `SELECT id, subject, status, priority, category, created_at, updated_at
             FROM tickets WHERE user_id = $1 ORDER BY created_at DESC`, [uid]
        );
        res.render('tickets', {
            title: 'Support Tickets — Syntex Solutions',
            tickets: result.rows,
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// GET /tickets/:id — VULNERABILITY: IDOR + internal notes exposed
router.get('/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    try {
        // VULNERABILITY: No ownership check — any user can read any ticket
        // VULNERABILITY: internal_notes visible to any authenticated user
        const result = await db.query(
            `SELECT t.*, u.username, u.email, u.first_name, u.last_name
             FROM tickets t JOIN users u ON u.id = t.user_id WHERE t.id = ${id}`
        );
        if (!result.rows.length) {
            return res.status(404).render('404', { title: 'Not Found', user: req.session.user });
        }
        const replies = await db.query(
            `SELECT tr.*, u.username FROM ticket_replies tr
             JOIN users u ON u.id = tr.user_id WHERE tr.ticket_id = ${id} ORDER BY tr.created_at`
        );
        res.render('ticket-detail', {
            title: `Ticket #${id} — Syntex Solutions`,
            ticket: result.rows[0],
            replies: replies.rows,
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// POST /tickets — create ticket
router.post('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const { subject, message, priority, category } = req.body;
    try {
        const r = await db.query(
            `INSERT INTO tickets (user_id, subject, message, priority, category)
             VALUES ($1,'${subject}','${message}','${priority || 'medium'}','${category || 'general'}')
             RETURNING id`,
            [uid]
        );
        res.redirect(`/tickets/${r.rows[0].id}`);
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

module.exports = router;
