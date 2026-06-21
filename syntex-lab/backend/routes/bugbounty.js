'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');

// GET /bug-bounty  — main program page
router.get('/', async (req, res) => {
    try {
        const hof = await db.query(
            `SELECT * FROM hall_of_fame ORDER BY rank ASC LIMIT 5`
        );
        const stats = await db.query(
            `SELECT
               COUNT(*)                                          AS total_reports,
               COUNT(*) FILTER (WHERE status='accepted')        AS accepted,
               COALESCE(SUM(bounty_amount),0)                   AS total_paid,
               COUNT(*) FILTER (WHERE severity='critical')      AS critical_count
             FROM reports`
        );
        res.render('bugbounty/index', {
            title: 'Bug Bounty Program — Syntex Solutions',
            hof:   hof.rows,
            stats: stats.rows[0],
            user:  req.session.user || null,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user || null });
    }
});

// GET /bug-bounty/scope
router.get('/scope', (req, res) => {
    res.render('bugbounty/scope', {
        title: 'Program Scope — Syntex Bug Bounty',
        user:  req.session.user || null,
    });
});

// GET /bug-bounty/hall-of-fame
router.get('/hall-of-fame', async (req, res) => {
    try {
        const hof = await db.query(`SELECT * FROM hall_of_fame ORDER BY rank ASC`);
        res.render('bugbounty/hall-of-fame', {
            title: 'Hall of Fame — Syntex Bug Bounty',
            hof:   hof.rows,
            user:  req.session.user || null,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user || null });
    }
});

module.exports = router;
