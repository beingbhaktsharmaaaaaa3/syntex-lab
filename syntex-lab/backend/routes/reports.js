'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const VALID_STATUSES = ['new','needs_more_info','accepted','duplicate','informative','not_applicable','resolved'];

// ── Helper: verify a submitted flag ──────────────────────────────
async function verifyFlag(flagSlug, flagValue, userId, reportId) {
    if (!flagSlug || !flagValue) return { verified: false, points: 0, title: null };

    const result = await db.query(
        `SELECT * FROM vuln_flags WHERE slug = $1 AND LOWER(flag_value) = LOWER($2)`,
        [flagSlug, flagValue.trim()]
    );

    if (result.rows.length === 0) return { verified: false, points: 0, title: null };

    const flag = result.rows[0];

    // Record in user_flags (ignore duplicates)
    await db.query(
        `INSERT INTO user_flags (user_id, flag_slug, report_id)
         VALUES ($1,$2,$3) ON CONFLICT (user_id, flag_slug) DO NOTHING`,
        [userId, flagSlug, reportId]
    );

    return { verified: true, points: flag.points, title: flag.vuln_title };
}

// ── GET /reports ─────────────────────────────────────────────────
router.get('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const { status } = req.query;

    let q = `SELECT id,title,vuln_type,severity,status,flag_verified,bounty_amount,created_at,updated_at
             FROM reports WHERE user_id = $1`;
    const params = [uid];
    if (status) { q += ` AND status = $2`; params.push(status); }
    q += ` ORDER BY created_at DESC`;

    try {
        const result  = await db.query(q, params);
        const counts  = await db.query(
            `SELECT status, COUNT(*) AS n FROM reports WHERE user_id=$1 GROUP BY status`, [uid]
        );
        const statusMap = {};
        counts.rows.forEach(r => { statusMap[r.status] = parseInt(r.n); });

        // How many flags has this user captured?
        const flagCount = await db.query(
            `SELECT COUNT(*) AS n FROM user_flags WHERE user_id=$1`, [uid]
        );
        const totalFlags = await db.query(`SELECT COUNT(*) AS n FROM vuln_flags`);

        res.render('reports/list', {
            title: 'My Reports — Syntex Bug Bounty',
            reports: result.rows,
            statusMap,
            filterStatus: status || null,
            flagProgress: { found: parseInt(flagCount.rows[0].n), total: parseInt(totalFlags.rows[0].n) },
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title:'Error', message:err.message, status:500, user:req.session.user });
    }
});

// ── GET /reports/flags  — flag hunt scoreboard ───────────────────
router.get('/flags', requireAuth, async (req, res) => {
    try {
        const uid   = req.session.userId;
        const all   = await db.query(`SELECT * FROM vuln_flags ORDER BY category, points DESC`);
        const found = await db.query(
            `SELECT flag_slug, found_at FROM user_flags WHERE user_id=$1`, [uid]
        );
        const foundSlugs = new Set(found.rows.map(r => r.flag_slug));
        const foundMap   = {};
        found.rows.forEach(r => { foundMap[r.flag_slug] = r.found_at; });

        const totalPoints = all.rows
            .filter(f => foundSlugs.has(f.slug))
            .reduce((s, f) => s + f.points, 0);

        res.render('reports/flags', {
            title: 'Flag Hunt — Syntex Bug Bounty',
            flags: all.rows,
            foundSlugs,
            foundMap,
            totalPoints,
            maxPoints: all.rows.reduce((s,f) => s+f.points, 0),
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title:'Error', message:err.message, status:500, user:req.session.user });
    }
});

// ── GET /reports/new ─────────────────────────────────────────────
router.get('/new', requireAuth, async (req, res) => {
    const flags = await db.query(`SELECT slug, vuln_title, category, points FROM vuln_flags ORDER BY category`);
    res.render('reports/new', {
        title: 'Submit Bug Report — Syntex Bug Bounty',
        availableFlags: flags.rows,
        error: null,
        user: req.session.user,
    });
});

// ── POST /reports  — submit + auto-verify ────────────────────────
router.post('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const {
        title, vuln_type, severity, cvss_score, affected_url,
        steps, impact, proof_of_concept, suggested_fix,
        flag_slug, flag_submitted,
    } = req.body;

    if (!title || !vuln_type || !severity || !affected_url || !steps || !impact) {
        const flags = await db.query(`SELECT slug, vuln_title, category, points FROM vuln_flags ORDER BY category`);
        return res.render('reports/new', {
            title:'Submit Bug Report', availableFlags:flags.rows,
            error:'Title, type, severity, URL, steps and impact are all required.',
            user:req.session.user,
        });
    }

    try {
        // Insert report first to get the ID
        const insertResult = await db.query(
            `INSERT INTO reports
               (user_id,title,vuln_type,severity,cvss_score,affected_url,
                steps,impact,proof_of_concept,suggested_fix,
                flag_slug,flag_submitted,status)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'new')
             RETURNING id`,
            [uid, title, vuln_type, severity, cvss_score||null, affected_url,
             steps, impact, proof_of_concept||null, suggested_fix||null,
             flag_slug||null, flag_submitted||null]
        );

        const reportId = insertResult.rows[0].id;

        // ── FLAG VERIFICATION ────────────────────────────────────
        if (flag_slug && flag_submitted) {
            const { verified, points, title: flagTitle } = await verifyFlag(
                flag_slug, flag_submitted, uid, reportId
            );

            if (verified) {
                // Auto-accept and mark verified
                await db.query(
                    `UPDATE reports SET
                       status        = 'accepted',
                       flag_verified = true,
                       verified_at   = NOW(),
                       triage_notes  = $1
                     WHERE id = $2`,
                    [`🤖 Auto-verified via flag submission. Flag "${flag_slug}" confirmed correct. +${points} pts.`, reportId]
                );
                return res.redirect(`/reports/${reportId}?verified=1`);
            } else {
                // Wrong flag — note it but keep as new
                await db.query(
                    `UPDATE reports SET
                       triage_notes = 'Flag submitted but did not match. Manual verification required.'
                     WHERE id = $1`,
                    [reportId]
                );
            }
        }

        res.redirect(`/reports/${reportId}`);
    } catch (err) {
        res.render('error', { title:'Error', message:err.message, status:500, user:req.session.user });
    }
});

// ── GET /reports/:id ─────────────────────────────────────────────
router.get('/:id', requireAuth, async (req, res) => {
    const uid  = req.session.userId;
    const role = req.session.role;
    const { id } = req.params;

    try {
        const result = await db.query(
            `SELECT r.*, u.username AS reporter, u.first_name, u.last_name,
                    t.username AS triager,
                    vf.vuln_title AS flag_title, vf.points AS flag_points
             FROM reports r
             JOIN users u ON u.id = r.user_id
             LEFT JOIN users t ON t.id = r.triaged_by
             LEFT JOIN vuln_flags vf ON vf.slug = r.flag_slug
             WHERE r.id = $1`, [id]
        );

        if (!result.rows.length) return res.status(404).render('404', { title:'404', user:req.session.user });

        const report = result.rows[0];

        if (report.user_id !== uid && !['admin','support','developer'].includes(role)) {
            return res.status(403).render('error', {
                title:'Access Denied', message:'You can only view your own reports.',
                status:403, user:req.session.user,
            });
        }

        // All flags for dropdown (admin triage use)
        const allFlags = await db.query(`SELECT slug, vuln_title, category FROM vuln_flags ORDER BY category`);

        res.render('reports/detail', {
            title: `Report #${report.id} — ${report.title}`,
            report,
            isStaff:       ['admin','support','developer'].includes(role),
            validStatuses: VALID_STATUSES,
            allFlags:      allFlags.rows,
            justVerified:  req.query.verified === '1',
            user:          req.session.user,
        });
    } catch (err) {
        res.render('error', { title:'Error', message:err.message, status:500, user:req.session.user });
    }
});

// ── POST /reports/:id/triage  — staff triage ─────────────────────
router.post('/:id/triage', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { status, triage_notes, bounty_amount, duplicate_of } = req.body;

    if (!VALID_STATUSES.includes(status)) return res.status(400).json({ error:'Invalid status' });

    await db.query(
        `UPDATE reports SET
           status=$1, triage_notes=$2, bounty_amount=$3,
           duplicate_of=$4, triaged_by=$5, updated_at=NOW()
         WHERE id=$6`,
        [status, triage_notes||null, parseFloat(bounty_amount)||0,
         duplicate_of||null, req.session.userId, id]
    );
    res.redirect(`/reports/${id}`);
});

// ── Admin triage dashboard ────────────────────────────────────────
router.get('/admin/all', requireAdmin, async (req, res) => {
    const { status, severity } = req.query;
    let q = `SELECT r.id,r.title,r.vuln_type,r.severity,r.status,r.flag_verified,
                    r.bounty_amount,r.created_at, u.username AS reporter
             FROM reports r JOIN users u ON u.id=r.user_id WHERE 1=1`;
    const params = [];
    if (status)   { params.push(status);   q += ` AND r.status=$${params.length}`; }
    if (severity) { params.push(severity); q += ` AND r.severity=$${params.length}`; }
    q += ` ORDER BY r.created_at DESC`;

    const result = await db.query(q, params);
    const totals = await db.query(`SELECT status, COUNT(*) n FROM reports GROUP BY status`);
    res.render('admin/reports', {
        title:'Report Triage — Admin', reports:result.rows,
        totals:totals.rows, filters:{status,severity}, user:req.session.user,
    });
});

module.exports = router;
