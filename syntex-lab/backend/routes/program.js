'use strict';

// ── Bug Bounty Program Platform ───────────────────────────────────
// Accessible via:
//   http://program.syntex.local  (virtual host)
//   http://localhost:3000/program (direct path)

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

// Mode helper
const getMode = (req) => process.env.LAB_MODE || 'beginner';
const isVisible = (req, feature) => {
    const mode = getMode(req);
    const rules = {
        hints:      { beginner:true, intermediate:true,  hard:false, realistic:false },
        flags:      { beginner:true, intermediate:true,  hard:false, realistic:false },
        challenges: { beginner:true, intermediate:true,  hard:true,  realistic:false },
        solutions:  { beginner:true, intermediate:false, hard:false, realistic:false },
        vuln_names: { beginner:true, intermediate:true,  hard:false, realistic:false },
    };
    return rules[feature]?.[mode] ?? true;
};

// ── /program ─────────────────────────────────────────────────────
router.get('/', async (req, res) => {
    try {
        const [hofR, statsR] = await Promise.all([
            db.query(`SELECT * FROM hall_of_fame ORDER BY rank ASC LIMIT 5`),
            db.query(`SELECT
                (SELECT COUNT(*) FROM reports)                             AS total_reports,
                (SELECT COUNT(*) FROM reports WHERE status='accepted')     AS accepted,
                (SELECT COALESCE(SUM(bounty_amount),0) FROM reports)      AS total_paid,
                (SELECT COUNT(*) FROM vuln_flags)                          AS total_flags`),
        ]);
        res.render('program/index', {
            title: 'Syntex Bug Bounty Program',
            hof: hofR.rows,
            stats: statsR.rows[0],
            mode: getMode(req),
            isVisible: (f) => isVisible(req, f),
            user: req.session.user || null,
        });
    } catch (err) {
        res.render('error', { title:'Error', message:err.message, status:500, user: req.session.user||null });
    }
});

// ── /program/scope ───────────────────────────────────────────────
router.get('/scope', (req, res) => {
    res.render('program/scope', {
        title: 'Program Scope — Syntex Bug Bounty',
        mode: getMode(req),
        user: req.session.user || null,
    });
});

// ── /program/rules ───────────────────────────────────────────────
router.get('/rules', (req, res) => {
    res.render('program/rules', {
        title: 'Rules of Engagement — Syntex Bug Bounty',
        mode: getMode(req),
        user: req.session.user || null,
    });
});

// ── /program/submit ──────────────────────────────────────────────
router.get('/submit', requireAuth, async (req, res) => {
    const flags = await db.query(`SELECT slug, vuln_title, category, points FROM vuln_flags ORDER BY category`);
    res.render('program/submit', {
        title: 'Submit Report — Syntex Bug Bounty',
        availableFlags: flags.rows,
        mode: getMode(req),
        error: null,
        user: req.session.user,
    });
});

router.post('/submit', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const { title, vuln_type, severity, cvss_score, affected_url, steps, impact, proof_of_concept, suggested_fix, flag_slug, flag_submitted } = req.body;

    if (!title || !vuln_type || !severity || !affected_url || !steps || !impact) {
        const flags = await db.query(`SELECT slug, vuln_title, category, points FROM vuln_flags ORDER BY category`);
        return res.render('program/submit', {
            title:'Submit Report', availableFlags:flags.rows, mode:getMode(req),
            error:'All required fields must be filled.', user:req.session.user,
        });
    }

    const r = await db.query(
        `INSERT INTO reports (user_id,title,vuln_type,severity,cvss_score,affected_url,steps,impact,proof_of_concept,suggested_fix,flag_slug,flag_submitted,status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'new') RETURNING id`,
        [uid,title,vuln_type,severity,cvss_score||null,affected_url,steps,impact,proof_of_concept||null,suggested_fix||null,flag_slug||null,flag_submitted||null]
    );
    const reportId = r.rows[0].id;

    // Auto-verify flag
    if (flag_slug && flag_submitted) {
        const flagR = await db.query(`SELECT * FROM vuln_flags WHERE slug=$1 AND LOWER(flag_value)=LOWER($2)`, [flag_slug, flag_submitted.trim()]);
        if (flagR.rows.length) {
            await db.query(`UPDATE reports SET status='accepted',flag_verified=true,verified_at=NOW(),triage_notes=$1 WHERE id=$2`,
                [`🤖 Auto-verified. Flag "${flag_slug}" confirmed. +${flagR.rows[0].points}pts`, reportId]);
            await db.query(`INSERT INTO user_flags (user_id,flag_slug,report_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, [uid, flag_slug, reportId]);
            return res.redirect(`/program/reports/${reportId}?verified=1`);
        }
    }
    res.redirect(`/program/reports/${reportId}`);
});

// ── /program/reports ─────────────────────────────────────────────
router.get('/reports', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const { status } = req.query;
    let q = `SELECT id,title,vuln_type,severity,status,flag_verified,bounty_amount,created_at FROM reports WHERE user_id=$1`;
    const params = [uid];
    if (status) { q += ` AND status=$2`; params.push(status); }
    q += ` ORDER BY created_at DESC`;
    const result = await db.query(q, params);
    res.render('program/reports', {
        title: 'My Reports — Syntex Bug Bounty',
        reports: result.rows,
        filterStatus: status || null,
        mode: getMode(req),
        user: req.session.user,
    });
});

// ── /program/reports/:id ─────────────────────────────────────────
router.get('/reports/:id', requireAuth, async (req, res) => {
    const uid  = req.session.userId;
    const role = req.session.role;
    const result = await db.query(
        `SELECT r.*, u.username AS reporter, t.username AS triager,
                vf.vuln_title AS flag_title, vf.points AS flag_points
         FROM reports r JOIN users u ON u.id=r.user_id
         LEFT JOIN users t ON t.id=r.triaged_by
         LEFT JOIN vuln_flags vf ON vf.slug=r.flag_slug
         WHERE r.id=$1`, [req.params.id]
    );
    if (!result.rows.length) return res.status(404).render('404', { title:'404', user:req.session.user });
    const report = result.rows[0];
    if (report.user_id !== uid && !['admin','support'].includes(role)) {
        return res.status(403).render('error', { title:'Access Denied', message:'You can only view your own reports.', status:403, user:req.session.user });
    }
    res.render('program/report-detail', {
        title: `Report #${report.id}`,
        report,
        isStaff: ['admin','support','developer'].includes(role),
        justVerified: req.query.verified === '1',
        mode: getMode(req),
        user: req.session.user,
    });
});

router.post('/reports/:id/triage', requireAdmin, async (req, res) => {
    const { status, triage_notes, bounty_amount, duplicate_of } = req.body;
    await db.query(
        `UPDATE reports SET status=$1,triage_notes=$2,bounty_amount=$3,duplicate_of=$4,triaged_by=$5,updated_at=NOW() WHERE id=$6`,
        [status, triage_notes||null, parseFloat(bounty_amount)||0, duplicate_of||null, req.session.userId, req.params.id]
    );
    res.redirect(`/program/reports/${req.params.id}`);
});

// ── /program/hints ───────────────────────────────────────────────
router.get('/hints', requireAuth, (req, res) => {
    if (!isVisible(req, 'hints')) {
        return res.render('program/mode-locked', { title:'Hints — Locked', feature:'hints', mode:getMode(req), user:req.session.user });
    }
    res.redirect('/hints');  // reuse existing hints system
});

// ── /program/flags ───────────────────────────────────────────────
router.get('/flags', requireAuth, (req, res) => {
    if (!isVisible(req, 'flags')) {
        return res.render('program/mode-locked', { title:'Flags — Locked', feature:'flags', mode:getMode(req), user:req.session.user });
    }
    res.redirect('/reports/flags');
});

// ── /program/challenges ──────────────────────────────────────────
router.get('/challenges', (req, res) => {
    res.redirect('/challenges');
});

// ── /program/leaderboard ─────────────────────────────────────────
router.get('/leaderboard', async (req, res) => {
    try {
        const [lbR, topReporters] = await Promise.all([
            db.query(`SELECT * FROM hall_of_fame ORDER BY rank ASC`),
            db.query(`SELECT u.username, u.first_name, u.last_name,
                             COUNT(r.id) AS report_count,
                             COUNT(r.id) FILTER (WHERE r.status='accepted') AS accepted,
                             COALESCE(SUM(r.bounty_amount),0) AS total_bounty,
                             COUNT(uf.id) AS flags_captured
                      FROM users u
                      LEFT JOIN reports r ON r.user_id=u.id
                      LEFT JOIN user_flags uf ON uf.user_id=u.id
                      GROUP BY u.id,u.username,u.first_name,u.last_name
                      HAVING COUNT(r.id) > 0
                      ORDER BY accepted DESC, total_bounty DESC
                      LIMIT 20`),
        ]);
        res.render('program/leaderboard', {
            title: 'Leaderboard — Syntex Bug Bounty',
            hof: lbR.rows,
            reporters: topReporters.rows,
            mode: getMode(req),
            user: req.session.user || null,
        });
    } catch (err) {
        res.render('error', { title:'Error', message:err.message, status:500, user:req.session.user||null });
    }
});

// ── /program/hall-of-fame ────────────────────────────────────────
router.get('/hall-of-fame', async (req, res) => {
    const hof = await db.query(`SELECT * FROM hall_of_fame ORDER BY rank ASC`);
    res.render('program/hall-of-fame', {
        title: 'Hall of Fame — Syntex Bug Bounty',
        hof: hof.rows,
        mode: getMode(req),
        user: req.session.user || null,
    });
});

// ── /program/examples/* ─────────────────────────────────────────
router.get('/examples/accepted',       (req, res) => res.render('program/examples/accepted',       { title:'Example: Accepted Report',     mode:getMode(req), user:req.session.user||null }));
router.get('/examples/duplicate',      (req, res) => res.render('program/examples/duplicate',      { title:'Example: Duplicate Report',    mode:getMode(req), user:req.session.user||null }));
router.get('/examples/informative',    (req, res) => res.render('program/examples/informative',    { title:'Example: Informative Report',  mode:getMode(req), user:req.session.user||null }));
router.get('/examples/not-applicable', (req, res) => res.render('program/examples/not-applicable', { title:'Example: Not Applicable Report',mode:getMode(req), user:req.session.user||null }));

// ── /program/admin/reports ── triage dashboard ───────────────────
router.get('/admin/reports', requireAdmin, async (req, res) => {
    const { status } = req.query;
    let q = `SELECT r.id,r.title,r.vuln_type,r.severity,r.status,r.flag_verified,r.bounty_amount,r.created_at,u.username AS reporter
             FROM reports r JOIN users u ON u.id=r.user_id WHERE 1=1`;
    const params = [];
    if (status) { params.push(status); q += ` AND r.status=$${params.length}`; }
    q += ` ORDER BY r.created_at DESC`;
    const result = await db.query(q, params);
    const totals = await db.query(`SELECT status,COUNT(*) n FROM reports GROUP BY status`);
    res.render('admin/reports', {
        title:'Triage Dashboard', reports:result.rows,
        totals:totals.rows, filters:{status}, user:req.session.user,
    });
});

module.exports = router;
