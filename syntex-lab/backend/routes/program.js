'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { getLabMode, labFeatureVisible, enforceLabMode } = require('../middleware/program');

// ── Flag validation helper ────────────────────────────────────────
async function validateAndAwardFlag(flagSlug, flagValue, userId, reportId) {
    if (!flagSlug || !flagValue) return { valid: false, reason: 'no_flag' };

    // 1. Check flag exists and matches
    const flagR = await db.query(
        `SELECT * FROM vuln_flags WHERE slug=$1 AND is_active=true`, [flagSlug]
    );
    if (!flagR.rows.length) return { valid: false, reason: 'invalid_slug' };

    const vuln = flagR.rows[0];
    if (flagValue.trim().toUpperCase() !== vuln.flag_value.toUpperCase()) {
        return { valid: false, reason: 'wrong_flag', vuln };
    }

    // 2. Check for duplicate by this user
    const dupR = await db.query(
        `SELECT id FROM user_flags WHERE user_id=$1 AND flag_slug=$2`, [userId, flagSlug]
    );
    if (dupR.rows.length > 0) {
        return { valid: true, duplicate: true, reason: 'already_claimed', vuln, points: 0 };
    }

    // 3. First blood check
    const fbR = await db.query(
        `SELECT user_id FROM first_blood_claims WHERE vuln_slug=$1`, [flagSlug]
    );
    const isFirstBlood = fbR.rows.length === 0;
    const bonusPoints  = isFirstBlood ? Math.floor(vuln.points * 0.5) : 0;
    const totalPoints  = vuln.points + bonusPoints;

    // 4. Record user flag
    await db.query(
        `INSERT INTO user_flags (user_id, flag_slug, report_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
        [userId, flagSlug, reportId]
    );

    // 5. Claim first blood
    if (isFirstBlood) {
        await db.query(
            `INSERT INTO first_blood_claims (vuln_slug, user_id, report_id) VALUES ($1,$2,$3)`,
            [flagSlug, userId, reportId]
        );
    }

    // 6. Update researcher stats
    await db.query(`
        INSERT INTO researcher_stats (user_id, total_points, valid_reports, first_bloods)
        VALUES ($1,$2,1,$3)
        ON CONFLICT (user_id) DO UPDATE SET
          total_points  = researcher_stats.total_points  + $2,
          valid_reports = researcher_stats.valid_reports + 1,
          first_bloods  = researcher_stats.first_bloods  + $3,
          updated_at    = NOW()
    `, [userId, totalPoints, isFirstBlood ? 1 : 0]);

    // 7. Update report
    await db.query(`
        UPDATE reports SET
          status             = 'accepted',
          flag_valid         = true,
          vuln_slug          = $1,
          points_awarded     = $2,
          first_blood        = $3,
          flag_verified      = true,
          verified_at        = NOW(),
          validation_message = $4,
          triage_notes       = $5
        WHERE id = $6
    `, [
        flagSlug, totalPoints, isFirstBlood,
        isFirstBlood
            ? `🩸 First Blood! Flag "${flagSlug}" confirmed. +${totalPoints}pts (${vuln.points} base + ${bonusPoints} first blood bonus).`
            : `✅ Flag "${flagSlug}" confirmed. +${totalPoints}pts.`,
        `🤖 Auto-verified. Flag matches ${vuln.vuln_title}. ${isFirstBlood ? '🩸 FIRST BLOOD!' : ''}`,
        reportId,
    ]);

    return { valid: true, duplicate: false, isFirstBlood, vuln, points: totalPoints, bonusPoints };
}

// ── /program ─────────────────────────────────────────────────────
router.get('/', async (req, res) => {
    try {
        const [hofR, statsR] = await Promise.all([
            db.query(`SELECT * FROM hall_of_fame ORDER BY rank ASC LIMIT 5`),
            db.query(`SELECT
                (SELECT COUNT(*) FROM reports)                             AS total_reports,
                (SELECT COUNT(*) FROM reports WHERE status='accepted')     AS accepted,
                (SELECT COALESCE(SUM(bounty_amount),0) FROM reports)      AS total_paid,
                (SELECT COUNT(*) FROM vuln_flags WHERE is_active=true)    AS total_flags`),
        ]);
        res.render('program/index', {
            title:'Syntex Bug Bounty Program', hof:hofR.rows, stats:statsR.rows[0],
            mode:getLabMode(), isVisible:(f)=>labFeatureVisible(f), user:req.session.user||null,
            lab:{ mode:getLabMode(), showHints:labFeatureVisible('hints'), showFlags:labFeatureVisible('flags'), bannerColor:{beginner:'#15803D',intermediate:'#B45309',hard:'#B91C1C',realistic:'#1B3A6B'}[getLabMode()], bannerLabel:getLabMode().toUpperCase(), showBanner:true },
        });
    } catch(err) { res.render('error',{title:'Error',message:err.message,status:500,user:req.session.user||null}); }
});

router.get('/scope',       (req,res) => res.render('program/scope',       { title:'Scope',      mode:getLabMode(), user:req.session.user||null }));
router.get('/rules',       (req,res) => res.render('program/rules',       { title:'Rules',      mode:getLabMode(), user:req.session.user||null }));
router.get('/hall-of-fame',async (req,res) => {
    const hof = await db.query(`SELECT * FROM hall_of_fame ORDER BY rank ASC`);
    res.render('program/hall-of-fame', { title:'Hall of Fame', hof:hof.rows, mode:getLabMode(), user:req.session.user||null });
});

// ── Hints (LAB_MODE gated) — served by /program/hints router ─────
// No redirect needed — mounted directly in server.js

// ── Flags (LAB_MODE gated) ───────────────────────────────────────
router.get('/flags', enforceLabMode('flags'), requireAuth, async (req, res) => {
    try {
        const uid    = req.session.userId;
        const mode   = getLabMode();
        const allR   = await db.query(`SELECT * FROM vuln_flags WHERE is_active=true ORDER BY category, points DESC`);
        const foundR = await db.query(`SELECT flag_slug, found_at FROM user_flags WHERE user_id=$1`, [uid]);
        const foundSlugs = new Set(foundR.rows.map(r => r.flag_slug));
        const foundMap   = {};
        foundR.rows.forEach(r => { foundMap[r.flag_slug] = r.found_at; });

        const fbR = await db.query(`SELECT vuln_slug, user_id FROM first_blood_claims`);
        const fbMap = {};
        fbR.rows.forEach(r => { fbMap[r.vuln_slug] = r.user_id; });

        const statsR = await db.query(`SELECT * FROM researcher_stats WHERE user_id=$1`, [uid]);
        const stats  = statsR.rows[0] || { total_points:0, valid_reports:0, first_bloods:0 };
        const totalPoints = allR.rows.filter(f => foundSlugs.has(f.slug)).reduce((s,f) => s+f.points, 0);

        res.render('program/flags', {
            title:'Flag Hunt', flags:allR.rows, foundSlugs, foundMap, fbMap,
            totalPoints, maxPoints:allR.rows.reduce((s,f)=>s+f.points,0),
            stats, mode, showFlagValues: labFeatureVisible('flag_values') && mode !== 'realistic',
            user:req.session.user,
        });
    } catch(err) { res.render('error',{title:'Error',message:err.message,status:500,user:req.session.user}); }
});

// ── Challenges — served by /program/challenges router ────────────
// No redirect needed — mounted directly in server.js

// ── Submit report ─────────────────────────────────────────────────
router.get('/submit', requireAuth, async (req, res) => {
    const flags = await db.query(`SELECT slug, vuln_title, category, severity, points FROM vuln_flags WHERE is_active=true ORDER BY category, points DESC`);
    res.render('program/submit', {
        title:'Submit Report', availableFlags:flags.rows,
        mode:getLabMode(), error:null, user:req.session.user,
    });
});

router.post('/submit', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const {
        title, vuln_type, severity, cvss_score, affected_url, affected_asset,
        steps, impact, proof_of_concept, suggested_fix, flag_slug, flag_submitted,
    } = req.body;

    if (!title || !vuln_type || !severity || !affected_url || !steps || !impact) {
        const flags = await db.query(`SELECT slug,vuln_title,category,severity,points FROM vuln_flags WHERE is_active=true ORDER BY category`);
        return res.render('program/submit', {
            title:'Submit Report', availableFlags:flags.rows,
            error:'Title, type, severity, endpoint, steps, and impact are all required.',
            mode:getLabMode(), user:req.session.user,
        });
    }

    try {
        const rpt = await db.query(
            `INSERT INTO reports
               (user_id,title,vuln_type,severity,cvss_score,affected_url,affected_asset,
                steps,impact,proof_of_concept,suggested_fix,flag_slug,flag_submitted,status)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'new')
             RETURNING id`,
            [uid, title, vuln_type, severity, cvss_score||null, affected_url, affected_asset||null,
             steps, impact, proof_of_concept||null, suggested_fix||null, flag_slug||null, flag_submitted||null]
        );
        const reportId = rpt.rows[0].id;

        let redirectSuffix = '';
        if (flag_slug && flag_submitted) {
            const result = await validateAndAwardFlag(flag_slug, flag_submitted, uid, reportId);
            if (result.valid && !result.duplicate) {
                redirectSuffix = result.isFirstBlood ? '?verified=1&firstblood=1' : '?verified=1';
            } else if (result.duplicate) {
                await db.query(`UPDATE reports SET status='duplicate', validation_message='You already submitted this flag.', flag_valid=true WHERE id=$1`, [reportId]);
                redirectSuffix = '?duplicate=1';
            } else {
                await db.query(`UPDATE reports SET status='needs_more_info', flag_valid=false, validation_message=$1 WHERE id=$2`, ['Flag submitted but did not match. Manual review required.', reportId]);
            }
        }

        res.redirect(`/program/reports/${reportId}${redirectSuffix}`);
    } catch(err) { res.render('error',{title:'Error',message:err.message,status:500,user:req.session.user}); }
});

// ── Reports list ──────────────────────────────────────────────────
router.get('/reports', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const { status } = req.query;
    let q = `SELECT id,title,vuln_type,severity,status,flag_valid,flag_verified,first_blood,points_awarded,bounty_amount,created_at FROM reports WHERE user_id=$1`;
    const params = [uid];
    if (status) { q += ` AND status=$2`; params.push(status); }
    q += ` ORDER BY created_at DESC`;
    const result = await db.query(q, params);
    res.render('program/reports', {
        title:'My Reports', reports:result.rows, filterStatus:status||null,
        mode:getLabMode(), user:req.session.user,
    });
});

// ── Report detail ─────────────────────────────────────────────────
router.get('/reports/:id', requireAuth, async (req, res) => {
    const uid  = req.session.userId;
    const role = req.session.role;
    const result = await db.query(
        `SELECT r.*, u.username AS reporter, u.first_name, u.last_name,
                t.username AS triager, vf.vuln_title AS flag_title, vf.points AS flag_points,
                vf.severity AS flag_severity, vf.category AS flag_category
         FROM reports r
         JOIN users u ON u.id=r.user_id
         LEFT JOIN users t ON t.id=r.triaged_by
         LEFT JOIN vuln_flags vf ON vf.slug=r.vuln_slug
         WHERE r.id=$1`, [req.params.id]
    );
    if (!result.rows.length) return res.status(404).render('404',{title:'404',user:req.session.user});
    const report = result.rows[0];
    if (report.user_id !== uid && !['admin','support','developer'].includes(role)) {
        return res.status(403).render('error',{title:'Access Denied',message:'You can only view your own reports.',status:403,user:req.session.user});
    }

    // Check first blood
    const fbR = await db.query(`SELECT user_id FROM first_blood_claims WHERE vuln_slug=$1`, [report.vuln_slug||'']);
    const isFirstBloodReport = fbR.rows[0]?.user_id === uid;

    res.render('program/report-detail', {
        title:`Report #${report.id}`, report, isStaff:['admin','support','developer'].includes(role),
        isFirstBloodReport, justVerified:req.query.verified==='1',
        isFirstBlood:req.query.firstblood==='1', isDuplicate:req.query.duplicate==='1',
        mode:getLabMode(), user:req.session.user,
    });
});

// ── Admin triage ──────────────────────────────────────────────────
router.post('/reports/:id/triage', requireAdmin, async (req, res) => {
    const { status, triage_notes, bounty_amount, severity, points_override, duplicate_of } = req.body;
    await db.query(
        `UPDATE reports SET status=$1,triage_notes=$2,bounty_amount=$3,severity=$4,
         points_awarded=COALESCE($5,points_awarded),duplicate_of=$6,triaged_by=$7,updated_at=NOW()
         WHERE id=$8`,
        [status, triage_notes||null, parseFloat(bounty_amount)||0, severity,
         points_override||null, duplicate_of||null, req.session.userId, req.params.id]
    );
    res.redirect(`/program/reports/${req.params.id}`);
});

// Admin triage dashboard — MUST be before any :id param catch
router.get('/admin/reports', requireAdmin, async (req, res) => {
    const { status, severity } = req.query;
    let q = `SELECT r.id,r.title,r.vuln_type,r.severity,r.status,r.flag_valid,r.first_blood,
                    r.flag_submitted,r.points_awarded,r.bounty_amount,r.created_at,
                    u.username AS reporter
             FROM reports r JOIN users u ON u.id=r.user_id WHERE 1=1`;
    const params = [];
    if (status)   { params.push(status);   q += ` AND r.status=$${params.length}`; }
    if (severity) { params.push(severity); q += ` AND r.severity=$${params.length}`; }
    q += ` ORDER BY r.created_at DESC`;
    const result = await db.query(q, params);
    const totals = await db.query(`SELECT status,COUNT(*) n FROM reports GROUP BY status`);
    res.render('admin/reports', {
        title:'Triage Dashboard', reports:result.rows, totals:totals.rows,
        filters:{status,severity}, user:req.session.user,
    });
});

// ── Leaderboard ───────────────────────────────────────────────────
router.get('/leaderboard', async (req, res) => {
    try {
        const [lbR, hofR] = await Promise.all([
            db.query(`SELECT rs.*, u.username, u.first_name, u.last_name,
                             (SELECT COUNT(*) FROM first_blood_claims WHERE user_id=rs.user_id) AS first_bloods_count
                      FROM researcher_stats rs
                      JOIN users u ON u.id=rs.user_id
                      WHERE rs.total_points > 0 OR rs.valid_reports > 0
                      ORDER BY rs.total_points DESC, rs.valid_reports DESC
                      LIMIT 25`),
            db.query(`SELECT * FROM hall_of_fame ORDER BY rank ASC LIMIT 5`),
        ]);
        res.render('program/leaderboard', {
            title:'Leaderboard', reporters:lbR.rows, hof:hofR.rows,
            mode:getLabMode(), user:req.session.user||null,
        });
    } catch(err) { res.render('error',{title:'Error',message:err.message,status:500,user:req.session.user||null}); }
});

// ── Example reports ───────────────────────────────────────────────
router.get('/examples/accepted',       (req,res)=>res.render('program/examples/accepted',       {title:'Example: Accepted',     mode:getLabMode(),user:req.session.user||null}));
router.get('/examples/duplicate',      (req,res)=>res.render('program/examples/duplicate',      {title:'Example: Duplicate',    mode:getLabMode(),user:req.session.user||null}));
router.get('/examples/informative',    (req,res)=>res.render('program/examples/informative',    {title:'Example: Informative',  mode:getLabMode(),user:req.session.user||null}));
router.get('/examples/not-applicable', (req,res)=>res.render('program/examples/not-applicable', {title:'Example: N/A',          mode:getLabMode(),user:req.session.user||null}));

module.exports = router;
