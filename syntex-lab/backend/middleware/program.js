'use strict';

// ── Program Platform Middleware ───────────────────────────────────
// Ensures bug bounty features are only accessible from
// program.syntex.local or via /program prefix.
// Returns 404 (not redirect) on the main site to avoid leaking URLs.

const PROGRAM_PATHS = ['/hints', '/reports', '/challenges', '/flags', '/bug-bounty', '/hall-of-fame', '/leaderboard', '/scope', '/solutions'];

// Middleware: blocks legacy bounty paths on main site
function blockBountyOnMainSite(req, res, next) {
    const host  = req.headers['x-vhost'] || req.headers.host || '';
    const isProgram = host.startsWith('program.') || host.startsWith('bounty.') || req.url.startsWith('/program');

    if (isProgram) return next();

    const path = req.path.toLowerCase();
    const isBountyPath = PROGRAM_PATHS.some(p => path.startsWith(p));

    if (isBountyPath) {
        // Return 404 instead of redirect so hunters can't discover the platform URL
        return res.status(404).render('404', {
            title: '404 — Page Not Found',
            path:  req.path,
            user:  req.session.user || null,
        });
    }
    next();
}

// Middleware: require program host for /program/* routes
function requireProgramHost(req, res, next) {
    next(); // Always allow /program/* (already routed correctly)
}

// LAB_MODE visibility helper (used in routes + views)
function getLabMode() {
    return (process.env.LAB_MODE || 'beginner').toLowerCase();
}

function labFeatureVisible(feature) {
    const mode  = getLabMode();
    const rules = {
        hints:        { beginner:true,  intermediate:true,  hard:false, realistic:false },
        flags:        { beginner:true,  intermediate:true,  hard:false, realistic:false },
        challenges:   { beginner:true,  intermediate:true,  hard:true,  realistic:false },
        solutions:    { beginner:true,  intermediate:false, hard:false, realistic:false },
        vuln_names:   { beginner:true,  intermediate:true,  hard:false, realistic:false },
        flag_values:  { beginner:true,  intermediate:false, hard:false, realistic:false },
        leaderboard:  { beginner:true,  intermediate:true,  hard:true,  realistic:true  },
        examples:     { beginner:true,  intermediate:true,  hard:true,  realistic:false },
    };
    return rules[feature]?.[mode] ?? true;
}

// Middleware: enforce LAB_MODE on hint routes
function enforceLabMode(feature) {
    return (req, res, next) => {
        if (!labFeatureVisible(feature)) {
            const mode = getLabMode();
            return res.status(403).render('program/mode-locked', {
                title:   `${feature.charAt(0).toUpperCase()+feature.slice(1)} — Locked`,
                feature,
                mode,
                user:    req.session.user || null,
                lab:     {
                    mode,
                    bannerColor: { beginner:'#15803D', intermediate:'#B45309', hard:'#B91C1C', realistic:'#1B3A6B' }[mode],
                    bannerLabel: mode.toUpperCase(),
                },
            });
        }
        next();
    };
}

module.exports = { blockBountyOnMainSite, requireProgramHost, enforceLabMode, getLabMode, labFeatureVisible };
