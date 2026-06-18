'use strict';

// VULNERABILITY: CORS misconfiguration
// Reflects any Origin header with Allow-Credentials: true
// This allows cross-origin credential theft from any malicious website

function corsMiddleware(req, res, next) {
    const origin = req.headers.origin;

    if (origin) {
        // VULNERABILITY: Reflects attacker-controlled origin instead of using allowlist
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    } else {
        res.setHeader('Access-Control-Allow-Origin', '*');
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Requested-With');
    res.setHeader('Access-Control-Expose-Headers', 'X-Auth-Token, X-Session-ID');

    // Intentional: Expose internal headers
    res.setHeader('X-Powered-By', 'Syntex/2.4.1 Node.js/20 Express/4.18');
    res.setHeader('X-Syntex-Version', '2.4.1');
    res.setHeader('X-Request-ID', Math.random().toString(36).slice(2));

    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }

    next();
}

module.exports = corsMiddleware;
