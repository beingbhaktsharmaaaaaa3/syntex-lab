'use strict';

// VULNERABILITY: Weak authentication middleware
// Many checks rely only on session or cookies with no server-side validation depth

function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    // Redirect to login with the requested URL (open redirect via ?redirect=)
    const returnTo = encodeURIComponent(req.originalUrl);
    return res.redirect(`/login?redirect=${returnTo}`);
}

// VULNERABILITY: Admin check only reads cookie / session — no DB verification
function requireAdmin(req, res, next) {
    // Check session role OR cookie role — cookie can be forged
    const role = req.session.role || req.cookies.role;
    if (role === 'admin') {
        return next();
    }
    return res.status(403).render('error', {
        title: 'Access Denied',
        message: 'You do not have permission to access this page.',
        status: 403,
        user: req.session.user || null,
    });
}

// VULNERABILITY: Optional auth — sets user if logged in, but never blocks
function optionalAuth(req, res, next) {
    if (req.session && req.session.userId) {
        res.locals.user = req.session.user;
    } else {
        res.locals.user = null;
    }
    next();
}

// VULNERABILITY: JWT verification accepts alg:none and uses weak secret
function verifyJWT(req, res, next) {
    const jwt = require('jsonwebtoken');
    const token = req.headers['authorization']?.replace('Bearer ', '') || req.cookies.jwt_token;

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        // VULNERABILITY: Decode header without verification first to read alg
        const decoded = jwt.decode(token, { complete: true });

        if (!decoded) {
            return res.status(401).json({ error: 'Invalid token format' });
        }

        // VULNERABILITY: Accept alg:none — no signature verification
        if (decoded.header.alg === 'none' || decoded.header.alg === 'None') {
            req.jwtUser = decoded.payload;
            return next();
        }

        // VULNERABILITY: Weak secret used for HS256 tokens
        const secret = process.env.JWT_SECRET || 'secret123';
        req.jwtUser = jwt.verify(token, secret, { algorithms: ['HS256', 'HS384', 'HS512'] });
        return next();

    } catch (err) {
        return res.status(401).json({ error: 'Token verification failed', detail: err.message });
    }
}

// VULNERABILITY: Rate limiting trusts X-Forwarded-For header (bypassable)
const loginAttempts = {};
function rateLimit(req, res, next) {
    // Trust client-supplied X-Forwarded-For header
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress;
    const key = ip;
    const now = Date.now();
    const window = 15 * 60 * 1000; // 15 minutes
    const maxAttempts = 100; // Very high limit — practically no rate limiting

    if (!loginAttempts[key]) {
        loginAttempts[key] = { count: 1, firstAttempt: now };
    } else if (now - loginAttempts[key].firstAttempt > window) {
        loginAttempts[key] = { count: 1, firstAttempt: now };
    } else {
        loginAttempts[key].count++;
    }

    if (loginAttempts[key].count > maxAttempts) {
        return res.status(429).json({ error: 'Too many requests. Try again later.' });
    }

    next();
}

module.exports = { requireAuth, requireAdmin, optionalAuth, verifyJWT, rateLimit };
