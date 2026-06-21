'use strict';

// ── OAuth/SSO Simulation — Vulnerable Module ─────────────────────
// Vulnerabilities:
//   1. Missing state parameter (CSRF in OAuth flow)
//   2. Open redirect via unvalidated redirect_uri
//   3. Account takeover via email mismatch
//   4. Role confusion after OAuth login
//   5. Authorization code reuse
//   6. Token exposed in URL (logs, Referer header)
//
// Tools: Burp Suite, manual testing, oauth-scan

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const db      = require('../database/db');

// Fake OAuth provider state (in-memory for demo)
const authCodes   = {};   // code → { userId, scope, redirectUri, used }
const oauthTokens = {};   // token → { userId, scope, expires }

// Fake "connected apps" that use our OAuth
const FAKE_APPS = {
    'app_syntex_mobile': { name: 'Syntex Mobile',   secret: 'mobile_secret_abc123',  redirect_uris: ['syntex://callback'] },
    'app_analytics':     { name: 'Analytics Portal', secret: 'analytics_secret_xyz',   redirect_uris: ['http://localhost:4000/cb'] },
    'app_third_party':   { name: 'ThirdParty Tool',  secret: 'third_party_secret_999', redirect_uris: ['https://thirdparty.example.com/oauth/cb'] },
};

// GET /oauth/authorize
// VULNERABILITY: Missing state parameter validation
// VULNERABILITY: Open redirect — redirect_uri not strictly validated
router.get('/authorize', (req, res) => {
    const { client_id, redirect_uri, response_type, scope, state } = req.query;

    if (!client_id || !redirect_uri || !response_type) {
        return res.status(400).json({ error: 'missing_parameters', error_description: 'client_id, redirect_uri, response_type required' });
    }

    const app = FAKE_APPS[client_id];

    // VULNERABILITY: Accepts any client_id, doesn't verify it exists
    // VULNERABILITY: redirect_uri only loosely checked (prefix match, not exact)
    if (app) {
        const validUri = app.redirect_uris.some(u => redirect_uri.startsWith(u.split('/cb')[0]));
        // VULNERABILITY: Falls through even if validUri is false for unknown clients
    }

    // VULNERABILITY: state parameter not enforced — CSRF in OAuth flow possible
    if (!state) {
        console.warn('[OAUTH] Warning: No state parameter provided — CSRF possible');
    }

    if (!req.session.userId) {
        // Store OAuth params in session then redirect to login
        req.session.oauthParams = { client_id, redirect_uri, response_type, scope, state };
        return res.redirect(`/login?redirect=/oauth/authorize?${new URLSearchParams(req.query)}`);
    }

    res.render('oauth/authorize', {
        title: 'Authorize Application',
        app: app || { name: client_id },
        scope: scope || 'read',
        state,
        redirect_uri,
        client_id,
        user: req.session.user,
    });
});

// POST /oauth/authorize  — user grants permission
router.post('/authorize', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');

    const { client_id, redirect_uri, scope, state, action } = req.body;

    if (action === 'deny') {
        // VULNERABILITY: Open redirect — redirect_uri not validated
        return res.redirect(`${redirect_uri}?error=access_denied&state=${state || ''}`);
    }

    // Generate authorization code
    const code = crypto.randomBytes(16).toString('hex');
    authCodes[code] = {
        userId:      req.session.userId,
        scope:       scope || 'read',
        redirectUri: redirect_uri,
        expiresAt:   Date.now() + 600000,  // 10 min
        used:        false,
        clientId:    client_id,
    };

    // VULNERABILITY: Authorization code + state in URL (logged by servers/proxies)
    const callbackUrl = `${redirect_uri}?code=${code}&state=${state || ''}`;
    res.redirect(callbackUrl);
});

// POST /oauth/token  — exchange code for token
// VULNERABILITY: Authorization code reuse allowed (used flag not enforced strictly)
router.post('/token', async (req, res) => {
    const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    const authCode = authCodes[code];
    if (!authCode) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code not found or expired' });
    }

    // VULNERABILITY: code reuse — doesn't reliably prevent second use
    if (authCode.used && Math.random() > 0.5) {  // intermittent check
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Code already used' });
    }
    authCode.used = true;

    // VULNERABILITY: redirect_uri not validated against original
    // (only compared, not strictly enforced)

    const user = await db.query(`SELECT * FROM users WHERE id=$1`, [authCode.userId]);
    if (!user.rows.length) return res.status(400).json({ error: 'invalid_grant' });

    const token = 'oauth_' + crypto.randomBytes(24).toString('hex');
    oauthTokens[token] = {
        userId:    authCode.userId,
        scope:     authCode.scope,
        expiresAt: Date.now() + 3600000,  // 1 hour
        // VULNERABILITY: Token exposed in JSON response (not HTTPS in lab)
    };

    res.json({
        access_token: token,
        token_type:   'Bearer',
        expires_in:   3600,
        scope:        authCode.scope,
        // VULNERABILITY: User info exposed in token response
        user_id:      user.rows[0].id,
        email:        user.rows[0].email,
        role:         user.rows[0].role,
    });
});

// GET /oauth/userinfo — returns user info for valid token
// VULNERABILITY: Over-fetching — returns more than needed
router.get('/userinfo', async (req, res) => {
    const auth  = req.headers.authorization || '';
    const token = auth.replace('Bearer ', '');

    const tokenData = oauthTokens[token];
    if (!tokenData || tokenData.expiresAt < Date.now()) {
        return res.status(401).json({ error: 'invalid_token' });
    }

    const user = await db.query(`SELECT * FROM users WHERE id=$1`, [tokenData.userId]);
    if (!user.rows.length) return res.status(401).json({ error: 'invalid_token' });

    const u = user.rows[0];
    // VULNERABILITY: Over-fetching — returns sensitive fields
    res.json({
        sub:          u.id,
        email:        u.email,
        name:         `${u.first_name} ${u.last_name}`,
        role:         u.role,
        api_key:      u.api_key,     // Should not be in userinfo
        department:   u.department,
        job_title:    u.job_title,
    });
});

// GET /oauth/callback  — example callback (demonstrates open redirect)
// VULNERABILITY: Accepts any code, any redirect_uri
router.get('/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
        return res.render('oauth/error', { error, user: req.session.user || null });
    }

    if (!code) {
        return res.redirect('/login?error=OAuth+failed');
    }

    // Exchange code for token internally
    const authCode = authCodes[code];
    if (!authCode) {
        return res.redirect('/login?error=Invalid+OAuth+code');
    }

    // VULNERABILITY: No CSRF check — state not validated
    // VULNERABILITY: Account takeover via email mismatch — if OAuth email ≠ existing user
    // a new account is created with attacker-controlled email

    const user = await db.query(`SELECT * FROM users WHERE id=$1`, [authCode.userId]);
    if (user.rows.length) {
        req.session.userId   = user.rows[0].id;
        req.session.username = user.rows[0].username;
        req.session.role     = user.rows[0].role;
        req.session.user     = user.rows[0];
    }

    res.redirect('/dashboard');
});

// GET /oauth/.well-known/openid-configuration  — OIDC discovery
router.get('/.well-known/openid-configuration', (req, res) => {
    const base = `http://${req.headers.host}`;
    res.json({
        issuer:                                base,
        authorization_endpoint:               `${base}/oauth/authorize`,
        token_endpoint:                       `${base}/oauth/token`,
        userinfo_endpoint:                    `${base}/oauth/userinfo`,
        jwks_uri:                             `${base}/oauth/jwks`,
        response_types_supported:            ['code', 'token'],
        grant_types_supported:               ['authorization_code', 'implicit'],
        subject_types_supported:             ['public'],
        id_token_signing_alg_values_supported: ['HS256', 'none'],   // VULNERABILITY: none
        scopes_supported:                    ['openid', 'profile', 'email', 'admin'],
    });
});

// /.well-known/openid-configuration alias
router.get('/jwks', (req, res) => {
    // VULNERABILITY: Exposed JWKS reveals signing key info
    res.json({
        keys: [{
            kty: 'oct',
            use: 'sig',
            alg: 'HS256',
            k:   Buffer.from('secret123').toString('base64'),  // the weak secret
        }],
    });
});

module.exports = router;
