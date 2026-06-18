'use strict';

// ── Enhanced Recon Targets ────────────────────────────────────────
// Practice discovering hidden recon targets used in real bug bounties
// Tools: gobuster, ffuf, katana, gau, waybackurls, LinkFinder, SecretFinder

const express = require('express');
const router  = express.Router();
const path    = require('path');
const fs      = require('fs');

// ── API Documentation (Swagger / OpenAPI) ────────────────────────
// VULNERABILITY: Full API spec exposed including internal endpoints

const openApiSpec = {
    openapi: '3.0.3',
    info: {
        title:   'Syntex Solutions API',
        version: '2.4.1',
        description: 'Internal API documentation — do not expose externally',
        contact: { email: 'developer@syntex.local' },
    },
    servers: [
        { url: 'http://syntex.local/api/v1',       description: 'Production' },
        { url: 'http://api.syntex.local',          description: 'API subdomain' },
        { url: 'http://dev.syntex.local/api/v1',   description: 'Development (verbose errors)' },
        { url: 'http://staging.syntex.local/api/v1', description: 'Staging' },
        { url: 'http://localhost:3000/api/v1',     description: 'Local' },
    ],
    // VULNERABILITY: Internal endpoints exposed in spec
    paths: {
        '/users':                  { get:  { summary: 'List users (no auth required)' } },
        '/users/me':               { get:  { summary: 'Current user (JWT required)' } },
        '/users/{id}':             { get:  { summary: 'Get user by ID (IDOR!)' } },
        '/orders':                 { get:  { summary: 'All orders (ignores user context!)' } },
        '/orders/{id}':            { get:  { summary: 'Order by ID (IDOR!)' } },
        '/token':                  { post: { summary: 'Get JWT token' } },
        '/fetch':                  { post: { summary: 'Server-side URL fetch (SSRF!)' } },
        '/debug/env':              { get:  { summary: 'Dump environment variables' } },
        '/graphql':                { post: { summary: 'GraphQL endpoint (introspection on!)' } },
        '/chat/{roomId}':          { get:  { summary: 'Chat history (no auth, IDOR!)' } },
        '/v2/internal/config':     { get:  { summary: 'Full config dump (no auth!)' } },
        '/v2/users/export':        { get:  { summary: 'Export all users (no auth!)' } },
        '/v2/admin/reset-all':     { post: { summary: 'Reset all passwords' } },
    },
    components: {
        securitySchemes: {
            BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
            ApiKey:     { type: 'apiKey', in: 'header', name: 'X-API-Key' },
        },
    },
    // VULNERABILITY: Leaked credentials in spec
    'x-internal-notes': {
        staging_key:   'sk_staging_9f8e7d6c5b4a',
        jwt_secret:    'secret123',
        db_connection: 'postgresql://syntex_admin:Synx@2024!Prod@db:5432/syntex_db',
    },
};

router.get('/swagger.json',  (req, res) => res.json(openApiSpec));
router.get('/openapi.json',  (req, res) => res.json(openApiSpec));
router.get('/api-docs',      (req, res) => res.json(openApiSpec));
router.get('/api/swagger',   (req, res) => res.json(openApiSpec));
router.get('/api/openapi',   (req, res) => res.json(openApiSpec));

// Swagger UI
router.get('/api-docs/ui', (req, res) => {
    res.type('html').send(`<!DOCTYPE html><html>
<head><title>Syntex API Docs</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.10.0/swagger-ui.min.css">
</head><body>
<div id="swagger-ui"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.10.0/swagger-ui-bundle.min.js"></script>
<script>
SwaggerUIBundle({ url: '/swagger.json', dom_id: '#swagger-ui',
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset] });
</script></body></html>`);
});

// ── JavaScript Source Maps ────────────────────────────────────────
// VULNERABILITY: Source maps expose original source code

const appBundleMap = JSON.stringify({
    version: 3,
    file: 'app.bundle.js',
    sourceRoot: '/app/src/',
    sources: [
        'components/Dashboard.jsx',
        'components/AdminPanel.jsx',
        'utils/api.js',
        'utils/auth.js',
        'config/endpoints.js',
        'config/secrets.js',  // leaked source file name
    ],
    // VULNERABILITY: Leaked secrets in source map metadata
    'x-sourcemap-note': {
        admin_endpoint: '/admin/execute',
        internal_token: 'int_key_9f8e7d6c5b4a3z2y1x',
        jwt_secret:     'secret123',
    },
    mappings: 'AAAA;AACA;AACA',
});

router.get('/js/app.bundle.js.map',  (req, res) => { res.type('json').send(appBundleMap); });
router.get('/js/vendor.bundle.js.map',(req, res) => { res.type('json').send(appBundleMap); });
router.get('/js/main.chunk.js.map',  (req, res) => { res.type('json').send(appBundleMap); });

// Fake JS bundle that references source map
router.get('/js/app.bundle.js', (req, res) => {
    res.type('js').send(`/* Syntex Solutions v2.4.1 — minified */
!function(e){"use strict";}();
const _c={"api":"http://api.syntex.local","key":"sk_live_syntex_8f3a2b1c"};
//# sourceMappingURL=app.bundle.js.map`);
});

// ── OpenID Connect Discovery ──────────────────────────────────────
router.get('/.well-known/openid-configuration', (req, res) => {
    const base = `http://${req.headers.host}`;
    res.json({
        issuer:                 `${base}`,
        authorization_endpoint: `${base}/oauth/authorize`,
        token_endpoint:         `${base}/oauth/token`,
        userinfo_endpoint:      `${base}/oauth/userinfo`,
        jwks_uri:               `${base}/oauth/jwks`,
        scopes_supported:       ['openid','profile','email','admin'],
        response_types_supported: ['code','token','id_token'],
        id_token_signing_alg_values_supported: ['HS256','none'],
        'x-debug': { jwt_secret: 'secret123', db_host: 'db:5432' },
    });
});

// ── Changelog / Version Disclosure ───────────────────────────────
router.get('/CHANGELOG.md', (req, res) => {
    res.type('text').send(`# Syntex Solutions Changelog

## v2.4.1 (2024-12-01)
- Fixed XSS in search results (TODO: verify fix is complete)
- Patched IDOR on /orders/:id (TODO: also fix /tickets/:id)
- Updated dependencies

## v2.4.0 (2024-11-15)
- Added GraphQL API at /graphql (introspection enabled for debugging)
- Added WebSocket support chat
- Added OAuth2 SSO integration

## v2.3.8 (2024-10-01)
- Added /api/v2/internal/ endpoints (internal use only, remove before prod)
- JWT secret rotated to: secret123
- Admin default password: admin123

## v2.3.0 (2024-08-20)
- Migrated from SHA1 to MD5 password hashing (TODO: upgrade to bcrypt)
- Added rate limiting (X-Forwarded-For based, 100 req/min per IP)
`);
});

// ── Crossdomain / Security Headers Info ──────────────────────────
router.get('/crossdomain.xml', (req, res) => {
    res.type('xml').send(`<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <!-- VULNERABILITY: Wildcard crossdomain allows Flash/PDF requests from any domain -->
  <allow-access-from domain="*"/>
  <allow-http-request-headers-from domain="*" headers="*"/>
</cross-domain-policy>`);
});

// ── CDN-specific endpoints (cdn.syntex.local) ────────────────────
router.get('/cdn/manifest.json', (req, res) => {
    res.json({
        name: 'Syntex Solutions',
        version: '2.4.1',
        build_date: '2024-12-01T03:00:00Z',
        git_commit: 'a1b2c3d4e5f6',
        git_branch: 'main',
        // VULNERABILITY: Environment info in manifest
        environment: 'production',
        api_base: 'http://api.syntex.local',
        internal_api: 'http://10.0.0.50:8080',
        cdn_secret: 'cdn_key_x9y8z7w6v5u4t3s2r1q0',
    });
});

// ── Actuator-style endpoints ──────────────────────────────────────
router.get('/actuator',       (req, res) => res.json({ endpoints: ['/actuator/env','/actuator/beans','/actuator/health'] }));
router.get('/actuator/env',   (req, res) => res.json({ properties: { ...process.env } }));
router.get('/actuator/health',(req, res) => res.json({ status: 'UP', db: 'UP', version: '2.4.1' }));

// ── Legacy endpoints ──────────────────────────────────────────────
router.get('/v1/api',     (req, res) => res.redirect('/api/v1'));
router.get('/old/api',    (req, res) => res.redirect('/api/v1'));
router.get('/legacy/api', (req, res) => res.redirect('/api/v1'));

module.exports = router;
