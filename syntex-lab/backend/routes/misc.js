'use strict';

const express = require('express');
const router  = express.Router();
const path    = require('path');
const fetch   = require('node-fetch');

// ─── RECON / FINGERPRINTING TARGETS ─────────────────────────────────────────

// robots.txt — VULNERABILITY: Discloses sensitive paths
router.get('/robots.txt', (req, res) => {
    res.type('text/plain').send(`User-agent: *
Disallow: /admin/
Disallow: /admin/users
Disallow: /admin/settings
Disallow: /admin/logs
Disallow: /admin/execute
Disallow: /api/v2/internal/
Disallow: /debug
Disallow: /backup.sql
Disallow: /.env
Disallow: /phpinfo.php
Disallow: /staging/
Disallow: /old-portal/
Disallow: /config.json
Disallow: /api/v1/debug/
Disallow: /metrics
Disallow: /_profiler

# Subdomains (add to /etc/hosts for testing):
# api.syntex.local
# admin.syntex.local
# staging.syntex.local
# dev.syntex.local
# mail.syntex.local
# backup.syntex.local
# vpn.syntex.local
# intranet.syntex.local

Sitemap: http://syntex.local/sitemap.xml
`);
});

// sitemap.xml — reveals hidden structure
router.get('/sitemap.xml', (req, res) => {
    const base = `http://${req.headers.host}`;
    res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${base}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>
  <url><loc>${base}/products</loc><priority>0.9</priority></url>
  <url><loc>${base}/blog</loc><priority>0.8</priority></url>
  <url><loc>${base}/contact</loc><priority>0.5</priority></url>
  <url><loc>${base}/login</loc><priority>0.6</priority></url>
  <url><loc>${base}/register</loc><priority>0.6</priority></url>
  <url><loc>${base}/dashboard</loc><priority>0.7</priority></url>
  <url><loc>${base}/staging/dashboard</loc><priority>0.1</priority></url>
  <url><loc>${base}/old-portal/index</loc><priority>0.1</priority></url>
  <url><loc>${base}/api/v1/docs</loc><priority>0.4</priority></url>
</urlset>`);
});

// security.txt — RFC 9116
router.get('/.well-known/security.txt', (req, res) => {
    res.type('text/plain').send(`Contact: security@syntex.local
Contact: https://syntex.local/contact
Expires: 2025-12-31T23:59:59.000Z
Acknowledgments: https://syntex.local/security/hall-of-fame
Preferred-Languages: en
Canonical: https://syntex.local/.well-known/security.txt
Policy: https://syntex.local/security/policy

# Bug Bounty: In-scope assets are *.syntex.local
# Out of scope: mail.syntex.local, vpn.syntex.local
`);
});

// health — reveals version info
router.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        version: '2.4.1',
        node: process.version,
        uptime: process.uptime(),
        environment: process.env.NODE_ENV,
        db_host: process.env.DB_HOST,
        timestamp: new Date().toISOString(),
    });
});

// ─── EXPOSED SENSITIVE FILES ─────────────────────────────────────────────────

// VULNERABILITY: .env file exposed
router.get('/.env', (req, res) => {
    res.type('text/plain').send(`# Syntex Solutions — Environment Configuration
# DO NOT COMMIT TO VERSION CONTROL

NODE_ENV=production
PORT=3000

# Database
DB_HOST=${process.env.DB_HOST || 'db'}
DB_PORT=5432
DB_NAME=${process.env.DB_NAME || 'syntex_db'}
DB_USER=${process.env.DB_USER || 'syntex_admin'}
DB_PASS=${process.env.DB_PASS || 'Synx@2024!Prod'}

# Auth
SESSION_SECRET=${process.env.SESSION_SECRET || 'syntex_session_secret_2024'}
JWT_SECRET=${process.env.JWT_SECRET || 'secret123'}

# Proof flag for report submission:
LAB_FLAG=${process.env.FLAG_SECRET ? 'FLAG{dotenv_file_publicly_served_u1v2w3x4}' : 'FLAG{dotenv_file_publicly_served_u1v2w3x4}'}

# Cloud
AWS_ACCESS_KEY=${process.env.AWS_ACCESS_KEY || 'AKIAIOSFODNN7EXAMPLE'}
AWS_SECRET_KEY=${process.env.AWS_SECRET_KEY || 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'}
S3_BUCKET=${process.env.S3_BUCKET || 'syntex-uploads-prod'}

# Payments
STRIPE_SK=${process.env.STRIPE_SK || 'sk_live_51Hfake_lab_only'}
STRIPE_PK=${process.env.STRIPE_PK || 'pk_live_51Hfake_lab_only'}

# Internal
INTERNAL_API_KEY=${process.env.INTERNAL_API_KEY || 'int_key_9f8e7d6c5b4a3z2y1x'}
INTERNAL_API_URL=http://10.0.0.50:8080
ADMIN_EMAIL=admin@syntex.local
`);
});

// VULNERABILITY: .git/config exposed
router.get('/.git/config', (req, res) => {
    res.type('text/plain').send(`[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://deploy:ghp_FakeToken1234567890abcdefABCDEF@github.com/syntex-internal/portal.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[branch "staging"]
	remote = origin
	merge = refs/heads/staging
[user]
	email = developer@syntex.local
	name = Syntex CI
`);
});

// VULNERABILITY: Exposed backup file
router.get('/backup.sql', (req, res) => {
    res.type('text/plain').send(`-- Syntex Solutions Database Backup
-- Generated: 2024-12-01 03:00:01 UTC
-- Host: syntex-db-prod.internal
-- Version: PostgreSQL 15.2

-- WARNING: Contains production data — CONFIDENTIAL

INSERT INTO users (id,username,email,password_hash,role) VALUES
(1,'admin','admin@syntex.local','0192023a7bbd73250516f069df18b500','admin'),
(2,'john.doe','john.doe@syntex.local','327a6c4304ad5938eaf0efb6cc3e53dc','user'),
(3,'jane.smith','jane.smith@contoso.com','0d107d09f5bbe40cade3de5c71e9e9b7','user');

-- DB credentials (rotate after restore):
-- Host: syntex-db-prod.rds.amazonaws.com
-- User: syntex_admin
-- Pass: Synx@2024!Prod
-- Key:  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`);
});

// VULNERABILITY: phpinfo.php exposed (fingerprinting)
router.get('/phpinfo.php', (req, res) => {
    res.type('text/html').send(`<html><body>
<h1>PHP Version 8.2.0</h1>
<p>This server uses PHP 8.2.0 (Note: This is a fingerprinting page for lab practice)</p>
<table>
<tr><td>Server API</td><td>Apache 2.4 Handler</td></tr>
<tr><td>Document Root</td><td>/var/www/html</td></tr>
<tr><td>SERVER_ADDR</td><td>172.18.0.2</td></tr>
<tr><td>DB_PASS</td><td>Synx@2024!Prod</td></tr>
</table></body></html>`);
});

// VULNERABILITY: Debug page exposes process environment
router.get('/debug', (req, res) => {
    // Should be removed in production — never was
    const env = { ...process.env };
    res.json({
        warning: 'DEBUG MODE — Remove this endpoint before production deployment',
        lab_flag: 'FLAG{debug_endpoint_dumps_all_env_vars_y5z6a7b8}',
        pid: process.pid,
        node_version: process.version,
        uptime_seconds: process.uptime(),
        cwd: process.cwd(),
        env,
        memory: process.memoryUsage(),
    });
});

// /config.json — leaked config
router.get('/config.json', (req, res) => {
    res.json({
        app_version: '2.4.1',
        api_base: '/api/v1',
        internal_api: process.env.INTERNAL_API_URL,
        internal_key: process.env.INTERNAL_API_KEY,
        jwt_secret: process.env.JWT_SECRET,
        environment: process.env.NODE_ENV,
        features: { debug_mode: true, maintenance_mode: false, verbose_errors: true },
    });
});

// /metrics — fake Prometheus metrics (fingerprinting)
router.get('/metrics', (req, res) => {
    res.type('text/plain').send(`# HELP node_process_uptime_seconds Process uptime
# TYPE node_process_uptime_seconds gauge
node_process_uptime_seconds ${process.uptime()}
# HELP http_requests_total Total HTTP requests
http_requests_total{method="GET",status="200"} 15432
http_requests_total{method="POST",status="200"} 3821
http_requests_total{method="POST",status="500"} 47
# DB connection info
db_pool_size 20
db_pool_idle 18
`);
});

// /staging/ — accessible staging panel
router.get('/staging', (req, res) => {
    res.send(`<html><body><h2>Syntex Staging Environment</h2>
<p>Environment: staging | Debug: enabled | Auth bypass: <code>?bypass=staging2024</code></p>
<p><a href="/login?bypass=staging2024">Login with bypass</a></p></body></html>`);
});

// /old-portal/ — old portal fingerprinting
router.get('/old-portal', (req, res) => {
    res.status(200).send(`<html><body><h2>Syntex Legacy Portal v1.x</h2>
<p>This portal has been deprecated. Please use <a href="/">the new portal</a>.</p>
<!-- TODO: Remove before final cutover. Default creds: admin / OldPortal2022! -->
</body></html>`);
});

// ─── SSRF ENDPOINT ───────────────────────────────────────────────────────────

// POST /api/fetch-url — VULNERABILITY: SSRF
// EDUCATIONAL NOTE: Server fetches attacker-controlled URL.
// In lab: probe Docker internal network (e.g., http://db:5432, http://169.254.169.254/)
router.post('/api/fetch-url', async (req, res) => {
    const { url, method = 'GET' } = req.body;
    if (!url) return res.status(400).json({ error: 'url parameter required' });

    try {
        // VULNERABILITY: No URL scheme/host allowlist — fetches any URL
        const response = await fetch(url, { method, timeout: 5000 });
        const body     = await response.text();
        res.json({
            url,
            status:  response.status,
            headers: Object.fromEntries(response.headers.entries()),
            body:    body.slice(0, 4096),
        });
    } catch (err) {
        // VULNERABILITY: Error message reveals internal network info
        res.json({ url, error: err.message });
    }
});

// GET /page — VULNERABILITY: LFI via template parameter
router.get('/page', (req, res) => {
    const page = req.query.p || 'home';
    // VULNERABILITY: Path traversal — user controls which file is included
    // Payload: /page?p=../../../../etc/passwd
    try {
        const filePath = path.join(__dirname, '../views/pages/', page + '.html');
        const fs = require('fs');
        if (!fs.existsSync(filePath)) {
            // Try to read path directly (LFI)
            const rawPath = path.join('/', page);
            if (fs.existsSync(rawPath)) {
                return res.type('text').send(fs.readFileSync(rawPath, 'utf8'));
            }
            return res.status(404).send('Page not found: ' + page); // Path disclosed
        }
        res.send(fs.readFileSync(filePath, 'utf8'));
    } catch (err) {
        res.status(500).send('Error loading page: ' + err.message);
    }
});

// Redirect shortener — VULNERABILITY: Open redirect
router.get('/go', (req, res) => {
    const { url, next } = req.query;
    const target = url || next;
    if (!target) return res.redirect('/');
    // VULNERABILITY: No validation — redirects to any URL
    res.redirect(target);
});

// /_profiler — Symfony-style debug profiler page (for fingerprinting)
router.get('/_profiler', (req, res) => {
    res.json({
        profiler: 'Syntex Debug Profiler v2.4',
        routes: [
            'GET  /api/v1/users', 'POST /api/v1/fetch-url',
            'GET  /api/v2/internal/config', 'GET  /api/v2/users/export',
            'POST /admin/execute', 'GET  /.env', 'GET  /debug',
        ],
        env_vars: Object.keys(process.env),
    });
});

// /web.config — IIS config (fingerprinting — server responds as if IIS)
router.get('/web.config', (req, res) => {
    res.type('application/xml').send(`<?xml version="1.0"?>
<configuration>
  <connectionStrings>
    <add name="SyntexDB" connectionString="Server=syntex-db;Database=syntex_db;User=syntex_admin;Password=Synx@2024!Prod;" />
  </connectionStrings>
  <appSettings>
    <add key="JWTSecret" value="secret123" />
    <add key="StripeKey" value="sk_live_51Hfake_lab_only" />
  </appSettings>
</configuration>`);
});

module.exports = router;
