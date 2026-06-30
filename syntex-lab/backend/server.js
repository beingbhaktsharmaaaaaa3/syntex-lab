'use strict';

const http         = require('http');
const express      = require('express');
const session      = require('express-session');
const cookieParser = require('cookie-parser');
const path         = require('path');

const app = express();

// ─── View engine ──────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Body parsers ─────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ─── Session (intentionally weak config) ─────────────────────────
app.use(session({
    secret: process.env.SESSION_SECRET || 'syntex_session_secret_2024',
    resave: true,
    saveUninitialized: true,
    name: 'SYNTEX_SESS',
    cookie: { httpOnly: false, secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 },
}));

// ─── CORS (misconfigured — reflects any origin) ───────────────────
app.use(require('./middleware/cors'));

// ─── LAB_MODE globals ─────────────────────────────────────────────
const { getLabMode, labFeatureVisible, blockBountyOnMainSite } = require('./middleware/program');

app.use((req, res, next) => {
    const mode = getLabMode();
    res.locals.labMode = mode;
    res.locals.lab = {
        mode,
        showHints:      labFeatureVisible('hints'),
        showFlags:      labFeatureVisible('flags'),
        showChallenges: labFeatureVisible('challenges'),
        showSolutions:  labFeatureVisible('solutions'),
        showBanner:     true,
        bannerColor:    { beginner:'#15803D', intermediate:'#B45309', hard:'#B91C1C', realistic:'#1B3A6B' }[mode] || '#1B3A6B',
        bannerLabel:    mode.toUpperCase(),
    };
    // Intentional fingerprinting headers
    res.setHeader('X-Powered-By',    `Syntex/2.4.1 Node.js/${process.version}`);
    res.setHeader('X-Syntex-Version','2.4.1');
    res.setHeader('Server',          'nginx/1.24.0');
    next();
});

// ─── Session user → locals ────────────────────────────────────────
app.use((req, res, next) => {
    res.locals.user    = req.session.user    || null;
    res.locals.isAdmin = req.session.role === 'admin' || req.cookies.role === 'admin';
    next();
});

// ─── Virtual host → rewrite to /program ──────────────────────────
app.use((req, res, next) => {
    const vhost = req.headers['x-vhost'] || '';
    const host  = req.headers.host       || '';
    if ((vhost === 'program' || host.startsWith('program.') || host.startsWith('bounty.'))
        && !req.url.startsWith('/program')) {
        req.url = '/program' + (req.url === '/' ? '' : req.url);
    }
    next();
});

// ─── Static files ─────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Recon targets (swagger, openapi, source maps) ───────────────
app.use('/', require('./routes/recon'));

// ─── GraphQL ──────────────────────────────────────────────────────
const { graphqlHandler } = require('./routes/graphql');
app.get('/graphql',  graphqlHandler);
app.post('/graphql', graphqlHandler);

// ─── OAuth / OIDC ─────────────────────────────────────────────────
app.use('/oauth', require('./routes/oauth'));

// ─── Race condition lab ───────────────────────────────────────────
app.use('/race', require('./routes/race'));

// ─── Core app routes ──────────────────────────────────────────────
app.use('/',          require('./routes/misc'));
app.use('/',          require('./routes/auth'));

// ─── Homepage (before other routes) ──────────────────────────────
app.get('/', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.render('index', { title: 'Syntex Solutions — Enterprise Resource Management' });
});

app.use('/dashboard', require('./routes/dashboard'));
app.use('/profile',   require('./routes/profile'));
app.use('/products',  require('./routes/products'));
app.use('/blog',      require('./routes/blog'));
app.use('/orders',    require('./routes/orders'));
app.use('/tickets',   require('./routes/tickets'));
app.use('/search',    require('./routes/search'));
app.use('/contact',   require('./routes/contact'));
app.use('/upload',    require('./routes/upload'));
app.use('/admin',     require('./routes/admin'));
app.use('/',          require('./routes/missing-vulns'));

// ─── API routes ───────────────────────────────────────────────────
const { chatApiRouter } = require('./routes/websocket');
app.use('/api/v1',      require('./routes/api/v1'));
app.use('/api/v2',      require('./routes/api/v2'));
app.use('/api/v1/chat', chatApiRouter());

// ─── Settings ─────────────────────────────────────────────────────
app.get('/settings', require('./middleware/auth').requireAuth, (req, res) => {
    res.render('settings', { title:'Account Settings', user:req.session.user, success:req.query.saved||null, error:null });
});

// ─── NEW vulnerability modules (v4.1 additions) ───────────────────
// Additive only — zero changes to existing routes
app.use('/', require('./routes/advanced'));    // SSTI, Host Header, CRLF, Email Header, Log Inject, Session Fix, Clickjacking, 2FA
app.use('/', require('./routes/vulns-extra')); // XXE, Mass Assignment, Prototype Pollution, Zip Slip
app.use('/otp', require('./routes/otp'));
app.use('/', require('./routes/modern-vulns')); // v4.2: AI/LLM, SAML, Tenant, CDN, Webhook, K8s, Storage, Reset, Email verify, Rate limit

// ── ADD these route aliases so pages are findable ─────────────────
app.get('/ai-assistant',   (req,res) => res.redirect('/ai-assistant'));   // already handled by modern-vulns
app.get('/employees',      require('./middleware/auth').requireAuth, async (req,res) => {
    const db = require('./database/db');
    const r  = await db.query(`SELECT * FROM employees ORDER BY department, full_name`).catch(()=>({rows:[]}));
    res.render('vulns/employees', { title:'Employee Directory — Syntex Solutions', employees:r.rows, user:req.session.user });
});
app.get('/invoices',       require('./middleware/auth').requireAuth, async (req,res) => {
    const db = require('./database/db');
    const uid = req.session.userId;
    // VULNERABILITY: IDOR — no ownership check, admin sees all, users should only see their own
    const r = await db.query(`SELECT * FROM invoices ORDER BY created_at DESC`).catch(()=>({rows:[]}));
    res.render('vulns/invoices', { title:'Invoices — Syntex Solutions', invoices:r.rows, user:req.session.user });
});
app.get('/api-tokens',     require('./middleware/auth').requireAuth, async (req,res) => {
    const db = require('./database/db');
    // VULNERABILITY: Returns ALL tokens, including other users' tokens and expired ones
    const r = await db.query(`SELECT * FROM api_tokens_v2 ORDER BY created_at DESC`).catch(()=>({rows:[]}));
    res.render('vulns/api-tokens', { title:'API Tokens — Syntex Solutions', tokens:r.rows, user:req.session.user });
});
app.get('/directory',      require('./middleware/auth').requireAuth, async (req,res) => {
    const db = require('./database/db');
    // VULNERABILITY: Sensitive fields (salary, ssn_last4, internal_notes, access_level) returned
    const r = await db.query(`SELECT * FROM employees WHERE is_active=true ORDER BY department, full_name`).catch(()=>({rows:[]}));
    res.render('vulns/employees', { title:'Employee Directory — Syntex Solutions', employees:r.rows, user:req.session.user });
});


// ─── Bug bounty platform (/program/*) ────────────────────────────
app.use('/program/hints',      require('./routes/hints'));
app.use('/program/challenges', require('./routes/challenges'));
app.use('/program', require('./routes/program'));

// ─── Block old /hints /challenges /flags on main site → 404 ──────
app.use(blockBountyOnMainSite);

// ─── Redirect old bare paths → /program equivalents ──────────────
app.get('/hints',              (req,res) => res.redirect(301,'/program/hints'));
app.get('/hints/*',            (req,res) => res.redirect(301,'/program/hints/'+req.params[0]));
app.get('/challenges',         (req,res) => res.redirect(301,'/program/challenges'));
app.get('/challenges/*',       (req,res) => res.redirect(301,'/program/challenges/'+req.params[0]));
app.get('/reports',            (req,res) => res.redirect(301,'/program/reports'));
app.get('/reports/flags',      (req,res) => res.redirect(301,'/program/flags'));
app.get('/reports/new',        (req,res) => res.redirect(301,'/program/submit'));
app.get('/reports/:id',        (req,res) => res.redirect(301,`/program/reports/${req.params.id}`));
app.post('/reports',           (req,res) => res.redirect(301,'/program/submit'));

// ─── Convenience aliases ──────────────────────────────────────────
app.get('/bug-bounty',     (req,res) => res.redirect('/program'));
app.get('/scope',          (req,res) => res.redirect('/program/scope'));
app.get('/hall-of-fame',   (req,res) => res.redirect('/program/hall-of-fame'));
app.get('/leaderboard',    (req,res) => res.redirect('/program/leaderboard'));
app.get('/security/policy',(req,res) => res.redirect('/program'));
app.get('/health',         (req,res) => res.json({ status:'ok', version:'4.1', mode:getLabMode() }));

// ─── 404 ──────────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).render('404', { title:'404 — Not Found', path:req.path, user:req.session.user||null });
});

// ─── Error handler (stack trace exposed — intentional vuln) ───────
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    res.status(err.status||500).render('error', {
        title:'Server Error', message:err.message,
        stack:err.stack, status:err.status||500, user:req.session.user||null,
    });
});

// ─── HTTP server (needed for WebSocket) ───────────────────────────
const server = http.createServer(app);

if (process.env.WS_ENABLED !== 'false') {
    const { setupWebSocket } = require('./routes/websocket');
    setupWebSocket(server);
    console.log('[SYNTEX] WebSocket attached at /ws/chat');
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`[SYNTEX] http://0.0.0.0:${PORT}  mode=${getLabMode()}`);
    console.log(`[SYNTEX] Program platform: /program`);
});

module.exports = { app, server };
