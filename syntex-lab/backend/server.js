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

// ─── Body parsers + cookies ───────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ─── Session (intentionally weak) ────────────────────────────────
app.use(session({
    secret: process.env.SESSION_SECRET || 'syntex_session_secret_2024',
    resave: true, saveUninitialized: true,
    name: 'SYNTEX_SESS',
    cookie: { httpOnly: false, secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 },
}));

// ─── CORS (misconfigured — reflects any origin) ───────────────────
app.use(require('./middleware/cors'));

// ─── LAB_MODE + fingerprinting headers ───────────────────────────
app.use((req, res, next) => {
    const mode = (process.env.LAB_MODE || 'beginner').toLowerCase();
    res.locals.labMode = mode;
    res.locals.lab = {
        mode,
        showHints:    ['beginner','intermediate'].includes(mode),
        showFlags:    ['beginner','intermediate'].includes(mode),
        showChallenges: mode !== 'realistic',
        showSolutions:  mode === 'beginner',
        bannerColor:  { beginner:'#15803D', intermediate:'#B45309', hard:'#B91C1C', realistic:'#1B3A6B' }[mode] || '#1B3A6B',
        bannerLabel:  mode.toUpperCase(),
    };
    // Intentional fingerprinting
    res.setHeader('X-Powered-By',    `Syntex/2.4.1 Node.js/${process.version} Express/4.18`);
    res.setHeader('X-Syntex-Version','2.4.1');
    res.setHeader('Server',          'nginx/1.24.0');
    next();
});

// ─── Session user into locals ─────────────────────────────────────
app.use((req, res, next) => {
    res.locals.user    = req.session.user    || null;
    res.locals.isAdmin = (req.session.role === 'admin') || (req.cookies.role === 'admin');
    next();
});

// ─── Virtual host → program platform ─────────────────────────────
// Detects program.syntex.local / bounty.syntex.local and rewrites path
app.use((req, res, next) => {
    const vhost = req.headers['x-vhost'] || '';
    const host  = req.headers.host || '';
    if (vhost === 'program' || host.startsWith('program.') || host.startsWith('bounty.')) {
        if (!req.url.startsWith('/program')) {
            req.url = '/program' + (req.url === '/' ? '' : req.url);
        }
    }
    next();
});

// ─── Static files ─────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── GraphQL endpoint ─────────────────────────────────────────────
const { graphqlHandler } = require('./routes/graphql');
app.get('/graphql',  graphqlHandler);
app.post('/graphql', graphqlHandler);

// ─── OAuth / OIDC ─────────────────────────────────────────────────
app.use('/oauth', require('./routes/oauth'));

// ─── Race condition lab ───────────────────────────────────────────
app.use('/race', require('./routes/race'));

// ─── Recon targets (swagger, openapi, source maps, actuator) ─────
app.use('/', require('./routes/recon'));

// ─── Core vulnerable app routes ───────────────────────────────────
app.use('/',          require('./routes/misc'));
app.use('/',          require('./routes/auth'));
app.use('/dashboard', require('./routes/dashboard'));
app.use('/profile',   require('./routes/profile'));
app.use('/products',  require('./routes/products'));
app.use('/blog',      require('./routes/blog'));
app.use('/orders',    require('./routes/orders'));
app.use('/tickets',   require('./routes/tickets'));
app.use('/search',    require('./routes/search'));
app.use('/contact',   require('./routes/contact'));
app.use('/',          require('./routes/upload'));
app.use('/admin',     require('./routes/admin'));

// ─── API routes ───────────────────────────────────────────────────
const { chatApiRouter } = require('./routes/websocket');
app.use('/api/v1',      require('./routes/api/v1'));
app.use('/api/v2',      require('./routes/api/v2'));
app.use('/api/v1/chat', chatApiRouter());

// ─── Bug bounty program platform ─────────────────────────────────
app.use('/program', require('./routes/program'));

// ─── Hints, challenges, reports (shared between main + program) ──
app.use('/hints',      require('./routes/hints'));
app.use('/challenges', require('./routes/challenges'));
// NOTE: /reports/flags must come before /reports/:id
app.use('/reports', require('./routes/reports'));

// ─── Convenience aliases ──────────────────────────────────────────
app.get('/bug-bounty',    (req, res) => res.redirect('/program'));
app.get('/scope',         (req, res) => res.redirect('/program/scope'));
app.get('/hall-of-fame',  (req, res) => res.redirect('/program/hall-of-fame'));
app.get('/leaderboard',   (req, res) => res.redirect('/program/leaderboard'));
app.get('/security/policy',(req,res) => res.redirect('/program'));

// ─── Homepage ─────────────────────────────────────────────────────
app.get('/', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.render('index', { title: 'Syntex Solutions — Enterprise Resource Management' });
});

// ─── Settings ─────────────────────────────────────────────────────
app.get('/settings', require('./middleware/auth').requireAuth, (req, res) => {
    res.render('settings', { title:'Account Settings', user:req.session.user, success:req.query.saved||null, error:null });
});

// ─── 404 ──────────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).render('404', { title:'404 — Not Found', path:req.path, user:req.session.user||null });
});

// ─── Error handler (stack trace exposed — intentional) ────────────
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    res.status(err.status||500).render('error', {
        title:'Server Error', message:err.message,
        stack: err.stack, status:err.status||500, user:req.session.user||null,
    });
});

// ─── HTTP server (needed for WebSocket) ───────────────────────────
const server = http.createServer(app);

// ─── WebSocket server ─────────────────────────────────────────────
if (process.env.WS_ENABLED !== 'false') {
    const { setupWebSocket } = require('./routes/websocket');
    setupWebSocket(server);
    console.log('[SYNTEX] WebSocket server attached at ws://0.0.0.0:3000/ws/chat');
}

// ─── Start ────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`[SYNTEX] http://0.0.0.0:${PORT}`);
    console.log(`[SYNTEX] Mode: ${process.env.LAB_MODE || 'beginner'}`);
    console.log(`[SYNTEX] GraphQL: http://0.0.0.0:${PORT}/graphql`);
    console.log(`[SYNTEX] Program: http://program.syntex.local  or  http://0.0.0.0:${PORT}/program`);
});

module.exports = { app, server };
