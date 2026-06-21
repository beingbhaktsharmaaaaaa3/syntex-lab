'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// ── Hint data ─────────────────────────────────────────────────────
const HINTS = {
  'sqli-login':           { title:'SQL Injection — Login Bypass',             category:'SQL Injection',     difficulty:'easy',   endpoint:'POST /login',                      file:'routes/auth.js',
    hints:['The login form inserts the username directly into a SQL query string without sanitisation.',
           'Try entering a single quote (\') in the username field. Does the server return a database error?',
           'SQL comments (--) terminate the rest of the query. Combine with a quote to close the string and bypass the WHERE clause entirely.'],
    solution:'/program/solutions/sqli-login' },
  'sqli-search':          { title:'SQL Injection — Search UNION Dump',         category:'SQL Injection',     difficulty:'medium', endpoint:'GET /search?q=',                   file:'routes/search.js',
    hints:['The search term is embedded in a LIKE clause without parameterisation.',
           'A single quote breaks the SQL string and may reveal a database error with table/column names.',
           'UNION SELECT can append a second result set. First count the columns in the original SELECT, then inject matching column count.'],
    solution:'/program/solutions/sqli-search' },
  'sqli-products':        { title:'SQL Injection — Products ORDER BY',          category:'SQL Injection',     difficulty:'medium', endpoint:'GET /products?sort=',              file:'routes/products.js',
    hints:['The ?sort= parameter controls ORDER BY. ORDER BY clauses cannot use parameterised values.',
           'Try ?sort=price and ?sort=name -- notice the query structure changes. What about ?sort=price--?',
           'Boolean-based injection: ORDER BY (CASE WHEN 1=1 THEN price ELSE name END). Time-based: ORDER BY (SELECT CASE WHEN 1=1 THEN pg_sleep(3) ELSE 1 END)'],
    solution:'/program/solutions/sqli-products' },
  'xss-reflected':        { title:'Reflected XSS — Search Results',             category:'XSS',               difficulty:'easy',   endpoint:'GET /search?q=',                   file:'views/search-results.ejs',
    hints:['The search term you enter is printed back on the results page.',
           'Check the EJS template: does it use <%=  %> (escaped) or <%-  %> (unescaped/raw)?',
           'Try entering <b>bold</b> in the search box. If it renders as bold text instead of literal characters, XSS is confirmed.'],
    solution:'/program/solutions/xss-reflected' },
  'xss-stored-comments':  { title:'Stored XSS — Blog Comments',                 category:'XSS',               difficulty:'easy',   endpoint:'POST /blog/:id/comment',           file:'views/post-detail.ejs',
    hints:['Comments are stored in the database and rendered to every visitor of the post.',
           'The comment content is rendered with the unescaped EJS tag (<%-). HTML and script tags are interpreted as markup.',
           'Submit: <img src=x onerror="console.log(\'FLAG\');alert(document.cookie)"> as a comment. Reload the page — did it fire?'],
    solution:'/program/solutions/xss-stored-comments' },
  'xss-dom':              { title:'DOM XSS — URL Parameters',                   category:'XSS',               difficulty:'easy',   endpoint:'GET /?message=',                   file:'public/js/app.js',
    hints:['Some URL parameters are read by client-side JavaScript and written directly into the page.',
           'Open browser DevTools → Sources → app.js. Search for innerHTML or document.write.',
           'Try: /?message=<img src=x onerror=alert(1)> — if you see an alert, DOM XSS confirmed.'],
    solution:'/program/solutions/xss-dom' },
  'idor-profile-admin':   { title:'IDOR — Admin via API (no auth)',              category:'IDOR',              difficulty:'easy',   endpoint:'GET /api/v1/users/1',              file:'routes/api/v1.js',
    hints:['The REST API has a /users/:id endpoint. Is authentication required to access it?',
           'Try: curl http://syntex.local/api/v1/users/1 without any cookies or tokens. What fields are returned?',
           'The api_key and secret_note fields of user ID 1 (admin) are returned in the response. No auth needed.'],
    solution:'/program/solutions/idor-profile-admin' },
  'idor-orders':          { title:'IDOR — Order #6 License Key',                 category:'IDOR',              difficulty:'easy',   endpoint:'GET /orders/6',                    file:'routes/orders.js',
    hints:['Order pages use a numeric ID from the URL. Is there a check that you own that order?',
           'Log in as any user. Visit /orders/1, /orders/2, /orders/3. Does the server check ownership?',
           'Order ID 6 belongs to another user and contains a flag in the notes field.'],
    solution:'/program/solutions/idor-orders' },
  'idor-tickets':         { title:'IDOR — Ticket #3 Internal Staff Notes',       category:'IDOR',              difficulty:'easy',   endpoint:'GET /tickets/3',                   file:'routes/tickets.js',
    hints:['Support tickets have an internal_notes field intended only for staff.',
           'The /tickets/:id endpoint returns internal_notes for any authenticated user regardless of ownership.',
           'Ticket ID 3 has internal notes containing a flag. Access it as a regular user.'],
    solution:'/program/solutions/idor-tickets' },
  'developer-secrets':    { title:'IDOR — Developer Account Secrets',            category:'IDOR',              difficulty:'medium', endpoint:'GET /profile/6',                   file:'routes/profile.js',
    hints:['User ID 6 is the developer account. Profile pages use /profile/:id without ownership checks.',
           'Try /api/v1/users/6 without authentication. What is in the secret_note field?',
           'The developer secret_note contains JWT_SECRET and DB_PASS values used by the application.'],
    solution:'/program/solutions/developer-secrets' },
  'admin-panel-bypass':   { title:'Admin Panel Bypass via Cookie',               category:'Auth Bypass',       difficulty:'easy',   endpoint:'GET /admin',                       file:'middleware/auth.js',
    hints:['The admin panel checks the user\'s role — but where does it read that role from?',
           'Open DevTools → Application → Cookies. What cookies are currently set on syntex.local?',
           'The requireAdmin middleware reads role from req.cookies.role before checking the session. Add a cookie: role=admin'],
    solution:'/program/solutions/admin-panel-bypass' },
  'jwt-algnone':          { title:'JWT alg:none — Signature Bypass',             category:'JWT',               difficulty:'medium', endpoint:'GET /js/config.js',                file:'middleware/auth.js',
    hints:['The JWT verification code reads the algorithm from the token header before verifying the signature.',
           'If alg is "none", the library skips signature verification. A pre-built admin token exists somewhere in the JS files.',
           'Fetch /js/config.js and look for _debug_token. Decode it at jwt.io. Send it as Authorization: Bearer <token>.'],
    solution:'/program/solutions/jwt-algnone' },
  'jwt-weaksecret':       { title:'JWT Weak Secret — Crackable with hashcat',    category:'JWT',               difficulty:'medium', endpoint:'POST /api/v1/token',               file:'middleware/auth.js',
    hints:['JWTs signed with HS256 use a shared secret. A weak secret can be brute-forced offline.',
           'Get a valid JWT from /api/v1/token. Paste it into jwt.io — what algorithm does the header show?',
           'Run: hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt. The secret is a common word.'],
    solution:'/program/solutions/jwt-weaksecret' },
  'csrf-profile':         { title:'CSRF — Profile Update No Token',              category:'CSRF',              difficulty:'medium', endpoint:'POST /profile/:id/edit',           file:'routes/profile.js',
    hints:['Look at the profile edit form in DevTools. Is there a hidden CSRF token field?',
           'The form submits via POST to /profile/:id/edit. No CSRF token is checked server-side.',
           'A page on any origin can submit this form. Combine with IDOR (any user ID) to update any user\'s profile.'],
    solution:'/program/solutions/csrf-profile' },
  'ssrf-internal':        { title:'SSRF — Internal Network via Fetch Endpoint',  category:'SSRF',              difficulty:'medium', endpoint:'POST /api/v1/fetch',               file:'routes/api/v1.js',
    hints:['One API endpoint accepts a URL parameter and fetches it server-side, returning the response.',
           'Try: POST /api/v1/fetch with body {"url":"http://localhost:3000/health"}. Does it return the response?',
           'Try {"url":"http://localhost:3000/debug"} — this endpoint dumps all environment variables including secrets.'],
    solution:'/program/solutions/ssrf-internal' },
  'file-upload-bypass':   { title:'File Upload — Double Extension Bypass',       category:'File Upload',       difficulty:'medium', endpoint:'POST /upload',                     file:'routes/upload.js',
    hints:['The upload handler validates files using only path.extname() which returns only the last extension.',
           'path.extname("shell.php.jpg") returns ".jpg" — the check passes even though the real extension is .php.',
           'Upload a file named shell.php.jpg — the extension validation passes. Check what the server actually stored.'],
    solution:'/program/solutions/file-upload-bypass' },
  'lfi-download':         { title:'Path Traversal — File Download',              category:'LFI',               difficulty:'medium', endpoint:'GET /download?file=',              file:'routes/upload.js',
    hints:['The /download endpoint reads a filename from the URL parameter and serves it from the uploads directory.',
           'No path validation exists. Try ../ sequences to escape the uploads directory.',
           'Try: /download?file=../../etc/passwd — if it returns the file, LFI is confirmed.'],
    solution:'/program/solutions/lfi-download' },
  'cmd-injection-contact':{ title:'Command Injection — Contact Form (exec)',     category:'Command Injection', difficulty:'medium', endpoint:'POST /contact',                    file:'routes/contact.js',
    hints:['The contact form logs submissions using a shell command. The user-supplied name is part of that command.',
           'Shell metacharacters like ; && | allow chaining additional commands.',
           'Try Name: "test; id" — if the response includes uid= output, RCE is confirmed.'],
    solution:'/program/solutions/cmd-injection-contact' },
  'cmd-injection-ping':   { title:'Command Injection — Admin Ping Utility',      category:'Command Injection', difficulty:'easy',   endpoint:'POST /admin/ping',                 file:'routes/admin.js',
    hints:['The admin panel has a network diagnostic tool that runs the ping command.',
           'The host parameter is concatenated directly into a shell string: exec(`ping -c 1 ${host}`).',
           'Enter: 127.0.0.1; id — the semicolon ends the ping and starts a new command.'],
    solution:'/program/solutions/cmd-injection-ping' },
  'open-redirect':        { title:'Open Redirect — Login ?redirect= Param',     category:'Open Redirect',     difficulty:'easy',   endpoint:'GET /login?redirect=',             file:'routes/auth.js',
    hints:['After successful login, the app redirects the user to a URL from the query string.',
           'Try logging in with: /login?redirect=https://google.com — where does it take you after login?',
           'No validation of the redirect URL exists. Useful for phishing: send a login link that redirects to an attacker-controlled page.'],
    solution:'/program/solutions/open-redirect' },
  'exposed-env':          { title:'Exposed .env File (Credentials Leaked)',      category:'Exposure',          difficulty:'easy',   endpoint:'GET /.env',                        file:'routes/misc.js',
    hints:['Developers sometimes forget to block access to configuration files via the web server.',
           'Try navigating to /.env in your browser or with curl.',
           'The file contains DB_PASS, JWT_SECRET, AWS keys, and Stripe secret keys.'],
    solution:'/program/solutions/exposed-env' },
  'internal-config-api':  { title:'Internal Config API — No Auth Required',     category:'Broken Access',     difficulty:'easy',   endpoint:'GET /api/v2/internal/config',      file:'routes/api/v2.js',
    hints:['The /api/v2/internal/ path was built for server-to-server use and has no authentication.',
           'Try: curl http://syntex.local/api/v2/internal/config without any session cookie.',
           'The response includes the full application config: DB_PASS, JWT_SECRET, AWS credentials.'],
    solution:'/program/solutions/internal-config-api' },
  'mass-user-export':     { title:'Unauthenticated User Export + MD5 Hashes',   category:'Broken Access',     difficulty:'easy',   endpoint:'GET /api/v2/users/export',         file:'routes/api/v2.js',
    hints:['One API v2 endpoint exports all users without requiring any authentication.',
           'Try: curl http://syntex.local/api/v2/users/export -- does it return data?',
           'Add ?format=csv for CSV output. The response includes MD5 password hashes. Run hashcat -m 0 against rockyou.txt.'],
    solution:'/program/solutions/mass-user-export' },
  'graphql-introspection': { title:'GraphQL Introspection — Full Schema Leak',  category:'GraphQL',           difficulty:'easy',   endpoint:'POST /graphql',                    file:'routes/graphql.js',
    hints:['GraphQL introspection lets you query the entire API schema — all types, fields, and mutations.',
           'Send: {"query":"{ __schema { types { name fields { name } } } }"} to /graphql.',
           'Open /graphql in a browser to see GraphiQL playground. Run the introspection query from there.'],
    solution:'/program/solutions/graphql-introspection' },
  'graphql-idor':         { title:'GraphQL IDOR — Sensitive Field Over-Fetching', category:'GraphQL',         difficulty:'medium', endpoint:'POST /graphql',                    file:'routes/graphql.js',
    hints:['GraphQL resolvers on this app perform no ownership checks on the user() query.',
           'The schema exposes secret_note, api_key, and password_hash on the User type.',
           'Query: { user(id: 1) { username secret_note api_key password_hash } } returns admin\'s sensitive data.'],
    solution:'/program/solutions/graphql-idor' },
  'oauth-missing-state':  { title:'OAuth — Missing State Parameter (CSRF Risk)', category:'OAuth/SSO',        difficulty:'medium', endpoint:'GET /oauth/authorize',             file:'routes/oauth.js',
    hints:['The OAuth flow should include a state parameter to prevent CSRF attacks.',
           'Visit /oauth/authorize?client_id=app_analytics&redirect_uri=http://localhost:4000/cb&response_type=code without a state param.',
           'The server issues an auth code without state. An attacker can forge an authorization request and trick a user into completing it.'],
    solution:'/program/solutions/oauth-missing-state' },
  'ws-room-idor':         { title:'WebSocket — Room IDOR (Read Any Chat)',       category:'WebSocket',         difficulty:'medium', endpoint:'ws://localhost:3000/ws/chat',      file:'routes/websocket.js',
    hints:['The WebSocket chat endpoint accepts a ?room= query parameter. Is this validated?',
           'Connect with: wscat -c "ws://localhost:3000/ws/chat?room=1" — you receive the full history of room 1.',
           'Change room=1 to room=2, room=3, etc. to access other users\' private support conversations.'],
    solution:'/program/solutions/ws-room-idor' },
  'race-condition':       { title:'Race Condition — Reward Claim (Check-then-Act)', category:'Race Condition', difficulty:'hard',  endpoint:'POST /race/claim-reward',          file:'routes/race.js',
    hints:['The reward endpoint checks if you already claimed today, then inserts the claim. No atomic transaction.',
           'Send 20 requests simultaneously before any single request completes the check-then-insert cycle.',
           'Use Burp Turbo Intruder or: for i in $(seq 1 20); do curl -s -X POST /race/claim-reward -b "SYNTEX_SESS=..." & done; wait'],
    solution:'/program/solutions/race-condition' },
  'rate-limit-bypass':    { title:'Rate Limit Bypass — X-Forwarded-For Header', category:'Rate Limiting',     difficulty:'easy',   endpoint:'POST /login',                      file:'middleware/auth.js',
    hints:['The login rate limiter identifies users by IP address. Where does it read the IP from?',
           'The middleware trusts req.headers["x-forwarded-for"] before req.socket.remoteAddress.',
           'X-Forwarded-For is a client-controlled header. Rotate its value with each request to bypass the per-IP limit.'],
    solution:'/program/solutions/rate-limit-bypass' },
  'source-map-secrets':   { title:'JS Source Map — Leaked JWT Secret',           category:'Exposure',          difficulty:'medium', endpoint:'GET /js/app.bundle.js.map',        file:'routes/recon.js',
    hints:['When JavaScript is bundled, source maps (.map files) are generated for debugging. Are they publicly accessible?',
           'Fetch: /js/app.bundle.js.map — is it served? Source maps can contain original source filenames and metadata.',
           'The x-sourcemap-note field in the map JSON contains jwt_secret, internal_token, and db credentials.'],
    solution:'/program/solutions/source-map-secrets' },
  'swagger-leak':         { title:'Swagger/OpenAPI — Internal Endpoints Exposed', category:'Exposure',         difficulty:'easy',   endpoint:'GET /swagger.json',                file:'routes/recon.js',
    hints:['API documentation files are sometimes left publicly accessible on production servers.',
           'Try: curl http://syntex.local/swagger.json | jq .paths -- what endpoints are listed?',
           'The spec lists /api/v2/internal/config, /api/v2/users/export, and contains x-internal-notes with credentials.'],
    solution:'/program/solutions/swagger-leak' },
};

// ── GET /program/hints ───────────────────────────────────────────
router.get('/', (req, res) => {
    const grouped = {};
    for (const [slug, data] of Object.entries(HINTS)) {
        if (!grouped[data.category]) grouped[data.category] = [];
        grouped[data.category].push({ slug, ...data });
    }
    res.render('program/hints-index', {
        title: 'Hints — Syntex Bug Bounty',
        grouped,
        user: req.session.user || null,
    });
});

// ── GET /program/hints/:slug ─────────────────────────────────────
router.get('/:slug', requireAuth, async (req, res) => {
    const { slug } = req.params;
    const hint = HINTS[slug];
    if (!hint) return res.status(404).render('404', { title:'404', user:req.session.user });

    const uid = req.session.userId;
    const unlocked = await db.query(
        `SELECT level FROM hint_unlocks WHERE user_id=$1 AND vuln_slug=$2 ORDER BY level`, [uid, slug]
    );
    const unlockedLevels = unlocked.rows.map(r => r.level);

    res.render('program/hints-detail', {
        title: `Hints: ${hint.title}`,
        slug, hint, unlockedLevels,
        user: req.session.user,
    });
});

// ── POST /program/hints/:slug/:level/unlock ──────────────────────
router.post('/:slug/:level/unlock', requireAuth, async (req, res) => {
    const { slug, level } = req.params;
    const lvl  = parseInt(level);
    const hint = HINTS[slug];
    if (!hint || lvl < 1 || lvl > hint.hints.length) return res.status(400).json({ error:'Invalid' });

    await db.query(
        `INSERT INTO hint_unlocks (user_id, vuln_slug, level)
         VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
        [req.session.userId, slug, lvl]
    );
    res.redirect(`/program/hints/${slug}`);
});

module.exports = router;
