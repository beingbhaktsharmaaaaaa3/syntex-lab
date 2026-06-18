'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// ── Hint data: 3 progressive levels per vulnerability ─────────
const HINTS = {
  'sqli-login': {
    title: 'SQL Injection — Login Form', category: 'SQLi', difficulty: 'easy',
    endpoint: 'POST /login', file: 'routes/auth.js',
    hints: [
      'The login form passes your input directly into a database query without any sanitisation.',
      'Try entering a single quote ( \' ) in the username field and observe the server response carefully.',
      'SQL comments (--) after a quote can end the query early. Think about what that means for the WHERE clause.',
    ],
    solution: '/solutions/sqli-login',
  },
  'sqli-search': {
    title: 'SQL Injection — Search Bar', category: 'SQLi', difficulty: 'easy',
    endpoint: 'GET /search?q=', file: 'routes/search.js',
    hints: [
      'The search query is placed inside a LIKE clause without parameterisation.',
      'A single quote in the search box will break the SQL string and may return a database error.',
      'UNION SELECT can append a second query. Count the columns in the original SELECT first.',
    ],
    solution: '/solutions/sqli-search',
  },
  'sqli-products': {
    title: 'SQL Injection — Products Filter / ORDER BY', category: 'SQLi', difficulty: 'medium',
    endpoint: 'GET /products?category=&sort=', file: 'routes/products.js',
    hints: [
      'The category and sort parameters are both injectable. The sort parameter is particularly interesting.',
      'ORDER BY clauses cannot use parameterised values — they must use string concatenation.',
      'ORDER BY (CASE WHEN 1=1 THEN price ELSE name END) is valid syntax. What can you deduce from this?',
    ],
    solution: '/solutions/sqli-products',
  },
  'xss-reflected': {
    title: 'Reflected XSS — Search Results', category: 'XSS', difficulty: 'easy',
    endpoint: 'GET /search?q=', file: 'views/search-results.ejs',
    hints: [
      'The search term you enter is displayed back on the page without HTML encoding.',
      'Look at the EJS template for the search results. Does it use <%=  %> or <%-  %>?',
      'Try entering HTML in the search box. If it renders as markup instead of text, you have XSS.',
    ],
    solution: '/solutions/xss-reflected',
  },
  'xss-stored': {
    title: 'Stored XSS — Blog Comments', category: 'XSS', difficulty: 'easy',
    endpoint: 'POST /blog/:id/comment', file: 'views/post-detail.ejs',
    hints: [
      'Comments are stored in the database and displayed to every visitor of the post.',
      'The comment content is rendered with the unescaped EJS tag (-%>). This means HTML is interpreted.',
      'A script tag or img onerror handler in a comment will execute in every visitor\'s browser.',
    ],
    solution: '/solutions/xss-stored',
  },
  'xss-dom': {
    title: 'DOM XSS — URL Parameters', category: 'XSS', difficulty: 'easy',
    endpoint: '/?message= or /?error=', file: 'public/js/app.js',
    hints: [
      'Some values from the URL are read by JavaScript and written directly to the page.',
      'Open the browser console and look at app.js. Find where it uses .innerHTML.',
      'Try adding ?message=<b>bold</b> to any page URL. If you see bold text, you have a DOM XSS entry point.',
    ],
    solution: '/solutions/xss-dom',
  },
  'idor-profile': {
    title: 'IDOR — User Profile', category: 'IDOR', difficulty: 'easy',
    endpoint: 'GET /profile/:id', file: 'routes/profile.js',
    hints: [
      'The profile page uses a numeric ID from the URL. There is no check that you own that profile.',
      'Log in and look at your own profile URL. What happens if you change the number?',
      'Profile 1 belongs to a very privileged account. The API endpoint /api/v1/users/:id is also unprotected.',
    ],
    solution: '/solutions/idor-profile',
  },
  'idor-orders': {
    title: 'IDOR — Order Detail', category: 'IDOR', difficulty: 'easy',
    endpoint: 'GET /orders/:id', file: 'routes/orders.js',
    hints: [
      'Order IDs are sequential integers. The server returns order data for any ID without checking ownership.',
      'Log in, place or view an order, then increment the ID in the URL.',
      'Order ID 6 contains something interesting in the notes field.',
    ],
    solution: '/solutions/idor-orders',
  },
  'idor-tickets': {
    title: 'IDOR — Support Tickets (Internal Notes)', category: 'IDOR', difficulty: 'medium',
    endpoint: 'GET /tickets/:id', file: 'routes/tickets.js',
    hints: [
      'Support tickets have internal staff notes that should only be visible to support staff.',
      'The ticket endpoint uses the ID from the URL directly. No ownership check exists.',
      'Ticket 3 has internal notes that contain sensitive information including a flag.',
    ],
    solution: '/solutions/idor-tickets',
  },
  'csrf-profile': {
    title: 'CSRF — Profile Update', category: 'CSRF', difficulty: 'medium',
    endpoint: 'POST /profile/:id/edit', file: 'routes/profile.js',
    hints: [
      'POST forms on this application do not include any CSRF tokens.',
      'A malicious website can submit a form to this application on behalf of a logged-in victim.',
      'Combine CSRF with IDOR: you can update any user\'s profile from an external page, including setting a stored XSS payload in their bio.',
    ],
    solution: '/solutions/csrf-profile',
  },
  'csrf-password': {
    title: 'CSRF — Password Change (no old password required)', category: 'CSRF', difficulty: 'medium',
    endpoint: 'POST /profile/:id/change-password', file: 'routes/profile.js',
    hints: [
      'The password change endpoint does not require the current password, and has no CSRF protection.',
      'An attacker who can make a victim\'s browser send a POST request can change their password.',
      'This endpoint also has an IDOR flaw — you can change ANY user\'s password, not just your own.',
    ],
    solution: '/solutions/csrf-password',
  },
  'admin-bypass': {
    title: 'Broken Access Control — Admin Panel via Cookie', category: 'Auth Bypass', difficulty: 'easy',
    endpoint: 'GET /admin', file: 'middleware/auth.js',
    hints: [
      'The admin panel checks the user\'s role, but where does it look for that role?',
      'Open your browser DevTools → Application → Cookies. What cookies are set?',
      'What if you added a new cookie called "role" with the value "admin"?',
    ],
    solution: '/solutions/admin-bypass',
  },
  'jwt-algnone': {
    title: 'JWT Flaw — Algorithm Confusion (alg:none)', category: 'JWT', difficulty: 'medium',
    endpoint: 'Authorization: Bearer header', file: 'middleware/auth.js',
    hints: [
      'The JWT verification code decodes the token header before verifying the signature.',
      'If the algorithm in the header is "none", the code skips signature verification entirely.',
      'A pre-built admin token with alg:none is already available somewhere in the application\'s JavaScript files.',
    ],
    solution: '/solutions/jwt-algnone',
  },
  'jwt-weaksecret': {
    title: 'JWT Flaw — Weak Signing Secret', category: 'JWT', difficulty: 'medium',
    endpoint: 'POST /api/v1/token', file: 'middleware/auth.js',
    hints: [
      'Tokens signed with HS256 use a shared secret. If that secret is weak, it can be brute-forced.',
      'Obtain a valid JWT from /api/v1/token and examine it with jwt.io.',
      'The secret is stored in an environment variable — and that environment variable is exposed somewhere on this application.',
    ],
    solution: '/solutions/jwt-weaksecret',
  },
  'ssrf-fetch': {
    title: 'SSRF — URL Fetch Endpoint', category: 'SSRF', difficulty: 'medium',
    endpoint: 'POST /api/v1/fetch', file: 'routes/api/v1.js',
    hints: [
      'One API endpoint accepts a URL and fetches it server-side, returning the response to the client.',
      'If you supply an internal URL (like http://localhost:3000/debug), the server will fetch it for you.',
      'The Docker internal hostname for the database container is "db". What port does PostgreSQL listen on?',
    ],
    solution: '/solutions/ssrf-fetch',
  },
  'lfi-download': {
    title: 'Path Traversal / LFI — File Download', category: 'LFI', difficulty: 'medium',
    endpoint: 'GET /download?file=', file: 'routes/upload.js',
    hints: [
      'The download endpoint takes a filename from the URL and serves it. No path validation exists.',
      'Path traversal uses ../ sequences to move up directories. Try it in the file parameter.',
      '/etc/passwd is always a good first target to confirm LFI. Work from there.',
    ],
    solution: '/solutions/lfi-download',
  },
  'cmd-injection-contact': {
    title: 'Command Injection — Contact Form', category: 'Command Injection', difficulty: 'medium',
    endpoint: 'POST /contact', file: 'routes/contact.js',
    hints: [
      'The contact form triggers a system command that logs the submission. User input is part of that command.',
      'Shell metacharacters like ; && | allow you to chain additional commands.',
      'Try submitting the form with Name = "test; id" and check if the response reveals command output.',
    ],
    solution: '/solutions/cmd-injection-contact',
  },
  'cmd-injection-ping': {
    title: 'Command Injection — Admin Ping Utility', category: 'Command Injection', difficulty: 'easy',
    endpoint: 'POST /admin/ping', file: 'routes/admin.js',
    hints: [
      'The admin panel includes a network diagnostic tool that runs ping. Gain admin access first.',
      'The hostname you enter is concatenated directly into a shell command string.',
      'Try: 127.0.0.1; id  — the semicolon ends the ping command and starts a new one.',
    ],
    solution: '/solutions/cmd-injection-ping',
  },
  'open-redirect': {
    title: 'Open Redirect — Login Redirect Parameter', category: 'Open Redirect', difficulty: 'easy',
    endpoint: 'GET /login?redirect=', file: 'routes/auth.js',
    hints: [
      'After login, the app redirects users to a URL from the query string. No validation exists.',
      'Try /login?redirect=https://google.com — where does a successful login take you?',
      'This is useful for phishing: send someone a syntex.local login link that redirects to your credential-harvesting page.',
    ],
    solution: '/solutions/open-redirect',
  },
  'cors-misconfig': {
    title: 'CORS Misconfiguration — Reflect Any Origin', category: 'CORS', difficulty: 'medium',
    endpoint: 'GET /api/v1/*', file: 'middleware/cors.js',
    hints: [
      'Add an Origin header to any API request. Look at what Access-Control-Allow-Origin is set to in the response.',
      'If the server reflects your origin AND sets Access-Control-Allow-Credentials: true, cross-origin requests with cookies are possible.',
      'A malicious page on any domain can make authenticated API calls to this server using the victim\'s session cookie.',
    ],
    solution: '/solutions/cors-misconfig',
  },
  'exposed-env': {
    title: 'Exposed .env File', category: 'Recon / Exposure', difficulty: 'easy',
    endpoint: 'GET /.env', file: 'routes/misc.js',
    hints: [
      'Developers sometimes forget to exclude configuration files from their web server\'s static file serving.',
      'Try navigating directly to /.env in your browser.',
      'This file contains database credentials, JWT secrets, AWS keys, and Stripe secret keys.',
    ],
    solution: '/solutions/exposed-env',
  },
  'exposed-git': {
    title: 'Exposed .git Directory', category: 'Recon / Exposure', difficulty: 'easy',
    endpoint: 'GET /.git/config', file: 'routes/misc.js',
    hints: [
      'Git repositories store configuration including remote URLs. If .git is served publicly, credentials may be embedded.',
      'Try GET /.git/config — if it returns a file, the git directory is exposed.',
      'Remote URLs sometimes contain tokens in the format: https://token@github.com/org/repo',
    ],
    solution: '/solutions/exposed-git',
  },
  'file-upload-bypass': {
    title: 'File Upload — Extension-Only Validation Bypass', category: 'File Upload', difficulty: 'medium',
    endpoint: 'POST /upload', file: 'routes/upload.js',
    hints: [
      'The upload handler validates files using only the file extension, not the MIME type or magic bytes.',
      'Node.js path.extname("shell.php.jpg") returns ".jpg" — it only looks at the last extension.',
      'Rename a file to shell.php.jpg and upload it. The extension check passes, but what did the server actually store?',
    ],
    solution: '/solutions/file-upload-bypass',
  },
  'business-logic-negqty': {
    title: 'Business Logic — Negative Quantity Order', category: 'Business Logic', difficulty: 'medium',
    endpoint: 'POST /orders', file: 'routes/orders.js',
    hints: [
      'The order form accepts a quantity field. What happens with input validation on the server?',
      'The total price is calculated as: unit_price × quantity. No check exists that quantity must be positive.',
      'Submit a quantity of -100. What is your total? What does this mean for your account balance?',
    ],
    solution: '/solutions/business-logic-negqty',
  },
  'business-logic-coupon': {
    title: 'Business Logic — Coupon Reuse', category: 'Business Logic', difficulty: 'medium',
    endpoint: 'POST /orders/apply-coupon', file: 'routes/orders.js',
    hints: [
      'The coupon application endpoint checks if a coupon is active, but does not record who has used it.',
      'There is a table tracking coupon uses — but no lookup is done before applying a coupon.',
      'Apply the same coupon code to the same order multiple times. What happens to the total?',
    ],
    solution: '/solutions/business-logic-coupon',
  },
  'rate-limit-bypass': {
    title: 'Rate Limit Bypass — X-Forwarded-For Header', category: 'Rate Limiting', difficulty: 'easy',
    endpoint: 'POST /login', file: 'middleware/auth.js',
    hints: [
      'The rate limiter determines your identity using your IP address. Where does it read that IP from?',
      'Look at the auth middleware. It reads from req.headers["x-forwarded-for"] before req.socket.remoteAddress.',
      'X-Forwarded-For is a client-controlled header. Send a different value with each login attempt to bypass the per-IP limit.',
    ],
    solution: '/solutions/rate-limit-bypass',
  },
  'mass-user-export': {
    title: 'Broken Access Control — Unauthenticated User Export', category: 'Broken Access', difficulty: 'easy',
    endpoint: 'GET /api/v2/users/export', file: 'routes/api/v2.js',
    hints: [
      'Some API v2 endpoints were built for internal use and never had authentication added.',
      'Try requesting /api/v2/users/export without any session or token.',
      'Add ?format=csv to get a CSV file containing all users including their hashed passwords.',
    ],
    solution: '/solutions/mass-user-export',
  },
  'weak-md5': {
    title: 'Weak Password Hashing — MD5', category: 'Cryptography', difficulty: 'easy',
    endpoint: 'Database / auth flow', file: 'database/seed.js',
    hints: [
      'Obtain password hashes from the database (via SQL injection or the user export endpoint).',
      'MD5 hashes are 32 hex characters long. Tools like hashcat can crack them against wordlists very quickly.',
      'hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt — all seed passwords are in rockyou.txt.',
    ],
    solution: '/solutions/weak-md5',
  },
};

// ── Routes ────────────────────────────────────────────────────

// GET /hints  — index of all vulnerabilities
router.get('/', (req, res) => {
    const grouped = {};
    for (const [slug, data] of Object.entries(HINTS)) {
        const cat = data.category;
        if (!grouped[cat]) grouped[cat] = [];
        grouped[cat].push({ slug, ...data });
    }
    res.render('hints/index', {
        title: 'Vulnerability Hints — Syntex Lab',
        grouped,
        user: req.session.user || null,
    });
});

// GET /hints/:slug  — show hint levels for one vulnerability
router.get('/:slug', requireAuth, async (req, res) => {
    const { slug } = req.params;
    const hint = HINTS[slug];
    if (!hint) return res.status(404).render('404', { title: '404', user: req.session.user });

    const uid = req.session.userId;
    const unlocked = await db.query(
        `SELECT level FROM hint_unlocks WHERE user_id=$1 AND vuln_slug=$2 ORDER BY level`, [uid, slug]
    );
    const unlockedLevels = unlocked.rows.map(r => r.level);
    const nextLevel = (unlockedLevels.length === 0) ? null : Math.max(...unlockedLevels) + 1;

    res.render('hints/detail', {
        title: `Hints: ${hint.title}`,
        slug,
        hint,
        unlockedLevels,
        nextLevel: nextLevel > hint.hints.length ? null : nextLevel,
        user: req.session.user,
    });
});

// POST /hints/:slug/:level/unlock
router.post('/:slug/:level/unlock', requireAuth, async (req, res) => {
    const { slug, level } = req.params;
    const lvl = parseInt(level);
    const hint = HINTS[slug];
    if (!hint || lvl < 1 || lvl > hint.hints.length) return res.status(400).json({ error: 'Invalid' });

    const uid = req.session.userId;
    await db.query(
        `INSERT INTO hint_unlocks (user_id, vuln_slug, level) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
        [uid, slug, lvl]
    );
    res.redirect(`/hints/${slug}`);
});

// Expose hints data for solutions page
router.hintsData = HINTS;
module.exports = router;
