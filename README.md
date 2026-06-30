# 🛡️ Syntex Lab — Bug Bounty Practice Environment

> **⚠️ FOR LOCAL/LAB USE ONLY**
> This application is **deliberately insecure**. Run it only in an isolated local environment.
> **Never** deploy on a VPS, public IP, college Wi-Fi, office network, or shared LAN.
> By using this lab you confirm you have authorization to test it.

A realistic, intentionally vulnerable corporate SaaS platform for bug bounty practice. Built to feel like a real HackerOne/Bugcrowd target — not a CTF page — with two separate experiences:

| URL | Purpose |
|-----|---------|
| `http://syntex.local` | Vulnerable target — hunt here |
| `http://program.syntex.local` | Bug bounty platform — submit reports, hints, leaderboard here |

---

## 🚀 Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/syntex-lab.git
cd syntex-lab

# Docker Compose v2 (modern — recommended):
docker compose up --build

# Docker Compose v1 (Kali Linux default / older systems):
docker-compose up --build
```

Wait ~30 seconds for seeding, then visit:
- `http://localhost:3000` — target website
- `http://localhost:3000/program` — bug bounty platform

Full setup, `/etc/hosts` config, and Windows/WSL instructions are in [docs/setup.md](syntex-lab/docs/setup.md).

---

## 🎯 Difficulty Modes

The lab supports four practice levels controlled by a single environment variable. Each mode changes what's visible — the underlying vulnerabilities never change, only how much guidance you get.

### How to change difficulty

**Edit `docker-compose.yml`:**

```yaml
services:
  app:
    environment:
      LAB_MODE: beginner   # ← change this line
```

Set `LAB_MODE` to one of: `beginner`, `intermediate`, `hard`, `realistic`

**Then restart the lab:**

```bash
docker compose down
docker compose up --build
```

### What each mode shows

| Feature | beginner | intermediate | hard | realistic |
|---------|:---:|:---:|:---:|:---:|
| Hints (3-level progressive) | ✅ | ✅ (limited) | ❌ | ❌ |
| Flags visible after solving | ✅ | ✅ | ❌ (manual review only) | ❌ |
| Challenge/vuln names shown | ✅ | ✅ | ❌ | ❌ |
| Solutions page | ✅ | ❌ | ❌ | ❌ |
| Vulnerability chain missions | ✅ | ✅ | ✅ | ❌ |
| Scope / Rules / Submit report | ✅ | ✅ | ✅ | ✅ |

**Recommended progression:**
1. Start in **beginner** — learn the techniques with full guidance
2. Move to **intermediate** — practice without solution spoilers
3. Switch to **hard** — no hints, simulates a harder program
4. Finish in **realistic** — only scope/rules/report submission visible, exactly like a live bug bounty program with zero hand-holding

You can also change difficulty per-request without rebuilding by setting the env var directly:
```bash
docker exec syntex_app sh -c "export LAB_MODE=realistic"
docker compose restart app
```

---

## 🌐 Subdomain Setup

Add **all** of these to `/etc/hosts` (Linux/Mac) or `C:\Windows\System32\drivers\etc\hosts` (Windows) — they match every vhost configured in `nginx.conf`, including several intentionally dead/restricted ones for recon practice:

```
# Main site + platform
127.0.0.1  syntex.local
127.0.0.1  www.syntex.local
127.0.0.1  program.syntex.local
127.0.0.1  bounty.syntex.local

# Application subdomains (live)
127.0.0.1  api.syntex.local
127.0.0.1  admin.syntex.local
127.0.0.1  cdn.syntex.local
127.0.0.1  staging.syntex.local
127.0.0.1  dev.syntex.local

# Recon practice — dead/restricted subdomains (503/403/401/301/302 responses)
127.0.0.1  mail.syntex.local
127.0.0.1  backup.syntex.local
127.0.0.1  vpn.syntex.local
127.0.0.1  intranet.syntex.local
127.0.0.1  internal.syntex.local
127.0.0.1  git.syntex.local
127.0.0.1  jenkins.syntex.local
127.0.0.1  jira.syntex.local
127.0.0.1  prometheus.syntex.local
127.0.0.1  grafana.syntex.local
127.0.0.1  s3.syntex.local
127.0.0.1  db.syntex.local
127.0.0.1  redis.syntex.local
127.0.0.1  legacy.syntex.local
127.0.0.1  old.syntex.local
127.0.0.1  test.syntex.local
127.0.0.1  beta.syntex.local
127.0.0.1  portal.syntex.local
```

**One-line install (Linux/Mac):**
```bash
sudo bash -c 'cat >> /etc/hosts << "EOF"
127.0.0.1  syntex.local www.syntex.local program.syntex.local bounty.syntex.local
127.0.0.1  api.syntex.local admin.syntex.local cdn.syntex.local staging.syntex.local dev.syntex.local
127.0.0.1  mail.syntex.local backup.syntex.local vpn.syntex.local intranet.syntex.local internal.syntex.local
127.0.0.1  git.syntex.local jenkins.syntex.local jira.syntex.local prometheus.syntex.local grafana.syntex.local
127.0.0.1  s3.syntex.local db.syntex.local redis.syntex.local legacy.syntex.local old.syntex.local
127.0.0.1  test.syntex.local beta.syntex.local portal.syntex.local
EOF'
```

27 subdomains total. `subfinder` will not discover them (no certificate transparency for `.local` domains) — use `ffuf` vhost fuzzing or the included `dns/` container with `gobuster dns` instead. Details in [docs/methodology.md](syntex-lab/docs/methodology.md).

---

## 📋 Full Vulnerability Catalog

All vulnerabilities are organized by category. Difficulty is shown per technique where the lab provides multiple variants.

### Injection
| Vulnerability | Difficulty | Where |
|---------------|:---:|-------|
| SQL Injection — login bypass | 🟢 Easy | Login form |
| SQL Injection — search UNION | 🟡 Medium | Search bar |
| SQL Injection — ORDER BY | 🟡 Medium | Product filters |
| Command Injection — admin ping | 🟢 Easy | Admin panel |
| Command Injection — contact form | 🟡 Medium | Contact page |
| Server-Side Template Injection (SSTI) | 🔴 Hard | Email template preview |
| XML External Entity (XXE) | 🟡 Medium | XML invoice upload |
| CRLF / HTTP Header Injection | 🟡 Medium | Link forwarder |

### Server-Side Logic
| Vulnerability | Difficulty | Where |
|---------------|:---:|-------|
| Server-Side Request Forgery (SSRF) | 🟡 Medium | URL fetch API |
| SSRF — webhook endpoint | 🟡 Medium | Webhook config |
| SSRF — cloud metadata theft | 🔴 Hard | K8s/cloud URL fetcher |
| Insecure File Upload | 🟡 Medium | File manager |
| Path Traversal / LFI | 🟡 Medium | File download |
| Cache Poisoning | 🔴 Hard | CDN cache lab |
| Cache Deception — static extension | 🟢 Easy | Profile stylesheet trick |
| Cache Deception — path confusion | 🟡 Medium | Account settings |
| HTTP Request Smuggling — CL.TE | 🟡 Medium | Smuggling simulation |
| HTTP Request Smuggling — TE.TE | 🔴 Hard | Smuggling simulation |
| Secondary Context — PDF renderer | 🟡 Medium | Invoice PDF export |
| Secondary Context — image processor | 🔴 Hard | Avatar image processor |
| Race Condition — reward/wallet abuse | 🔴 Hard | Rewards system |

### Client-Side
| Vulnerability | Difficulty | Where |
|---------------|:---:|-------|
| Reflected XSS | 🟢 Easy | Search results |
| Stored XSS — blog comments | 🟢 Easy | Blog post comments |
| Stored XSS — product reviews | 🟢 Easy | Product reviews |
| DOM XSS — URL parameters | 🟢 Easy | Homepage / dashboard |
| CSRF — profile update | 🟡 Medium | Profile edit form |
| CSRF — password change | 🟡 Medium | Account settings |
| Open Redirect | 🟢 Easy | Login redirect parameter |
| Client-Side Template Injection (CSTI) | 🟡 Medium | Profile bio live preview |
| PostMessage — missing origin check | 🟢 Easy | PostMessage lab |
| PostMessage — innerHTML XSS sink | 🔴 Hard | PostMessage lab |
| Prototype Pollution | 🔴 Hard | Config merge API |

### Authentication
| Vulnerability | Difficulty | Where |
|---------------|:---:|-------|
| 2FA / OTP — brute force (no rate limit) | 🟡 Medium | OTP security lab |
| 2FA / OTP — parameter bypass | 🟡 Medium | OTP security lab |
| 2FA / OTP — leaked in API response | 🟢 Easy | OTP security lab |
| 2FA / OTP — predictable algorithm | 🟡 Medium | OTP security lab |
| 2FA / OTP — reuse not invalidated | 🟡 Medium | OTP security lab |
| 2FA / OTP — short 4-digit code | 🟢 Easy | OTP security lab |
| Weak Password Policy — no min length | 🟢 Easy | Registration |
| Weak Password Policy — no complexity | 🟡 Medium | Registration |
| Weak Password Policy — blocklist bypass | 🔴 Hard | Registration |
| Password Reset — Host header poisoning | 🟡 Medium | Forgot password |
| Password Reset — token reuse | 🟡 Medium | Reset flow |
| Session Fixation | 🟡 Medium | Login flow |
| OAuth — missing state parameter | 🟡 Medium | SSO authorize |
| OAuth — open redirect / token leak | 🟡 Medium | OAuth callback |
| SAML — signature not verified | 🔴 Hard | SSO login |
| JWT — algorithm confusion (alg:none) | 🟡 Medium | JWT auth |
| JWT — weak signing secret | 🟡 Medium | JWT auth |
| Email Verification Bypass | 🟡 Medium | Email verify flow |
| Rate Limit Bypass — header rotation | 🟢 Easy | Login / API |
| Clickjacking — missing X-Frame-Options | 🟢 Easy | Account settings frame |

### Authorization
| Vulnerability | Difficulty | Where |
|---------------|:---:|-------|
| IDOR — user profile | 🟢 Easy | Profile pages |
| IDOR — orders | 🟢 Easy | Order details |
| IDOR — support tickets | 🟢 Easy | Ticket internal notes |
| IDOR — API user data | 🟢 Easy | REST API |
| IDOR — developer secrets | 🟡 Medium | Profile API |
| Multi-Tenant Authorization — cross-tenant access | 🟡 Medium | Tenant workspace |
| Broken Access Control — admin bypass | 🟢 Easy | Admin panel cookie check |
| Broken Access Control — internal API | 🟢 Easy | Internal config endpoint |
| Mass Assignment — role escalation | 🟡 Medium | Profile update API |
| Webhook Signature Bypass | 🟡 Medium | Webhook verification |
| Log Injection — forged entries | 🟡 Medium | Event logging API |
| Email Header Injection | 🟡 Medium | Newsletter signup |
| Information Disclosure — .env exposed | 🟢 Easy | Static file serving |
| Information Disclosure — source maps | 🟡 Medium | JS bundle source maps |
| Information Disclosure — Swagger/OpenAPI leak | 🟢 Easy | API docs endpoint |
| Information Disclosure — object storage bucket | 🟢 Easy | Storage browser |
| Unauthenticated Data Export | 🟢 Easy | User export API |

### API & Modern
| Vulnerability | Difficulty | Where |
|---------------|:---:|-------|
| GraphQL Introspection Exposure | 🟢 Easy | GraphQL endpoint |
| GraphQL IDOR / over-fetching | 🟡 Medium | GraphQL queries |
| WebSocket — no authentication | 🟡 Medium | Support chat |
| WebSocket — room IDOR | 🟡 Medium | Support chat |
| WebSocket — stored XSS | 🟢 Easy | Support chat |
| Business Logic — negative quantity | 🟡 Medium | Order checkout |
| Business Logic — coupon reuse | 🟡 Medium | Coupon system |
| AI/LLM Prompt Injection | 🟡 Medium | AI support assistant |
| CORS Misconfiguration | 🟡 Medium | API endpoints |
| Weak Cryptography (MD5 hashing) | 🟢 Easy | Password storage |

---

## 👥 Bug Bounty Platform Features

The `/program` platform mirrors a real HackerOne/Bugcrowd workflow:

- **Scope & rules of engagement** — in-scope assets, severity guide (P1–P5)
- **Report submission** — title, vuln type, steps to reproduce, impact, PoC, severity
- **Flag-based instant verification** — submit a proof string with your report for automatic acceptance
- **First Blood tracking** — first researcher to find each bug earns bonus recognition
- **Triage workflow** — New → Needs More Info → Accepted → Duplicate → Informative → N/A → Resolved
- **Admin triage dashboard** — staff can override status, severity, and add notes
- **Leaderboard & Hall of Fame**
- **Example reports** — accepted, duplicate, informative, not-applicable templates to learn report writing
- **Progressive 3-level hint system** for every vulnerability (gated by `LAB_MODE`)

---

## 🗂️ Architecture

```
syntex-lab/
├── docker-compose.yml          ← All services, localhost-only ports, LAB_MODE setting
├── nginx.conf                  ← 27 vhosts (main + program + recon targets)
├── dns/dnsmasq.conf            ← Local DNS server for subdomain discovery tools
├── wordlist.txt                ← Custom wordlist for ffuf/gobuster
├── .env.example                ← Environment variable template
├── README.md
├── SOLUTIONS.md                ← Walkthroughs (spoilers)
├── CHANGELOG.md
├── CONTRIBUTING.md
├── TROUBLESHOOTING.md
├── docs/
│   ├── setup.md
│   └── methodology.md
└── backend/
    ├── server.js
    ├── database/
    │   ├── init.sql
    │   └── seed.js
    ├── middleware/
    ├── routes/                 ← One file per vulnerability domain
    └── views/
        ├── partials/           ← Shared layout (main site + program platform)
        ├── vulns/              ← Vulnerability-specific pages
        └── program/            ← Bug bounty platform pages
```

---

## 🔄 Lab Management

```bash
# Start
docker compose up -d

# Stop
docker compose down

# Fresh start (wipes database)
docker compose down -v && docker compose up --build

# Reset lab data only (keeps schema, clears reports/progress)
docker exec syntex_app node database/reset.js

# View logs
docker logs syntex_app -f
```

---

## 🔭 Recon Quick Reference

```bash
# Tech fingerprinting
curl -I http://syntex.local/

# Subdomain discovery (subfinder won't work on .local — use ffuf)
ffuf -u http://127.0.0.1 -H "Host: FUZZ.syntex.local" -w wordlist.txt -mc 200,301,302,403,503

# API documentation discovery
curl http://syntex.local/swagger.json | jq .paths

# JavaScript analysis
python3 linkfinder.py -i http://syntex.local/js/config.js -o cli
```

Full methodology and recon phases are documented in [docs/methodology.md](docs/methodology.md).

---

## 🔒 Safety

- All ports bound to `127.0.0.1` (localhost only)
- The lab contains command injection, SSRF, and file read vulnerabilities
- **Never expose this lab to any network**
- Reset regularly between sessions: `docker exec syntex_app node database/reset.js`

---

## 📚 Learning Paths

**Beginner path** — set `LAB_MODE=beginner`. Read the scope, hunt obvious IDOR/XSS/exposure bugs, use hints liberally, submit your first report.

**Intermediate path** — set `LAB_MODE=intermediate`. SQLi to admin dump, JWT attacks, SSRF chains, GraphQL exploitation — hints available but no solutions.

**Advanced path** — set `LAB_MODE=hard`. Full recon methodology, vulnerability chaining, race conditions, request smuggling — no hints.

**Realistic path** — set `LAB_MODE=realistic`. Only scope, rules, and report submission are visible. No vulnerability names, no flags, no hints. This is the closest simulation to a live bug bounty program.

---

## ⚠️ Disclaimer

This lab is for **educational purposes only**. All vulnerabilities are intentional. Do not use techniques practiced here against any system you do not own or have explicit written permission to test.

**Hack the planet — legally.** 🌍
