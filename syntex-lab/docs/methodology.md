# Bug Bounty Methodology — Syntex Lab

This lab is mapped to the real-world methodology used by top hunters on HackerOne/Bugcrowd.

## Phase 1 — Passive Recon
```bash
curl -I http://syntex.local/         # headers, version
curl http://syntex.local/robots.txt  # hidden paths
curl http://syntex.local/.well-known/security.txt
curl http://syntex.local/swagger.json | jq .paths
```

## Phase 2 — Subdomain Enum
```bash
# ffuf vhost (recommended for .local)
ffuf -u http://127.0.0.1 -H "Host: FUZZ.syntex.local" -w wordlist.txt -mc 200,301,302,403,503

# httpx probe
cat found_subs.txt | httpx -status-code -title -tech-detect
```

## Phase 3 — Directory Fuzzing
```bash
ffuf -u http://syntex.local/FUZZ -w wordlist.txt -mc 200,301,302,403,500
gobuster dir -u http://syntex.local -w wordlist.txt -x js,json,sql,bak,env
```

## Phase 4 — JS Analysis
```bash
python3 linkfinder.py -i http://syntex.local/js/config.js -o cli
python3 SecretFinder.py -i http://syntex.local/js/internal.js -o cli
curl http://syntex.local/js/app.bundle.js.map | jq .
```

## Phase 5 — Automated Scanning
```bash
nuclei -u http://syntex.local -t exposures/ -t misconfiguration/ -t vulnerabilities/
dalfox url 'http://syntex.local/search?q=test'
sqlmap -u 'http://syntex.local/search?q=test' -p q --dbs --batch
python3 corsy.py -u http://syntex.local/api/v1/users
```

## Phase 6 — Manual Testing
Use Burp Suite for all manual testing. Install these extensions:
- Autorize (IDOR)
- JWT Editor (JWT attacks)
- Param Miner (hidden params)
- Logger++ (request filtering)
- Turbo Intruder (race conditions)
