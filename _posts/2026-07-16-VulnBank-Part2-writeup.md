---
title: "VulnBank Series #2 — BOLA, Mass Assignment, Broken Transaction Logic & Weak Password Reset"
date: 2026-07-16
categories: [VulnBank, Web Security]
tags: [vulnbank, bola, mass-assignment, broken-access-control, transaction-validation, password-reset, api-security, owasp, cwe-639, cwe-915, cwe-20, cwe-640, mini-series]
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
**Post:** 2 of idk yet ヽ(´ー｀)ﾉ
**Scope:** `http://localhost:5000`

---

## Quick Recap

Post 1 covered the initial access findings: unauthenticated Swagger docs exposing the full API surface, SQL injection bypassing the entire login mechanism, a weak JWT secret enabling token forgery, and stored XSS chained with localStorage token exposure for admin account takeover.

Post 2 goes deeper into the authenticated attack surface. With a valid session in hand, the real damage begins...and in a banking application, that damage has a very direct financial meaning.

---

## Finding VB-005 — Broken Object Level Authorization (BOLA)

**Severity:** High  
**CVSS:** 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)  
**CWE:** CWE-639 Authorization Bypass Through User-Controlled Key  
**OWASP:** A01:2021 Broken Access Control

### What Happened

Five API endpoints accept object identifiers directly from the URL path —> account numbers, user IDs, card IDs, without ever checking whether the authenticated user actually owns that resource. Changing the number in the URL is enough to access anyone else's data.

This is BOLA in its most classic form: the API trusts the client to only request what belongs to them. It does not verify that trust at the server.

### Confirmed Vulnerable Endpoints

**Data access:**

```
GET /check_balance/{account_number}
GET /transactions/{account_number}
GET /api/v3/user/{user_id}
GET /api/virtual-cards/{card_id}/transactions
```

**Actions:**

```
POST /api/virtual-cards/{card_id}/toggle-freeze
```

### Reproducing It

Logged in as a standard user with user ID 2. Sent a balance request for the admin account:

```
GET /check_balance/ADMIN001
```

Response came back with the admin's balance — $1,000,000.00. No authorization error. No indication the server questioned whether user ID 2 should be reading the admin's balance.

Then pulled the full admin profile:

```
GET /api/v3/user/1
```

Response returned username, balance, and `"is_admin": true` for the admin account. From a standard user session.

**BOLA — Accessing Admin Balance from Standard User Account:**
![BOLA — standard user accessing admin balance](/assets/images/VULNBANK/check-balance.png)

**BOLA — Accessing Admin Full User Profile (via API v3):**
![BOLA — admin profile returned to standard user](/assets/images/VULNBANK/transactions.png)

**BOLA — Accessing full admin profile with is_admin flag exposed:**
![BOLA — full admin profile with is_admin flag exposed](/assets/images/VULNBANK/v3.png)

For the card endpoints, created a second user account (`0x5h4q`, user ID 3) with a virtual card (card ID 2). Then from the original session as `qxvat7r`:

```
POST /api/virtual-cards/2/toggle-freeze
```

Response: `"Card frozen successfully"` — froze another user's card from a completely different account.

<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExemd3cW9ma3R3ZzNqODl1dDh0eHFldHNqOWRjejZvcTVjdXhnZ3h0MSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/ep78UZy5FVbfN6mhCU/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">


```
GET /api/virtual-cards/2/transactions
```

Returned the full transaction history for a card that doesn't belong to the requesting user.

**BOLA — Freezing Another User's Virtual Card (qxvat7r freezing 0x5h4q's card):**
![BOLA — freezing another user's virtual card](/assets/images/VULNBANK/toggle-freeze.png)

![BOLA — freezing another user's card](/assets/images/VULNBANK/freeze.png)

**BOLA — Accessing Another User's Card Transactions:**
![BOLA — card transaction history from another user](/assets/images/VULNBANK/shaq-transac.png)

**BOLA — Full Card Transactions Data Exposed:**
![BOLA — full card transaction data exposed](/assets/images/VULNBANK/shaq-card-id.png)

### Impact

Any authenticated user can enumerate account numbers and user IDs to access the entire user base's financial data. Combined with the transaction history access, an attacker builds a complete picture of every account; balances, transfer history, card activity, etc...across the whole platform. The card freeze is a denial-of-service primitive against any user.

### Remediation

Server-side ownership verification on every object-level endpoint. Before returning data or performing an action, confirm the authenticated user's ID matches the resource owner. Use UUIDs instead of sequential identifiers to make enumeration harder. Centralize the authorization check in middleware rather than implementing it per-endpoint.

---

## Finding VB-006 — Mass Assignment and Excessive Data Exposure

**Severity:** High  
**CVSS:** 8.6 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)  
**CWE:** CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes + CWE-200 Exposure of Sensitive Information  
**OWASP:** A04:2021 Insecure Design / A01:2021 Broken Access Control

### What Happened

Two separate problems, both serious, both touching the virtual card system.

**Mass Assignment:** The card update endpoints blindly pass every field from the request body directly into the database UPDATE statement. An attacker can inject any column name into the request and the application will attempt to update it. The database errors themselves confirm the fields were processed.

**Excessive Data Exposure:** The card creation and listing endpoints return full unmasked 16-digit card numbers (PAN) and CVV codes in the API response. This is a direct PCI-DSS violation. CVV must never be stored after initial verification. PAN must be masked in all displays.

### Mass Assignment — Card Limit Update

Sent an update request with unauthorized fields injected:

```json
POST /api/virtual-cards/1/update-limit
{
  "card_limit": 999999,
  "is_admin": true
}
```

Response included the database error:

```
"column \"is_admin\" of relation \"virtual_cards\" does not exist"
```

The error confirms the application attempted to execute `UPDATE virtual_cards SET is_admin = true`. The column did not exist, so it errored — but if it had existed, the update would have succeeded.

Tried financial fields next:

```json
{
  "limit": 50000,
  "card_number": "9999999999999999",
  "balance": 1000000
}
```

Again the SQL error confirmed all three fields were processed in the UPDATE statement.

**Mass Assignment — is_admin Field Accepted by Card Limit Update:**  
![Mass Assignment — is_admin field accepted and processed](/assets/images/VULNBANK/is_admin.png)

**Mass Assignment — Multiple Financial Fields Injected into UPDATE Statement:**  
![Mass Assignment — multiple financial fields injected into UPDATE](/assets/images/VULNBANK/Screenshot_2026-07-16-044242.png)

### Mass Assignment — Card Funding Exchange Rate

Funded a card with a manipulated exchange rate:

```json
POST /api/virtual-cards/1/fund
{
  "amount": 1,
  "exchange_rate": 1000000
}
```

The application accepted and processed the user-supplied `exchange_rate` field with no validation. Client-controlled currency conversion means an attacker can credit any card with an arbitrarily inflated balance by supplying a fake exchange rate.

### Excessive Data Exposure

Created a virtual card and inspected the response:

```json
{
  "card_number": "4532871234567890",
  "cvv": "847",
  "expiry_date": "07/29"
}
```

Full PAN, full CVV, expiry — everything needed for card-not-present fraud, returned in plaintext in the API response. The card listing endpoint did the same for every card in the account.

**Excessive Data Exposure — Full PAN, CVV, and Expiry in Card Creation Response:**  
![Excessive Data Exposure — full PAN and CVV in card creation response](/assets/images/VULNBANK/full-pan.png)

**Excessive Data Exposure — Full Card Details Unmasked in Card List Response:**  
![Excessive Data Exposure — full card details in listing response](/assets/images/VULNBANK/full-card.png)

### Impact

Mass Assignment means an attacker who understands the database schema can overwrite any column on the virtual cards table; i.e balances, card numbers, admin flags, anything. The exchange rate manipulation provides direct financial gain: fund a card with $1 at a fake exchange rate of 1,000,000 and credit the card balance with $1,000,000.

The excessive data exposure is a PCI-DSS violation at baseline. Combined with BOLA (VB-005), an attacker can enumerate every card in the system and retrieve complete card details for all users in a single enumeration pass.

### Remediation

For Mass Assignment: implement explicit allowlists per endpoint using DTOs or schema validation (Marshmallow or Pydantic). Only the fields defined in the allowlist should reach the database. Reject requests containing any unexpected field.

For Excessive Data Exposure: mask all PANs in responses (return only the last 4 digits). Never return CVV in any response after initial card creation. Never store CVV after authorization — PCI-DSS Requirement 3.2 is unambiguous on this.

---

## Finding VB-007 — Insufficient Transaction Validation

**Severity:** Critical  
**CVSS:** 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H)  
**CWE:** CWE-20 Improper Input Validation + CWE-841 Improper Enforcement of Behavioral Workflow  
**OWASP:** A03:2021 Injection / A04:2021 Insecure Design

### What Happened

The money transfer endpoint at `/transfer` performs no validation on the transaction amount. Negative amounts are accepted and processed. The sign of the amount flips the direction of the transaction; debiting the recipient and crediting the sender instead of the other way around.

This is not a logic edge case. This is a financial theft primitive.

### Reproducing It

Noted the starting balances of both accounts, then sent a transfer with a negative amount:

```json
POST /transfer
{
  "to_account": "4664359451",
  "amount": -500
}
```

Response: `"Transfer Completed"`

The sender's balance increased by $500. The recipient lost $500.

Sent money to another account and the platform reversed the transaction direction — stealing from the recipient and crediting the attacker. Zero-value transfers were also accepted with no error.

**Starting Balances Before Attack:**  
![Starting balances before the attack](/assets/images/VULNBANK/starting-balance.png)

**Negative Amount Transfer Accepted — $500 Stolen:**  
![Negative amount transfer accepted — $500 stolen](/assets/images/VULNBANK/negative-transfers.png)

**Balances After Attack — Attacker Gained $500, Victim Lost $500:**  
![Balances after — attacker gained, victim lost](/assets/images/VULNBANK/after-transfers.png)

**Zero Amount Transfer Accepted:**  
![Zero amount transfer accepted with no error](/assets/images/VULNBANK/zero-amount.png)

**Transaction History of both Users:**  
![HISTORY ](/assets/images/VULNBANK/transac-history.png)

### Impact

Any authenticated user can drain funds from any account they know the account number for (which BOLA already provides). Combined with VB-005, an attacker enumerates all accounts and systematically drains every balance on the platform. This is the most direct financial damage vector in the application.

### Remediation

Reject any amount at or below zero at the API validation layer. Enforce minimum transaction amounts. Add balance sufficiency checks before processing. Implement daily transfer limits and idempotency keys. Use integer arithmetic (cents) rather than floating-point for all monetary values. Add database-level CHECK constraints as a last line of defence.

---

## Finding VB-008 — Weak Password Reset Mechanism

**Severity:** Critical  
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**CWE:** CWE-640 Weak Password Recovery Mechanism + CWE-200 Exposure of Sensitive Information  
**OWASP:** A07:2021 Identification and Authentication Failures

### What Happened

The password reset functionality ships in three API versions. Version 1 returns the reset PIN directly in the JSON response. The v2 and v3 endpoints hide the PIN but use 3-4 digit numeric codes with no rate limiting and no account lockout. All three versions allow full account takeover. V1 does it in one request.

### Part A — v1 PIN Exposure

Sent a password reset request for any username:

```json
POST /api/v1/forgot-password
{"username": "qxvat7r"}
```

Response:

```json
{
  "debug_info": {
    "pin": "501",
    "pin_length": 3,
    "username": "qxvat7r"
  }
}
```

The PIN is in the response. Used it immediately:

```json
POST /api/v1/reset-password
{"username": "qxvat7r", "pin": "501", "new_password": "attacker123"}
```

Account taken over. No email access required. No interaction from the victim.

**v1 API — PIN Exposed Directly in API Response:**  
![v1 API returning the reset PIN in the debug_info field](/assets/images/VULNBANK/v1-pin.png)

**Swagger Documentation Confirming v1 PIN Exposure, v2/v3 Weak PINs:**  
![Swagger docs showing all three API versions](/assets/images/VULNBANK/reset-docs.png)

### Part B — v2/v3 Brute-Force

v2 uses a 3-digit PIN (1,000 possible values). v3 uses a 4-digit PIN (10,000 possible values). Neither version implements rate limiting or account lockout. Burp Intruder or a simple Python loop exhausts the entire keyspace in seconds to minutes.

**v2 API — PIN Hidden but Still 3-Digit (Brute-Forceable):**  
![v2 — PIN hidden but 3-digit and brute-forceable](/assets/images/VULNBANK/v2-pin.png)

**v3 API — PIN Hidden but  4-Digit (takes longer time but Brute-Forceable ):**
![v3 — 4-digit PIN takes longer but still brute-forceable](/assets/images/VULNBANK/intruder.png)

### API Version Comparison

| Version | PIN Length | PIN in Response | Max Attempts | Secure? |
|---|---|---|---|---|
| v1 | 3 digits | Exposed directly | 1 | Critical |
| v2 | 3 digits | Hidden | 1,000 | High risk |
| v3 | 4 digits | Hidden | 10,000 | High risk |

None of the three versions are acceptable.

### Impact

An unauthenticated attacker with only a username can take over any account on the platform via v1. No email access required. For v2 and v3, the brute-force window is trivially small with no rate limiting. This completely undermines the entire authentication model as regardless of password strength, any account can be reset from the outside.

### Remediation

Disable the v1 endpoint immediately. Implement rate limiting across all versions —> maximum 3-5 attempts per account per hour. Replace the PIN mechanism entirely: generate a cryptographically random token, send it via email (not in the API response), set a 15-minute expiration. Remove all `debug_info` blocks from production responses. Audit all API versions for similar patterns.

---

## Findings Summary — Posts 1 and 2

| ID | Finding | Severity | CVSS |
|---|---|---|---|
| VB-001 | Unauthenticated API Documentation Exposure | High | 7.5 |
| VB-002 | SQL Injection Authentication Bypass | Critical | 9.8 |
| VB-003 | Weak JWT Implementation | Critical | 9.1 |
| VB-004 | Stored XSS and JWT Token Theft | High | 8.3 |
| VB-005 | Broken Object Level Authorization | High | 8.1 |
| VB-006 | Mass Assignment and Excessive Data Exposure | High | 8.6 |
| VB-007 | Insufficient Transaction Validation | Critical | 9.1 |
| VB-008 | Weak Password Reset Mechanism | Critical | 9.8 |

Eight findings across two posts. Four criticals, four highs. Every single authentication and authorization control in the application has failed.

---

## What Did We Learn?

**1. BOLA is the most common API vulnerability for a reason**  
Every endpoint that uses an identifier from the URL is a potential BOLA. The question is always: does the server verify ownership before responding? In VulnBank the answer was no across five endpoints. In real fintech APIs, this pattern shows up constantly — especially on older or rushed implementations where authorization was added as an afterthought.

**2. Mass Assignment happens when the server trusts the client's field names**  
Passing the raw request body directly to a database update query is the root cause. The application has no concept of which fields are allowed to change for a given endpoint. Allowlists at the schema validation layer are the only reliable fix.

**3. Negative amounts in financial APIs are a theft primitive, not an edge case**  
The moment a transfer endpoint accepts negative values, the transaction direction can be reversed. This is not a subtle logic bug — it is a direct financial attack vector. Amount validation should be the first check before any transaction is processed.

**4. Debug information in production API responses is a critical finding**  
The v1 forgot-password endpoint returned the reset PIN in a `debug_info` field. Debug output that makes development convenient becomes a critical vulnerability in production. Every `debug_info`, stack trace, and internal message that reaches the client is a potential finding.

**5. API versioning without security review creates an attack surface**  
VulnBank ships three versions of the password reset API with progressively better but still inadequate security. Old API versions rarely get decommissioned and often bypass newer security controls applied to the current version. Always include all active API versions in scope during a pentest.

**Next post:** SSRF via the profile picture URL endpoint, path traversal in file uploads, and internal endpoint access.

---

<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExdW95MWNrcTA5cnN0b2E3enkwc2p0ZzB4enpmYXVhODUwMDhmejdncCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/oPQJidn1zDv2UomYO9/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">

*Written by 0x5h4q | [0x5h4q.github.io](https://0x5h4q.github.io)*
