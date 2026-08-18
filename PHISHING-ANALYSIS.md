# Phishing Email Analysis Report

**Analyst:** Sohail Ali
**Date of analysis:** 2026-08-18
**Sample type:** Simulated credential-phishing email (training exercise, IOCs deliberately constructed for analysis practice)

---

## Summary

A phishing email impersonating internal IT Support was analyzed. The email attempts to trick the recipient (`brolf@easyas123.tech`) into "verifying" their domain credentials via a lookalike login page, using urgency-based social engineering ("password expires in 2 hours"). Header and link analysis confirmed the email is fraudulent across four independent indicators.

## Email Overview

| Field | Value |
|---|---|
| Subject | "URGENT: Your Password Expires in 2 Hours - Immediate Action Required" |
| Claimed sender | "IT Support Desk" |
| Target recipient | brolf@easyas123.tech |
| Social engineering technique | Urgency / fear of account lockout |

## Findings — Header Analysis

**1. Sender domain spoofing**
```
From: "IT Support Desk" <it-support@easyas123-tech-portal.com>
```
The display name ("IT Support Desk") is designed to look trustworthy, but the actual sending domain, `easyas123-tech-portal.com`, does not match the organization's real domain, `easyas123.tech`. This is a lookalike domain registered to impersonate the company.

**2. Reply-To mismatch**
```
Reply-To: helpdesk.response@mail-recovery-service.ru
```
Any reply would route to a completely unrelated domain, not even the spoofed IT domain from the From field — a strong indicator of malicious intent, since legitimate IT communications reply within their own infrastructure.

**3. Authentication results — SPF/DKIM/DMARC all failed**
```
spf=fail
dkim=fail
dmarc=fail (p=REJECT sp=REJECT dis=NONE)
```
The receiving mail server's own cryptographic checks confirm this email was not authorized to be sent as it claims. In a properly configured environment, DMARC policy `p=REJECT` means this message should have been blocked before reaching the inbox.

## Findings — Link Analysis

The embedded call-to-action link:
```
http://easyas123-secure-login.tech-verify.net/reset?user=brolf&token=8f3a9c2e
```

- **True domain**: `tech-verify.net` — the company name (`easyas123-secure-login`) is stuffed into the subdomain to deceive a casual glance; the actual registered/controlling domain is unrelated to the organization.
- **No HTTPS**: the link uses plain `http://`, meaning any credentials entered would be transmitted unencrypted.
- **Parameterized token**: the `token=` value suggests the link may be uniquely tied to the recipient, consistent with a targeted credential-harvesting campaign rather than generic spam.

## Verdict

**Malicious — Credential Phishing.** Recommend blocking sender domain and link domain at the email gateway/proxy, and issuing a security awareness notice to staff referencing this specific lure pattern.

## Recommended Actions

1. Block `easyas123-tech-portal.com` and `tech-verify.net` at the email gateway and web proxy.
2. Confirm the email was not clicked/interacted with by the recipient; if it was, treat as a potential credential compromise and force a password reset.
3. Report the sending infrastructure (IP/domain) to relevant blocklist services.
4. Reinforce user awareness: legitimate IT communications will never link to a domain other than the organization's own.

---
*Analysis performed as part of a self-directed SOC training lab. Sample email was constructed with deliberate, realistic IOCs for training purposes.*
