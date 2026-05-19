# 📧 Operation: Phantom Invoice — BEC Forensic Analysis

## 🗂️ Overview

- **Classification:** Confidential
- **Category:** BEC · Invoice Fraud · Header Forensics
- **Sprint:** CyBlack Email Phishing Analysis Sprint
- **Files Analysed:** Email1.eml · Email2.eml · Email3.eml (https://drive.google.com/drive/folders/1lpUyshLC5g90Qc9bLcvoeyimB7DHjcl9?usp=sharing)
- **Date:** May 2026

---

## 👤 Executive Summary

A mid-sized logistics company (Nexus Logistics) reported that its accounts-payable team received a three-email chain over five days purporting to originate from the company CFO (James Hargrove) and a known vendor (Meridian Freight Solutions LLC), requesting an urgent wire transfer of **$47,000**. The finance manager (Sarah) nearly approved the transfer before IT Security flagged the request.

All indicators point to a coordinated Business Email Compromise (BEC) campaign executed by a threat actor who spoofed both the CFO and vendor identities from a single external sending infrastructure (`smtp.webmailpro.xyz` / IP `185.234.219.101`, geolocated to Vienna, Austria). No legitimate authentication records (SPF, DKIM, DMARC) passed for any of the three emails.

> ⚠️ All analysis was conducted on the provided `.eml` files in a sandboxed, offline environment. No domains, IPs, or file hashes were interacted with in a live environment.

---

## 🔬 Analysis Findings

### 1. Sending Email Addresses & Lookalike Domains

Two distinct sending addresses were identified across the three emails:

- `j.hargrove@nexus-logistics.com` — Email1 & Email3, impersonating the CFO
- `billing@meridianfreight-solutions.net` — Email2, impersonating the vendor

Both addresses share the same underlying SMTP relay (`smtp.webmailpro.xyz`), strongly suggesting a single threat actor operating both identities. Both domains are lookalikes engineered to pass a quick visual inspection of a legitimate organisation name. 
nexus-Iogistics.com impersonates the legitimate nexuslogistics.com by substituting a capital letter 'I' (eye) in place of a lowercase 'l' (ell) in the word 'logistics'. This is a classic homoglyph substitution attack, visually indistinguishable at a glance in most email clients.

<img width="975" height="107" alt="image" src="https://github.com/user-attachments/assets/f23fbdae-9d22-4aae-a7c6-d9af6b63d884" />
<img width="975" height="54" alt="image" src="https://github.com/user-attachments/assets/7eb59a36-4be9-4c7d-a614-0b64bff7b17a" />

---

### 2. Header Discrepancies — From, Reply-To, Return-Path

Critical mismatches were found in all three emails:

- **From:** Displays the impersonated identity, creating the illusion of legitimacy
- **Reply-To:** Redirects replies to a separate attacker-controlled address — a classic BEC indicator
- **Return-Path:** Resolves to `smtp.webmailpro.xyz` for all three emails, completely unrelated to either organisation

This divergence between the displayed sender and the actual mail routing path is definitive evidence of email spoofing, and confirms both identities share one sending infrastructure.

<img width="850" height="93" alt="image" src="https://github.com/user-attachments/assets/60601006-b99a-41f1-89fe-29e188e207cb" />
<img width="975" height="107" alt="image" src="https://github.com/user-attachments/assets/e7a623f5-5f60-4c3a-8835-428617765310" />

---

### 3. Email Authentication Results — SPF, DKIM, DMARC

None of the three emails passed any authentication check.

- **SPF:** FAIL across all three — IP `185.234.219.101` is not an authorised sender for either domain
- **DKIM:** No valid signatures found — message integrity cannot be cryptographically verified
- **DMARC:** Failed for all three, yet emails were still delivered due to a missing enforce policy on the target organisation's email gateway

<img width="975" height="107" alt="image" src="https://github.com/user-attachments/assets/98268b63-22e6-417d-a945-ba8c7db4f9e3" />
<img width="975" height="107" alt="image" src="https://github.com/user-attachments/assets/f40bf953-3fd6-4499-a144-40925f483a75" />

---

### 4. Originating IP Geolocation

The external originating IP identified across all three emails is `185.234.219.101`, geolocated to **Vienna, Austria** — directly contradicting the CFO's claimed location of Singapore in the email body.

Three internal relay IPs were also observed in the Received headers:

- `192.168.1.45` — internal relay, Email1 (RFC 1918, not attacker infrastructure)
- `10.0.0.22` — internal relay, Email2 (RFC 1918, not attacker infrastructure)
- `172.16.0.55` — internal relay, Email3 (RFC 1918, not attacker infrastructure)

<img width="975" height="454" alt="image" src="https://github.com/user-attachments/assets/c1829d7c-8eee-4461-b8ac-bdf1f7508d35" />

---

### 5. Links and Attachments

Email 2 (vendor follow-up) references an invoice attachment: Invoice_MFS_Q4_2023_047.pdf. This filename is consistent with the reference number INV-MFS-Q4-2023-047 cited throughout the chain, suggesting it was crafted to appear as a legitimate overdue invoice. No attachment was confirmed as physically present in the visible header data — the reference appears in the email body only. In a full .eml analysis, the MIME structure would need to be examined to confirm whether the file was actually attached or merely referenced to add credibility.

<img width="975" height="107" alt="image" src="https://github.com/user-attachments/assets/09da64bf-22e5-4d7a-9a22-13da91c84590" />

No hyperlinks were present in the body text of any of the three emails. The attack relied entirely on social engineering and wire transfer instructions rather than malicious URLs, which is characteristic of BEC campaigns. They typically avoid links to evade URL-scanning gateways.

Without confirmed extraction of the PDF attachment from the .eml file, a file hash (MD5/SHA-256) cannot be computed at this stage. If the attachment is confirmed present, the hash should be submitted to VirusTotal and cross-referenced against known malware repositories. The filename itself (Invoice_MFS_Q4_2023_047.pdf) should be treated as an IOC regardless.

---

### 6. Social Engineering Technique

The primary technique is **Spear Phishing** — a highly targeted variant where the attacker conducts deep pre-attack research to craft credible, personalised communications.

Evidence of extensive reconnaissance:

- Accurate use of the CFO's full name and email display
- Accurate knowledge of the CFO's travel schedule (Singapore), likely harvested from social media
- Detailed knowledge of the Nexus–Meridian business relationship and vendor contact details
- Direct targeting of Sarah as the accounts-payable approver
- Fabricated banking detail change narrative to redirect the $47,000 payment

Supporting techniques: **authority bias** (C-level impersonation), **urgency pressure**, and **social proof** (vendor email corroborating the CFO's request).

---

### 7. WHOIS Registration & Domain Age

WHOIS lookups for `nexus-Iogistics.com` and `meridianfreight-solutions.net` returned no results. Two likely explanations:

- **Ephemeral domains** — registered specifically for this campaign and taken down or allowed to expire after use. Common practice for disposable phishing infrastructure.
- **WHOIS redaction** — privacy-protected registration obscuring the details.

Either outcome is consistent with freshly registered phishing infrastructure designed for short-lived, single-campaign use.

---

### 8. X-Mailer / Sending Client

The X-Mailer header identifies the sending client as **`The Bat! 10.3 (UNREG)`** for Windows.

Two red flags:

- The Bat! is a personal desktop email client, not a corporate mail server. No mid-sized logistics company would send CFO-level financial communications from a personal client.
- **(UNREG)** indicates an unregistered, unlicensed copy of the software — inconsistent with legitimate corporate operations.

<img width="975" height="183" alt="image" src="https://github.com/user-attachments/assets/77754b85-2103-422b-8771-2142bbce612c" />

---

### 9. Thread Hijacking Assessment

The email chain does not technically exhibit thread hijacking. Thread hijacking occurs when an attacker injects a reply into a legitimate existing thread to leverage established trust.

Evidence against thread hijacking in this case:

- All three emails originate from the same external relay (`smtp.webmailpro.xyz`) — the entire chain was constructed from scratch by the attacker
- The vendor email references the CFO's communication, but this is fabricated coordination between two attacker-controlled identities, not a hijacked legitimate reply
- No evidence of a prior legitimate email thread that was compromised

---

### 10. MITRE ATT&CK Classification

| T-Code | Technique | Application |
|--------|--------|-----------|
| T1566.001 | Spearphishing via Attachment | Invoice PDF in Email 2 |
| T1036.005 | Masquerading – Match Legitimate Name | nexus-Iogistics.com spoofing |
| T1585.001 | Establish Accounts – Email Accounts | Gmail and webmailpro.xyz accounts |
| T1534 | Internal Spearphishing (BEC pattern) | CFO-to-employee wire fraud |
| T1656 | Impersonation | CFO and vendor accounts impersonated |

See the full technique mapping with evidence breakdown in [Forensic_Report.md](Forensic_Report.md#️-mitre-attck-technique-mapping).

---

### 11. Indicators of Compromise

| Type | Value |
|------|-------|
| IP — External C2 | `185.234.219.101` (Vienna, Austria) |
| IP — Internal Relay | `192.168.1.45` · `10.0.0.22` · `172.16.0.55` |
| Domain — Relay | `smtp.webmailpro.xyz` |
| Domain — Lookalike | `nexus-logistics.com` |
| Domain — Lookalike | `meridianfreight-solutions.net` |
| Email | `j.hargrove@nexus-logistics.com` |
| Email | `billing@meridianfreight-solutions.net` |
| Email | `j.hargrove.cfo@gmail.com` |
| Email | `bounce@smtp.webmailpro.xyz` |
| File Hashes | `Invoice_MFS_Q4_2023_047.pdf` |
| Bank Account | `4782910365 / Routing 084201278` |
| Reference | `INV-MFS-Q4-2023-047` |

See the full IOC table with classifications and confidence levels in [Forensic_Report.md](Forensic_Report.md#️-indicators-of-compromise-ioc-table).

---

### 12. Containment Actions & Preventive Controls

**Immediate Containment:**

1. **Block & Blacklist** — Block IP `185.234.219.101`, domain `smtp.webmailpro.xyz`, and all lookalike domains at the perimeter firewall, email gateway, and spam filter
2. **Mailbox Remediation** — Purge all three phishing emails from Sarah's mailbox; audit for attacker-planted auto-forwarding or auto-deletion inbox rules
3. **Credential & Access Audit** — Verify no mailbox credentials were compromised; review internal access logs for anomalous IPs or session behaviour

**Preventive Controls:**

- Enforce DMARC reject policy and configure DKIM signing on all outbound mail
- Implement multi-step wire transfer approval — no single employee approves a large transfer based solely on email
- Conduct BEC-specific awareness training with simulated wire-transfer phishing exercises targeting finance staff
- Apply Principle of Least Privilege (PoLP) to financial and vendor data systems
- Deploy external email warning banners on all inbound emails from outside the organisation

---

📄 **Full IOC Table, MITRE ATT&CK Mapping, and Remediation Plan → [Forensic_Report.md](Forensic_Report.md)**
