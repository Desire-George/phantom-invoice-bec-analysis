# 📋 Operation: Phantom Invoice — Forensic Report

## 🗂️ Overview

- **Classification:** Confidential
- **Category:** BEC · Invoice Fraud · Header Forensics
- **Sprint:** CyBlack Email Phishing Analysis Sprint
- **Files Analysed:** Email1.eml · Email2.eml · Email3.eml
  (https://drive.google.com/drive/folders/1lpUyshLC5g90Qc9bLcvoeyimB7DHjcl9?usp=sharing)
- **Date:** May 2026

📄 **Full analysis findings → [README.md](README.md)**

---

## 🗄️ Indicators of Compromise (IOC Table)

| Indicator Type | Value | Source | Classification | Confidence |
|----------------|-------|--------|----------------|------------|
| IP Address | `185.234.219.101` | Received headers — all 3 emails | C2 / External Sending Server | High |
| IP Address | `192.168.1.45` | Received headers — Email1 | Internal Mail Relay | Medium |
| IP Address | `10.0.0.22` | Received headers — Email2 | Internal Mail Relay | Medium |
| IP Address | `172.16.0.55` | Received headers — Email3 | Internal Mail Relay | Medium |
| Domain | `smtp.webmailpro.xyz` | Return-Path — all 3 emails | Phishing Relay Infrastructure | High |
| Domain | `nexus-Iogistics.com` | From header — Email1 & Email3 | Homoglyph Lookalike (CFO) | High |
| Domain | `meridianfreight-solutions.net` | From header — Email2 | Spoofed Lookalike (Vendor) | High |
| Email Address | `j.hargrove@nexus-Iogistics.com` | From header — Email1 & Email3 | Impersonated CFO | High |
| Email Address | `billing@meridianfreight-solutions.net` | From header — Email2 | Impersonated Vendor | High |
| Email Address | `j.hargrove.cfo@gmail.com` | Reply-To header — Email1 & Email3 | Attacker-Controlled Reply Address | High |
| Email Address | `bounce@smtp.webmailpro.xyz` | Return-Path — Email2 | Phishing Relay Bounce Address | High |
| Email Address | `sarah.okonkwo@nexuslogistics.com` | To header — all 3 emails | Targeted Victim | High |
| File | `Invoice_MFS_Q4_2023_047.pdf` | Email2 body — attachment reference | Fraudulent Invoice (unconfirmed attachment) | Medium |
| Reference Number | `INV-MFS-Q4-2023-047` | Email body — all 3 emails | Fabricated Invoice Reference | Medium |
| Bank Account | `4782910365` | Email2 body — payment instructions | Fraudulent Beneficiary Account | High |
| Routing Number | `084201278` | Email2 body — payment instructions | Fraudulent Routing Number | High |

> ⚠️ The PDF attachment (`Invoice_MFS_Q4_2023_047.pdf`) was referenced in the Email2 body but not confirmed as physically present in the available header data. Full MIME structure analysis of the `.eml` file is required to confirm presence and extract a file hash for VirusTotal submission. The filename itself should be treated as an IOC regardless.

---

## 🛡️ MITRE ATT&CK Technique Mapping

Analysis of the email campaign identifies multiple techniques consistent with the MITRE ATT&CK framework.

| T-Code | Technique Name | How It Applies | Evidence |
|--------|----------------|----------------|----------|
| T1566 | Phishing (parent) | The overall campaign is a spear phishing BEC attack targeting a specific named employee with a fraudulent wire transfer request | All three emails; targeted recipient `sarah.okonkwo@nexuslogistics.com` |
| T1566.001 | Spearphishing Attachment | Email2 introduced a fraudulent invoice attachment (`Invoice_MFS_Q4_2023_047.pdf`) to increase legitimacy and pressure the victim | Email2 body — attachment reference |
| T1566.003 | Spearphishing via Service | All three emails were delivered through a third-party mail relay service (`smtp.webmailpro.xyz`) rather than a self-hosted server | Return-Path and Received headers across all emails |
| T1656 | Impersonation | The attacker impersonated the company CFO (James Hargrove) and a trusted vendor (Meridian Freight Solutions Accounts) across two attacker-controlled identities | From headers — Email1, Email2 & Email3 |
| T1036.005 | Masquerading — Match Legitimate Name | `nexus-Iogistics.com` uses homoglyph substitution (capital 'I' replacing lowercase 'l') to visually impersonate `nexuslogistics.com` | From header — Email1 & Email3 |
| T1534 | Internal Spearphishing (BEC pattern) | The attack mimics an internal executive-to-employee payment instruction, exploiting the trust relationship between a CFO and accounts payable staff | Email1 & Email3 body content |
| T1585.001 | Establish Accounts — Email Accounts | The attacker established a Gmail account (`j.hargrove.cfo@gmail.com`) and accounts on `smtp.webmailpro.xyz` to send and receive email as part of the attack infrastructure | Reply-To header — Email1 & Email3 |
| T1071.003 | Application Layer Protocol: Mail Protocols | Standard SMTP protocol was used via `smtp.webmailpro.xyz` to deliver all three malicious messages, blending with normal email traffic | Received headers across all emails |

---

## ⚙️ Recommendations & Remediation

### 1. Immediate Containment (0–24 hours)

- Block IP `185.234.219.101` and domain `smtp.webmailpro.xyz` at the perimeter firewall and email security gateway
- Add `nexus-Iogistics.com` and `meridianfreight-solutions.net` to the organisation's domain blocklist
- Flag and block the attacker Gmail address `j.hargrove.cfo@gmail.com` across all inbound mail filters
- Delete all three phishing emails from Sarah's mailbox and perform a cross-mailbox search for the invoice reference `INV-MFS-Q4-2023-047`
- Audit Sarah's mailbox for attacker-planted inbox rules (auto-forward / auto-delete) that may indicate persistent access
- Immediately notify the bank of the fraudulent account (`4782910365 / Routing 084201278`) and file a report with relevant financial authorities

### 2. Short-Term Controls (1–4 weeks)

- Enforce **DMARC policy = reject** on all corporate sending domains to prevent domain spoofing at the gateway level
- Configure **DKIM signing** on all outbound mail flows to allow cryptographic verification of message integrity
- Implement **external email warning banners** on all inbound emails originating outside the organisation
- Deploy **dual-approval controls** for wire transfers above a defined threshold (e.g. $5,000) — requiring independent verbal confirmation via a known registered phone number, not a number provided in the email
- Register defensive typosquat and homoglyph variants of `nexuslogistics.com` to prevent reuse of the same spoofing vector

### 3. Long-Term Controls

- Run **BEC-specific security awareness training** annually, including simulated wire-transfer phishing exercises targeting finance and accounts payable staff
- Apply **Principle of Least Privilege (PoLP)** to financial systems — restrict access to vendor banking details and payment approval to essential personnel only
- Implement a formal **Vendor Payment Change Verification** process: any change to banking instructions must be confirmed via a registered phone call before processing — email confirmation alone is never sufficient
- Monitor for **lookalike and homoglyph domain registrations** targeting the organisation's brand using threat intelligence feeds
- Deploy **email header anomaly detection** in the SIEM to flag mismatches between From, Reply-To, and Return-Path at scale

---

## ✅ Conclusion

Operation Phantom Invoice demonstrates a well-researched, operationally disciplined Business Email Compromise campaign. The threat actor conducted significant pre-attack reconnaissance — accurately mapping the CFO's travel schedule, the victim's role, and the Nexus–Meridian vendor relationship — before constructing a three-stage impersonation chain designed to build trust progressively and bypass standard approval controls.

Technically, the attacker showed awareness of email authentication mechanisms: the use of a third-party SMTP relay, homoglyph domain substitution, a separate Gmail Reply-To address, and an unregistered desktop mail client all reflect deliberate choices to reduce detection risk while operating without DKIM signatures or SPF authorisation. The absence of malicious URLs or confirmed malware is consistent with BEC tradecraft — the payload was financial, not technical.

The attack was disrupted by manual IT Security review rather than automated controls. No DMARC enforcement, no payment verification workflow, and no external email warning banners were in place at the time of delivery. These gaps were the direct enablers of the attack reaching the victim's inbox and nearly succeeding.

All identified IOCs are documented in the table above and should be actioned immediately.

> ⚠️ **Analyst Safety Note**
> All analysis was conducted on the provided `.eml` files in a sandboxed, offline environment. No domains, IPs, or file hashes were interacted with in a live environment. All IOCs should be treated as active threats until confirmed otherwise by the security team.

---

📄 **Full analysis findings → [README.md](README.md)**
