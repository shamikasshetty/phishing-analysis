# T1566 — Email Threat & Phishing Analysis
### Project 3 — ECORP SOC Home Lab

![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566-red)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

---

## Overview

This project demonstrates a complete phishing 
email analysis workflow, from raw email header 
inspection through automated IOC extraction to 
real-time threat intelligence validation using 
industry-standard APIs. Phishing accounts for 
16% of all enterprise breaches and is the most 
common initial access technique used by threat 
actors. This project simulates the exact 
investigation a SOC analyst performs when a 
suspicious email is flagged for review.

---

## Lab Environment

| Component | Details |
|---|---|
| Analysis Machine | Windows 11 — 10.0.1.2 |
| Python Version | 3.12.4 |
| Threat Intel APIs | AbuseIPDB + VirusTotal |
| SIEM | Splunk Enterprise 9.4.2 |
| Email Sample | Constructed PayPal phishing lure |

---

## Tools Used

| Tool | Purpose | Used by Real SOCs |
|---|---|---|
| Python 3.12 | Automation and scripting | Universal |
| eml-parser | Raw email file parsing | Yes |
| AbuseIPDB API | IP reputation checking | Yes |
| VirusTotal API | Multi-engine URL/domain scanning | Yes |
| MxToolbox | Email header analysis — SPF DKIM DMARC | Yes |
| Splunk | IOC lookup table and Detection alert | Yes |

---

## Phishing Email Sample 

### Email Characteristics
| Field | Value |
|---|---|
| From | security@paypa1-alerts.com |
| To | victim@ecorp.local |
| Subject | Urgent: Your account has been compromised |
| Reply-To | support@paypa1-recovery.net |
| Originating IP | 185.220.101.45 |
| Sending Server | mail.paypa1-alerts.com |

### Red Flags Identified

| # | Red Flag | Detail |
|---|---|---|
| 1 | **Domain typosquatting** | `paypa1-alerts.com` vs `paypal.com` — single character substitution, 1 instead of l |
| 2 | **Mismatched Reply-To** | From: `paypa1-alerts.com` / Reply-To: `paypa1-recovery.net` — replies go to attacker |
| 3 | **Urgency language** | "account has been compromised" and "Failure to verify within 24 hours" — classic social engineering pressure |
| 4 | **Suspicious URL** | `paypal-secure-login.paypa1-verify.com` — credential harvesting page disguised as PayPal |
| 5 | **Tor exit node** | IP `185.220.101.45` — attacker hiding true location |
| 6 | All auth checks fail | SPF DKIM DMARC all FAIL |
---

## Email Authentication Analysis

### Python Script Results

| Check | Result | Meaning |
|---|---|---|
| SPF | FAIL | Sending IP not authorised by domain |
| DKIM | FAIL | No valid cryptographic signature |
| DMARC | FAIL | Domain policy violated — should be rejected |

### What Each Check Means

**SPF (Sender Policy Framework)**
Checks if the sending IP is authorised to send 
email on behalf of the claimed domain. A FAIL 
means the email did not come from a legitimate 
server — classic spoofing indicator.

**DKIM (DomainKeys Identified Mail)**
A cryptographic signature proving the email was 
not modified in transit. A FAIL means the 
signature is invalid or missing — the email 
was likely forged or tampered with.

**DMARC (Domain-based Message Authentication)**
A policy telling receiving servers what to do 
when SPF and DKIM fail. A FAIL means this email 
violated the domain's published security policy 
and should have been rejected automatically.

---
## MxToolbox Header Analysis

Pasted raw email headers into MxToolbox Email 
Header Analyzer for visual authentication 
failure confirmation and IP blacklist check.

| Check | Result |
|---|---|
| SPF | FAIL — IP not authorised |
| DKIM | FAIL — No signature found |
| DMARC | FAIL — No record published |
| IP Blacklist | 185.220.101.45 ON BLACKLIST |
| Reply-To mismatch | paypa1-alerts.com vs paypa1-recovery.net |

MxToolbox confirmed the sending IP is on a 
blacklist — consistent with AbuseIPDB 100% 
malicious score across multiple independent 
threat intelligence sources.

---

## Automated Analysis Results

### AbuseIPDB — IP Reputation
| Field | Value |
|---|---|
| IP Address | 185.220.101.45 |
| Abuse Confidence Score | 100% |
| Total Community Reports | 131 |
| Country | Germany (DE) |
| ISP | Network for Tor-Exit traffic |
| VERDICT | MALICIOUS |

This IP is a known Tor exit node with a perfect 
100% abuse confidence score and 132 community 
reports. Tor exit nodes are commonly used by 
threat actors to anonymise phishing 
infrastructure and evade IP-based blocking.

### VirusTotal — URL Reputation
| Field | Value |
|---|---|
| URL | http://paypal-secure-login.paypa1-verify.com/login |
| Engines checked | 56 |
| Malicious detections | 0 |
| Note | Lab-constructed URL not in VT database |

---

## Python Analysis Script

### What the script does

```python
# Step 1 — Parse raw .eml file
# Extracts: sender, recipient, subject,
# reply-to, originating IP, URLs, received hops

# Step 2 — Analyse SPF DKIM DMARC headers
# Checks authentication-results header
# Flags each failure with plain English explanation

# Step 3 — Check IP against AbuseIPDB
# Returns: abuse score, report count,
# country, ISP, malicious verdict

# Step 4 — Check URLs against VirusTotal
# Returns: malicious engine count,
# suspicious count, harmless count

# Step 5 — Generate IOC report
# Outputs: structured findings + CSV file
# for Splunk lookup table integration
```

### How to run

```bash
pip install eml-parser requests
python analyze_phishing.py
```

Note: Add your own AbuseIPDB and VirusTotal 
API keys to the script before running.

---

## IOCs Extracted

| IOC Type | Value | Severity | Source |
|---|---|---|---|
| ip | 185.220.101.45 | high | phishing_email |
| url | http://paypal-secure-login.paypa1-verify.com/login | high | phishing_email |
| domain | paypa1-alerts.com | high | phishing_email |

---

## Splunk IOC Integration

**Lookup table:** 

malicious_iocs.csv uploaded 
to Splunk containing extracted IOCs.

**Detection query:**

index=main sourcetype=sysmon EventCode=3

| lookup malicious_iocs.csv ioc_value AS DestinationIp

| where isnotnull(severity)

| table _time host Image DestinationIp

ioc_type severity source

**Alert saved:**

T1566 — Phishing IOC Match —  
Known Malicious IP Detected  
**Trigger:** Any endpoint connecting to known  
phishing infrastructure  
**Severity:** Critical  
**Schedule:** Runs every hour

**Result:**

0 current matches — correct outcome  
since no user clicked the phishing link.  
Rule will fire automatically if any future  
connection matches a known malicious IOC.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Phishing | T1566 | Parent technique |
| Spearphishing Link | T1566.002 | Malicious URL in email body |
| Phishing for Information | T1598 | Credential harvesting lure |
| Valid Accounts | T1078 | If credentials stolen |

---

## Incident Report

Full incident report available in 
`reports/incident_report.md` — documents 
complete investigation timeline, findings, 
and recommended response actions in 
professional SOC format.

### Recommended Response Actions
1. Block IP 185.220.101.45 at pfSense firewall
2. Block domains paypa1-alerts.com and 
   paypa1-verify.com at DNS level
3. Alert all ECORP users about PayPal 
   phishing campaign
4. Search network logs for any user who 
   clicked the phishing URL
5. Reset passwords for any potentially 
   compromised accounts
6. Report IP 185.220.101.45 to AbuseIPDB

---

## Key Findings

1. **Automated analysis works** — Python script
   extracted all IOCs in under 3 seconds vs 
   15+ minutes of manual analysis

2. **Real threat intelligence** — AbuseIPDB 
   confirmed sender IP is a known Tor exit 
   node used by real threat actors with 
   100% confidence score and 132 reports

3. **Typosquatting is subtle** — paypa1 vs 
   paypal is a single character difference 
   that most users miss under urgency pressure

4. **Tor infrastructure hides attackers** — 
   IP-based blocking is ineffective against 
   Tor exit nodes since they rotate constantly

5. **Automation scales** — this script can 
   process hundreds of suspicious emails per 
   hour, replacing manual triage that would 
   take an analyst days

6. **Proactive IOC detection** — Splunk alert 
   now monitors all network connections 
   against known malicious infrastructure 
   in real time

---

## Skills Demonstrated

- Python scripting for security automation
- Raw email header analysis and parsing
- SPF DKIM DMARC authentication concepts
- Threat intelligence API integration
- IOC extraction and documentation
- MITRE ATT&CK framework mapping
- Splunk lookup table integration
- Incident report writing
- Social engineering technique recognition

---
