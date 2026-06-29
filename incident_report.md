\# Incident Report — Phishing Email Analysis

\*\*Incident ID:\*\* INC-2026-001  

\*\*Date:\*\* June 29, 2026  

\*\*Analyst:\*\* Shamika Shetty  

\*\*Severity:\*\* High  

\*\*Status:\*\* Closed  



\---



\## Executive Summary



A phishing email impersonating PayPal was 

identified and analysed. The email used domain 

typosquatting, failed all email authentication 

checks, and originated from a known malicious 

Tor exit node with a 100% abuse confidence 

score. No users clicked the malicious link. 

IOCs have been added to Splunk for ongoing 

detection.



\---



\## Incident Timeline



| Time | Event |

|---|---|

| 10:23 AM | Phishing email received by victim@ecorp.local |

| 10:25 AM | Email flagged for analysis |

| 10:30 AM | Header analysis completed — SPF DKIM DMARC all FAIL |

| 10:35 AM | Sender IP confirmed malicious via AbuseIPDB |

| 10:40 AM | IOCs extracted and uploaded to Splunk |

| 10:45 AM | Detection rule created and activated |

| 10:50 AM | Incident closed — no user compromise detected |



\---



\## Attack Details



| Field | Value |

|---|---|

| Attack Type | Credential Harvesting Phishing |

| MITRE Technique | T1566.002 — Spearphishing Link |

| Sender | security@paypa1-alerts.com |

| Subject | Urgent: Your account has been compromised |

| Reply-To | support@paypa1-recovery.net |

| Sending IP | 185.220.101.45 |

| Malicious URL | http://paypal-secure-login.paypa1-verify.com/login |



\---



\## Email Authentication Analysis



| Check | Result | Meaning |

|---|---|---|

| SPF | FAIL | Sending IP not authorised by domain |

| DKIM | FAIL | No valid cryptographic signature |

| DMARC | FAIL | Domain policy violated |



All three authentication checks failed confirming 

this email is spoofed and did not originate from 

a legitimate PayPal server.



\---



\## Threat Intelligence



\### AbuseIPDB — 185.220.101.45

| Field | Value |

|---|---|

| Abuse Confidence Score | 100% |

| Total Community Reports | 131 |

| Country | Germany (DE) |

| ISP | Network for Tor-Exit traffic |

| Verdict | MALICIOUS |



The sending IP is a confirmed Tor exit node used 

by threat actors to anonymise phishing 

infrastructure. The 100% confidence score across 

131 independent reports confirms this is known 

malicious infrastructure.



\### VirusTotal — URL Analysis

| Field | Value |

|---|---|

| URL | paypal-secure-login.paypa1-verify.com/login |

| Engines checked | 56 |

| Malicious | 0 |

| Note | Lab-constructed URL — not in VT database |



\---



\## IOCs Extracted



| IOC Type | Value | Severity |

|---|---|---|

| IP | 185.220.101.45 | High |

| Domain | paypa1-alerts.com | High |

| Domain | paypa1-verify.com | High |

| URL | http://paypal-secure-login.paypa1-verify.com/login | High |



\---



\## Red Flags Identified



| # | Red Flag | Detail |

|---|---|---|

| 1 | Domain typosquatting | paypa1 vs paypal — 1 instead of l |

| 2 | Mismatched Reply-To | Different domain from sender |

| 3 | Urgency language | 24 hour account suspension threat |

| 4 | Suspicious URL | Fake PayPal login page |

| 5 | Tor exit node | Attacker hiding true location |

| 6 | SPF DKIM DMARC all fail | No legitimate authentication |



\---



\## Detection Actions Taken



1\. IOCs uploaded to Splunk lookup table

2\. SPL detection rule created and saved as alert

3\. Alert fires if any endpoint connects to 

&#x20;  known malicious IP or domain

4\. MITRE ATT\&CK T1566 mapped and documented



\## Splunk Detection Query

index=main sourcetype=sysmon EventCode=3



| lookup malicious\_iocs.csv ioc\_value AS DestinationIp



| where isnotnull(severity)



| table \_time host Image DestinationIp



ioc\_type severity source

---



\## Recommended Response Actions



1\. Block IP 185.220.101.45 at pfSense firewall

2\. Block domains paypa1-alerts.com and 

&#x20;  paypa1-verify.com at DNS level

3\. Alert all ECORP users about PayPal 

&#x20;  phishing campaign

4\. Search Sysmon EventCode 3 logs for any 

&#x20;  connection to phishing domains

5\. Reset passwords for any potentially 

&#x20;  compromised accounts

6\. Report IP 185.220.101.45 to AbuseIPDB



\---



\## Outcome



No users clicked the malicious link. No 

credentials were compromised. IOCs have been 

added to Splunk for ongoing monitoring. Any 

future connection to known phishing 

infrastructure will trigger an immediate alert.



\---



\## MITRE ATT\&CK Mapping



| Technique | ID | Description |

|---|---|---|

| Phishing | T1566 | Parent technique |

| Spearphishing Link | T1566.002 | Malicious URL in email |

| Phishing for Information | T1598 | Credential harvesting |

| Valid Accounts | T1078 | If credentials stolen |

