# SOC Incident Report Template

> **Usage:** Copy this template for each new SOC investigation.
> **Classification:** [TLP:WHITE / TLP:GREEN / TLP:AMBER / TLP:RED]

---

## Report Header

| Field | Value |
|---|---|
| **Case ID** | SOC-YYYY-NNN |
| **Report Title** | [Short description of incident] |
| **Analyst** | [Your Name] |
| **Date Created** | YYYY-MM-DD |
| **Date Closed** | YYYY-MM-DD |
| **Severity** | Critical / High / Medium / Low |
| **Status** | Open / In Progress / Closed |
| **Category** | Malware / Phishing / Brute Force / C2 / Insider / DDoS / Other |
| **Affected System(s)** | [hostname / IP] |
| **Affected User(s)** | [username / department] |

---

## 1. Executive Summary

> Write 3-5 sentences summarizing the incident for non-technical audience.
> Include: what happened, when, how it was detected, and what was done.

[SUMMARY HERE]

---

## 2. Alert Overview

| Field | Value |
|---|---|
| **Alert Name** | [SIEM rule or alert name] |
| **Alert Source** | Splunk / Sentinel / QRadar / Other |
| **Alert ID** | [Alert ID if applicable] |
| **Detection Time** | YYYY-MM-DD HH:MM UTC |
| **Rule Triggered** | [Detection rule name] |
| **Initial Triage** | True Positive / False Positive / Undetermined |

---

## 3. Evidence Reviewed

| Source | Description | Timeframe |
|---|---|---|
| SIEM Logs | [Log type, index] | [Start – End] |
| Windows Event Logs | [Event IDs reviewed] | [Start – End] |
| Network Logs | [Firewall / Proxy logs] | [Start – End] |
| Endpoint Logs | [EDR / AV alerts] | [Start – End] |
| Email Headers | [If phishing involved] | [Date] |
| PCAP | [Network capture analyzed] | [Start – End] |

---

## 4. Investigation Timeline

| Timestamp (UTC) | Event | Source |
|---|---|---|
| YYYY-MM-DD HH:MM | [First indicator observed] | [Log source] |
| YYYY-MM-DD HH:MM | [Next event in chain] | [Log source] |
| YYYY-MM-DD HH:MM | [Analyst notified] | SIEM Alert |
| YYYY-MM-DD HH:MM | [Triage completed] | Analyst |
| YYYY-MM-DD HH:MM | [Containment action taken] | SOC Team |
| YYYY-MM-DD HH:MM | [Incident closed] | Analyst |

---

## 5. Indicators of Compromise (IOCs)

| IOC | Type | Value | Notes |
|---|---|---|---|
| [Name] | IP Address | [x.x.x.x] | [AbuseIPDB score, location] |
| [Name] | Domain | [evil[.]com] | [Registration date, reputation] |
| [Name] | URL | hxxps://evil[.]com/path | [Sandbox result] |
| [Name] | File Hash (MD5) | [hash] | [VirusTotal detections] |
| [Name] | File Hash (SHA256) | [hash] | [VirusTotal detections] |
| [Name] | Email Address | [email@domain[.]com] | [Phishing sender] |
| [Name] | User-Agent | [string] | [Malware beacon pattern] |

> **Note:** All IOCs are defanged. Replace [.] with . before using in tools.

---

## 6. MITRE ATT&CK Mapping

| Phase | Tactic | Technique | ID | Evidence |
|---|---|---|---|---|
| 1 | [Tactic Name] | [Technique Name] | [T####.###] | [Observable evidence] |
| 2 | [Tactic Name] | [Technique Name] | [T####.###] | [Observable evidence] |
| 3 | [Tactic Name] | [Technique Name] | [T####.###] | [Observable evidence] |

---

## 7. Root Cause Analysis

> What was the root cause that allowed this incident to occur?

**Root Cause:**
[Describe the vulnerability, misconfiguration, or gap that enabled the attack]

**Contributing Factors:**
- [Factor 1: e.g., Weak password policy]
- [Factor 2: e.g., No MFA on remote access]
- [Factor 3: e.g., Alert threshold too high]

---

## 8. Impact Assessment

| Area | Impact | Details |
|---|---|---|
| Confidentiality | High / Medium / Low / None | [Data accessed or exfiltrated?] |
| Integrity | High / Medium / Low / None | [Data modified or deleted?] |
| Availability | High / Medium / Low / None | [Service disruption?] |
| Financial | Estimated / Unknown | [Business impact] |
| Reputational | High / Medium / Low / None | [Customer or partner impact] |

---

## 9. Response Actions Taken

| Action | Status | Time | Performed By |
|---|---|---|---|
| [ ] Isolated affected endpoint | Done/Pending | HH:MM | [Analyst] |
| [ ] Blocked malicious IP at firewall | Done/Pending | HH:MM | [Analyst] |
| [ ] Blocked malicious domain at proxy | Done/Pending | HH:MM | [Analyst] |
| [ ] Locked compromised user account | Done/Pending | HH:MM | [Analyst] |
| [ ] Forced password reset | Done/Pending | HH:MM | [Analyst] |
| [ ] Notified affected user | Done/Pending | HH:MM | [Analyst] |
| [ ] Escalated to Tier 2 / IR team | Done/Pending | HH:MM | [Analyst] |
| [ ] Evidence preserved for forensics | Done/Pending | HH:MM | [Analyst] |
| [ ] SIEM rule created for detection | Done/Pending | HH:MM | [Analyst] |

---

## 10. Recommendations

1. **[Short-term]** [Immediate fix — e.g., Enable MFA for all remote access accounts]
2. **[Short-term]** [Immediate fix — e.g., Implement account lockout after 5 failed attempts]
3. **[Medium-term]** [e.g., Deploy EDR solution on all endpoints]
4. **[Long-term]** [e.g., Conduct quarterly phishing awareness training]
5. **[Detection]** [e.g., Tune SIEM rule to reduce false positives for this pattern]

---

## Appendix

### Raw Log Samples (Sanitized)
```
[Include relevant sanitized log entries that support the investigation]
[Remove all PII, real IPs, and sensitive data]
```

### Additional Notes
[Any other relevant information for future reference]

---

> **Disclaimer:** This report is based on a simulated/lab environment.
> No real production data, credentials, or personal information is included.
