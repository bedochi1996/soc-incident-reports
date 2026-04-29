# IR-2026-002 | Phishing Email Campaign — Incident Report

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-002 |
| **Date Detected** | 2026-04-22 |
| **Severity** | Critical |
| **Status** | Resolved |
| **Analyst** | Badi Alosaimi |
| **Category** | Phishing / Initial Access |
| **MITRE ATT&CK** | T1566.001 — Phishing: Spearphishing Attachment |

---

## 1. Executive Summary

On April 22, 2026, a targeted spearphishing campaign was detected targeting finance department employees. Three users received a spoofed email impersonating the CFO with a malicious Excel attachment (`Q1-Finance-Report.xlsx`). The attachment contained an obfuscated macro that attempted to download and execute a remote payload. Email gateway and EDR blocked the payload on two endpoints; one endpoint was successfully compromised before containment.

---

## 2. Alert Details

| Field | Value |
|---|---|
| **Alert Source** | Email Gateway + EDR |
| **Sender (Spoofed)** | cfo@company-corp.com (spoofed) |
| **Legitimate Domain** | cfo@company.com |
| **Recipients** | finance01, finance02, finance03 |
| **Subject** | “Q1 Financial Report — Urgent Review Required” |
| **Attachment** | Q1-Finance-Report.xlsx (malicious macro) |
| **C2 Server** | hxxp://185.220.101.47/payload.exe |
| **Time Detected** | 2026-04-22 09:14:00 UTC |
| **Compromised Host** | WKSTN-FIN-003 (finance03) |

---

## 3. Timeline Reconstruction

| Time (UTC) | Event |
|---|---|
| 09:12:00 | Phishing emails sent to 3 finance accounts |
| 09:13:45 | Email gateway flags email — delayed delivery |
| 09:14:00 | finance01 opens email, does NOT open attachment |
| 09:16:22 | finance02 opens attachment — EDR blocks macro execution |
| 09:18:55 | finance03 opens attachment — macro executes (EDR bypassed) |
| 09:19:10 | Outbound connection to 185.220.101.47 detected |
| 09:19:45 | Payload download partially completed (blocked at proxy) |
| 09:21:00 | SOC SIEM alert triggered — analyst paged |
| 09:28:00 | Analyst isolates WKSTN-FIN-003 from network |
| 09:35:00 | Email quarantined from all inboxes |
| 09:50:00 | Forensic image of WKSTN-FIN-003 initiated |
| 11:30:00 | Full investigation completed |

---

## 4. IOC Extraction

| IOC Type | Value | Confidence |
|---|---|---|
| IP Address | 185.220.101.47 | High |
| Domain | company-corp.com | High |
| File Hash (MD5) | a3f2c8b19e4d7a61f5e0c2b4d8f9a012 | High |
| File Name | Q1-Finance-Report.xlsx | High |
| URL | hxxp://185.220.101.47/payload.exe | High |
| Sender Email | cfo@company-corp.com | High |

### Threat Intel Lookup
- **185.220.101.47** — Known Tor exit node, listed on multiple threat intel feeds
- **company-corp.com** — Registered 3 days before attack (2026-04-19), typosquatting
- File hash matches known **Emotet dropper** variant

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 | Malicious Excel with VBA macro |
| Execution | User Execution: Malicious File | T1204.002 | User opened attachment |
| Command & Control | Application Layer Protocol | T1071.001 | HTTP C2 communication |
| Defense Evasion | Obfuscated Files | T1027 | Obfuscated VBA macro code |
| Collection | Email Collection | T1114 | Targeting finance credentials |

---

## 6. Root Cause Analysis

- **Primary Cause:** User opened macro-enabled attachment from spoofed executive email
- **Contributing Factor 1:** Domain typosquatting not caught by email gateway SPF/DMARC
- **Contributing Factor 2:** EDR policy allowed macro execution on one legacy endpoint
- **Contributing Factor 3:** Finance team lacked recent phishing awareness training

---

## 7. Containment & Remediation

### Immediate Actions
- [x] Isolated WKSTN-FIN-003 from network
- [x] Quarantined phishing email from all mailboxes
- [x] Blocked C2 IP 185.220.101.47 at perimeter firewall
- [x] Blocked company-corp.com domain at DNS level
- [x] Reset credentials for finance03 user

### Long-Term Remediation
- [x] Enforced DMARC strict policy on all outbound domains
- [x] Enabled EDR macro blocking on all endpoints (including legacy)
- [ ] Conduct mandatory phishing awareness training for finance team
- [ ] Implement email sandboxing for attachment analysis
- [ ] Deploy lookalike domain monitoring

---

## 8. Lessons Learned

1. DMARC/SPF policies must be enforced in reject mode, not monitor mode
2. Macro execution should be disabled by default on all Windows endpoints
3. Finance and HR teams are high-value targets — require targeted security training
4. Domain registration monitoring can catch typosquatting before attacks launch

---

## 9. References

- MITRE ATT&CK T1566.001: https://attack.mitre.org/techniques/T1566/001/
- Emotet Threat Profile: https://attack.mitre.org/software/S0367/
- NIST SP 800-61 Incident Handling Guide
- NCA ECC Control: ECC-2-6 (Email Security)

---

*Report prepared by: Badi Alosaimi | SOC Analyst | April 2026*
*Classification: Portfolio / Training — Simulated Incident*
