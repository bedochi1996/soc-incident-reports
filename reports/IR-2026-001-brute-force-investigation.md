# IR-2026-001 | Brute Force Login Attack — Incident Report

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-001 |
| **Date Detected** | 2026-04-15 |
| **Severity** | High |
| **Status** | Resolved |
| **Analyst** | Badi Alosaimi |
| **Category** | Credential Attack / Brute Force |
| **MITRE ATT&CK** | T1110.001 — Brute Force: Password Guessing |

---

## 1. Executive Summary

On April 15, 2026, a brute force attack was detected targeting the SSH service on an internal Linux server (192.168.10.45). The SIEM platform triggered an alert after detecting 847 failed authentication attempts originating from a single external IP within a 12-minute window. The attacker eventually succeeded in authenticating with a weak service account. Immediate containment actions were taken including IP blocking, session termination, and password reset.

---

## 2. Alert Details

| Field | Value |
|---|---|
| **Alert Name** | Multiple Failed SSH Logins — Threshold Exceeded |
| **SIEM Rule** | AUTH_FAIL_SSH_HIGH_FREQUENCY |
| **Source IP** | 45.142.212.100 |
| **Destination IP** | 192.168.10.45 |
| **Destination Port** | 22 (SSH) |
| **Time Window** | 2026-04-15 02:14:00 – 02:26:00 UTC |
| **Failed Attempts** | 847 |
| **Successful Login** | Yes — user: `svc_backup` at 02:26:14 UTC |

---

## 3. Timeline Reconstruction

| Time (UTC) | Event |
|---|---|
| 02:14:00 | First failed SSH login attempt from 45.142.212.100 |
| 02:14:00 – 02:26:00 | 847 failed login attempts (avg ~70/min) |
| 02:26:14 | Successful login with user `svc_backup` |
| 02:27:45 | SIEM alert triggered — analyst notified |
| 02:35:00 | Analyst confirmed malicious activity |
| 02:38:00 | Source IP blocked at perimeter firewall |
| 02:39:00 | Active SSH session terminated |
| 02:42:00 | `svc_backup` password reset & MFA enforced |
| 03:10:00 | Full forensic review completed |
| 03:30:00 | Incident closed — post-incident report initiated |

---

## 4. IOC Extraction

| IOC Type | Value | Confidence |
|---|---|---|
| IP Address | 45.142.212.100 | High |
| Username | svc_backup | Medium |
| Tool Signature | Hydra (User-Agent pattern) | Medium |
| Country | Netherlands (NL) | High |

### Threat Intel Lookup
- **45.142.212.100** — Listed on AbuseIPDB with 312 prior reports
- Associated with brute force campaigns targeting SSH and RDP
- Last reported: 2026-04-14

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 | Automated SSH login attempts |
| Initial Access | Valid Accounts | T1078 | Successfully authenticated with weak credentials |
| Defense Evasion | Off-hours timing | — | Attack at 02:14 UTC (non-business hours) |

---

## 6. Root Cause Analysis

- **Primary Cause:** Weak password on service account `svc_backup` (8-char, no complexity)
- **Contributing Factor 1:** SSH port 22 exposed directly to internet
- **Contributing Factor 2:** No account lockout policy configured for SSH
- **Contributing Factor 3:** Service account not enrolled in MFA

---

## 7. Containment & Remediation

### Immediate Actions
- [x] Blocked source IP 45.142.212.100 at perimeter firewall
- [x] Terminated active SSH session
- [x] Reset `svc_backup` password with strong 20-char random password
- [x] Disabled direct SSH for service account

### Long-Term Remediation
- [x] Enforced MFA for all SSH service accounts
- [x] Implemented account lockout after 5 failed attempts
- [ ] Move SSH to non-standard port or implement VPN-only access
- [ ] Rotate all service account credentials organization-wide
- [ ] Deploy fail2ban on all public-facing Linux servers

---

## 8. Lessons Learned

1. Service accounts must follow the same password policy as user accounts
2. SSH should never be exposed directly to the internet without IP allowlisting
3. SIEM alert threshold (500 attempts) was appropriate — response time needs improvement
4. Threat intel feeds should be integrated with automated IP blocking

---

## 9. References

- MITRE ATT&CK T1110.001: https://attack.mitre.org/techniques/T1110/001/
- AbuseIPDB Report: https://www.abuseipdb.com/check/45.142.212.100
- NIST SP 800-61 Incident Handling Guide
- NCA ECC Control: ECC-2-1 (Access Control)

---

*Report prepared by: Badi Alosaimi | SOC Analyst | April 2026*
*Classification: Portfolio / Training — Simulated Incident*
