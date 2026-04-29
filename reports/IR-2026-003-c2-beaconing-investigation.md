# SOC Incident Report: C2 Beaconing Investigation

**Case ID**: IR-2026-003  
**Incident Date**: April 27, 2026  
**Report Date**: April 29, 2026  
**Analyst**: Badi Alosaimi  
**Severity**: HIGH  
**Status**: Contained & Remediated  

---

## Executive Summary

On April 27, 2026, the SOC detected suspicious beaconing activity from an internal workstation (WS-FINANCE-08) communicating with an unknown external IP address. Investigation revealed a compromised system establishing Command and Control (C2) communication with a suspected malicious server. The infected system was isolated, malware removed, and the threat actor's infrastructure blocked. No data exfiltration was detected.

---

## Alert Overview

**Alert ID**: SIEM-2026-04271845  
**Alert Name**: Suspicious Periodic Outbound Connections  
**Detection Time**: 2026-04-27 18:45:23 UTC  
**Source**: Firewall Logs + EDR Behavioral Analysis  

### Initial Alert Details
- **Source IP**: 10.50.12.88 (WS-FINANCE-08)  
- **Destination IP**: 185.220.101.47 (Netherlands)  
- **Protocol**: HTTPS (TCP/443)  
- **Beacon Interval**: Every 60 seconds  
- **Duration**: 2 hours 15 minutes  
- **User**: fmahdi (Finance Department)  

---

## Scope

### Affected Systems
- **Primary**: WS-FINANCE-08 (10.50.12.88)  
- **User**: fmahdi  
- **Department**: Finance  
- **OS**: Windows 11 Pro  

### Timeline
- **2026-04-27 16:30**: User opened suspicious email attachment  
- **2026-04-27 16:45**: Initial malware execution detected  
- **2026-04-27 18:45**: C2 beaconing activity triggered SIEM alert  
- **2026-04-27 19:00**: Incident escalated to SOC analyst  
- **2026-04-27 19:15**: System isolated from network  
- **2026-04-27 20:30**: Malware removed, forensic image captured  
- **2026-04-27 22:00**: System reimaged and returned to service  

---

## Evidence Reviewed

### Network Traffic Analysis
```
# Firewall Logs
Timestamp: 2026-04-27 18:45:23
Src: 10.50.12.88:49217 → Dst: 185.220.101.47:443
Bytes Out: 328 | Bytes In: 512
Connection Duration: 2.3 seconds

# Pattern: Consistent 60-second intervals
18:45:23, 18:46:23, 18:47:23, 18:48:23...
```

### EDR Telemetry
```powershell
# Suspicious Process Tree
outlook.exe (PID: 4512)
 └─ Invoice_Q1.pdf.exe (PID: 7823)
    └─ powershell.exe -enc [base64] (PID: 8105)
       └─ svchost.exe (PID: 8420) [MALICIOUS]
```

### File Analysis
- **Malicious File**: `C:\Users\fmahdi\AppData\Local\Temp\svchost.exe`  
- **MD5**: 8f14e45fceea167a5a36dedd4bea2543  
- **SHA256**: 7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730  
- **File Type**: PE32 executable (trojan/loader)  
- **VirusTotal**: 45/70 vendors flagged as malicious  

---

## Indicators of Compromise (IOCs)

### Network IOCs
| Type | Indicator | Description |
|------|-----------|-------------|
| IP | 185.220.101.47 | C2 Server (Netherlands) |
| Domain | update-cdn.top | C2 Domain |
| URL | https://185.220.101.47/api/beacon | Beaconing Endpoint |

### File IOCs
| Type | Value | Description |
|------|-------|-------------|
| MD5 | 8f14e45fceea167a5a36dedd4bea2543 | Malicious Payload |
| SHA256 | 7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730 | Main Dropper |
| Filename | Invoice_Q1.pdf.exe | Initial Delivery |
| Path | C:\\Users\\fmahdi\\AppData\\Local\\Temp\\ | Malware Location |

### Registry Persistence
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  "SystemUpdate" = "C:\Users\fmahdi\AppData\Local\Temp\svchost.exe"
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **Initial Access** | T1566.001 - Phishing: Spearphishing Attachment | Malicious email attachment |
| **Execution** | T1059.001 - PowerShell | Encoded PowerShell execution |
| **Persistence** | T1547.001 - Registry Run Keys | Autostart via Run key |
| **Command and Control** | T1071.001 - Web Protocols | HTTPS C2 communication |
| **Command and Control** | T1573.002 - Encrypted Channel | TLS-encrypted beaconing |

---

## Investigation Timeline

### Phase 1: Detection (18:45 - 19:00)
1. SIEM correlation rule triggered on periodic HTTPS connections
2. Analyst reviewed firewall logs confirming 60-second intervals
3. Cross-referenced with EDR for process context
4. Identified suspicious process tree from email attachment

### Phase 2: Containment (19:00 - 19:30)
1. Isolated workstation from network via VLAN change
2. Disabled user account (fmahdi) temporarily
3. Blocked C2 IP at perimeter firewall
4. Initiated forensic snapshot via EDR

### Phase 3: Eradication (19:30 - 20:30)
1. Terminated malicious processes
2. Removed malware files from disk
3. Cleaned registry persistence mechanisms
4. Scanned system with updated antivirus

### Phase 4: Recovery (20:30 - 22:00)
1. Reimaged workstation with clean OS
2. Restored user data from backups
3. Reset user credentials
4. Reconnected to network with enhanced monitoring

---

## Root Cause Analysis

The infection originated from a spearphishing email sent to the Finance department. The email impersonated a vendor and contained a malicious attachment disguised as an invoice PDF. The user executed the file, which dropped a trojan establishing C2 communication.

**Contributing Factors:**
- User bypassed security warning to execute unknown attachment
- Email gateway did not flag the malicious attachment
- Real-time antivirus did not detect the payload initially
- No email security awareness training in past 6 months

---

## Impact Assessment

### Business Impact
- **Severity**: Medium
- **Affected Users**: 1 (fmahdi)
- **System Downtime**: 3.5 hours
- **Data Compromise**: None detected
- **Financial Loss**: Minimal (productivity loss only)

### Technical Impact
- Workstation compromise
- Unauthorized C2 communication
- Persistence mechanism established
- No lateral movement detected
- No data exfiltration confirmed

---

## Response Actions

### Immediate Actions Taken
✅ Isolated compromised system from network  
✅ Blocked C2 infrastructure at firewall  
✅ Terminated malicious processes  
✅ Removed malware and persistence  
✅ Reimaged affected system  
✅ Reset user credentials  
✅ Captured forensic evidence  

### Monitoring Enhancements
✅ Added C2 IOCs to threat intelligence feeds  
✅ Enhanced SIEM rule for beaconing detection  
✅ Deployed additional EDR behavioral rules  
✅ Increased monitoring of Finance department systems  

---

## Recommendations

### Short-term (0-30 days)
1. **Email Security Training**: Conduct mandatory phishing awareness training for Finance department
2. **Email Gateway Tuning**: Review and enhance email attachment filtering rules
3. **EDR Coverage**: Verify all Finance workstations have active EDR agents
4. **IOC Hunt**: Scan all systems for related IOCs to ensure no lateral spread

### Medium-term (30-90 days)
1. **Email Sandboxing**: Implement email attachment sandboxing solution
2. **Application Whitelisting**: Deploy AppLocker to restrict unauthorized executables
3. **Network Segmentation**: Isolate Finance systems on separate VLAN
4. **Regular Simulations**: Conduct quarterly phishing simulations

### Long-term (90+ days)
1. **Zero Trust Architecture**: Implement micro-segmentation for critical departments
2. **SOAR Integration**: Automate C2 beaconing detection and response
3. **Threat Intelligence**: Subscribe to commercial threat intelligence feeds
4. **User Behavior Analytics**: Deploy UEBA solution for anomaly detection

---

## Lessons Learned

### What Went Well
- SIEM detection rule effectively identified C2 beaconing pattern
- Response time from alert to containment was under 30 minutes
- EDR provided comprehensive visibility into attack chain
- No data exfiltration or lateral movement occurred

### Areas for Improvement
- Initial email attachment was not blocked by gateway
- User executed unknown file despite security warnings
- Antivirus did not detect malware until after execution
- Finance department lacked recent security awareness training

### Action Items
- [ ] Update email gateway rules (Owner: Email Admin, Due: May 5)
- [ ] Schedule Finance dept security training (Owner: Security Awareness, Due: May 10)
- [ ] Review AV detection capabilities (Owner: Endpoint Team, Due: May 15)
- [ ] Implement email sandboxing pilot (Owner: Security Architecture, Due: June 1)

---

## Compliance & Reporting

**NCA ECC Notification**: Not Required (No PII/sensitive data compromise)  
**Internal Stakeholders Notified**:  
- Finance Department Manager  
- IT Security Manager  
- CISO  

---

**Report Prepared By**: Badi Alosaimi, SOC Analyst  
**Date**: April 29, 2026  
**Classification**: Internal Use Only  
**Review Status**: Approved by Security Manager  

---

**Disclaimer**: This is a simulated incident report created for portfolio and training purposes. All data, IP addresses, and details are fictional and do not represent real security incidents or organizations.
