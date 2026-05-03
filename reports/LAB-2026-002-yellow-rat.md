# Lab Report LAB-2026-002
## Yellow RAT Lab Investigation
## Blue Team Lab | CyberDefenders

---

### Lab Information

| Field | Details |
|-------|----------|
| **Lab ID** | LAB-2026-002 |
| **Lab Title** | Yellow RAT - Remote Access Trojan Investigation |
| **Platform** | CyberDefenders |
| **Track** | Blue Team / DFIR / SOC |
| **Analyst** | Badi Alosaimi |
| **Date of Analysis** | May 4, 2026 |
| **Status** | Completed |

---

## Executive Summary

أتممت مختبر **Yellow RAT** من منصة **CyberDefenders**، وهو مختبر عملي ركّز على تحليل تهديد مرتبط بـ **Remote Access Trojan (RAT)** وفهم سلوك البرمجية الخبيثة داخل البيئة المستهدفة.

خلال هذا المختبر عملت على:
- **تتبع السلوك المشبوه** وتحليل الأنشطة المرتبطة بالتهديد
- **استخراج المؤشرات الفنية** (Indicators of Compromise - IOCs)
- **ربط الأدلة** لفهم مسار الهجوم بشكل أوضح

In this hands-on lab, I investigated a threat scenario involving a **Remote Access Trojan (RAT)**, tracked suspicious behavior, extracted technical indicators, and correlated evidence to understand the attack path.

---

## Key Highlights

### أبرز ما طبّقته في المختبر:

🔍 **تحليل السلوك العدائي والأنشطة المشبوهة**  
تحديد السلوكيات غير الطبيعية والأنماط المرتبطة بـ RAT

🕵️ **تتبع مؤشرات الاختراق واستخراج الأدلة الفنية**  
تعريف IOCs (عناوين IP، المجالات، معرفات Hash، مفاتيح Registry)

🌐 **تحليل الاتصالات والأنشطة المرتبطة بالبرمجية الخبيثة**  
فحص اتصالات Command & Control (C2) وتحليل الترافيك الشبكي

🛡️ **فهم آلية عمل Remote Access Trojan داخل البيئة**  
تحليل طرق الاستمرارية (Persistence)، الاتصال بـ C2، وتنفيذ الأوامر

📊 **تعزيز عقلية التحقيق في Blue Team و SOC**  
تطوير منهجية التحليل والاستجابة للحوادث

🔗 **تطوير مهارات التحليل وربط الأحداث**  
الوصول للصورة الكاملة للهجوم عبر Event Correlation

---

## Threat Analysis Overview

### What is a Remote Access Trojan (RAT)?

A **Remote Access Trojan (RAT)** is a type of malware that allows an attacker to:
- Gain unauthorized remote access to a victim's system
- Execute commands remotely
- Exfiltrate sensitive data
- Maintain persistent access
- Monitor user activity
- Deploy additional payloads

### Attack Lifecycle

1. **Initial Compromise**
   - Malware delivered via phishing, malicious attachments, or drive-by downloads
   - Execution of malicious payload on victim system

2. **Establishing Persistence**
   - Registry modifications for auto-start
   - Scheduled tasks creation
   - Service installation

3. **Command & Control (C2) Communication**
   - Beacon to attacker-controlled server
   - Establish encrypted communication channel
   - Receive remote commands

4. **Post-Exploitation Activities**
   - Credential harvesting
   - Lateral movement
   - Data exfiltration
   - Additional malware deployment

---

## Technical Investigation

### Indicators of Compromise (IOCs) Analyzed

#### 💻 Process Analysis
- Suspicious process names and paths
- Parent-child process relationships
- Command-line arguments examination
- Memory analysis for injected code

#### 🌐 Network Traffic Analysis
- Outbound connections to suspicious IPs/domains
- Unusual protocols or ports
- Beaconing patterns (regular C2 communication)
- Data exfiltration indicators

#### 🗄️ File System Forensics
- File modifications and timestamps
- Hash values (MD5, SHA256)
- File locations and naming patterns
- Dropped files and artifacts

#### 📊 Registry Analysis
- Auto-run registry keys
- Persistence mechanisms
- Configuration storage
- System modifications

---

## Key Malware Behaviors Identified

### Persistence Mechanisms
- **Registry Run Keys**: Ensuring malware executes on system startup
- **Scheduled Tasks**: Automated execution at specific intervals
- **Service Creation**: Running as a Windows service

### Command & Control (C2) Infrastructure
- **Domain Analysis**: Identifying malicious domains
- **IP Addresses**: Tracking C2 server locations
- **Communication Protocols**: TCP, HTTP, or custom protocols
- **Beacon Intervals**: Regular check-ins to C2 server

### Data Exfiltration Techniques
- **File Upload**: Sending stolen data to C2 server
- **Screenshot Capture**: Visual reconnaissance
- **Keylogging**: Credential harvesting
- **Clipboard Monitoring**: Capturing sensitive information

---

## Analysis Tools & Techniques

### Tools Applied:

✅ **Process Explorer / Process Hacker**  
Investigating running processes and their behavior

✅ **Wireshark / NetworkMiner**  
Network traffic analysis and C2 detection

✅ **Registry Editor / RegRipper**  
Examining persistence mechanisms

✅ **Sysinternals Suite**  
Process Monitor, Autoruns, TCPView for behavioral analysis

✅ **VirusTotal / Hybrid Analysis**  
Malware identification and threat intelligence

---

## Lessons Learned

### الخلاصة:

هـذا النوع من المختبرات يطوّر بشكل كبير:

👁️ **القدرة على التحليل**  
Identifying malicious patterns in process behavior, network traffic, and system artifacts

🔍 **التحقيق الجنائي الرقمي**  
Extracting forensic evidence and building attack timelines

🔗 **ربط الأدلة**  
Correlating events from multiple sources (logs, network, files, registry)

🛡️ **فهم سلوك المهاجمين**  
Understanding attacker TTPs (Tactics, Techniques, and Procedures)

📊 **بناء عقلية Blue Team قوية**  
Developing a defensive mindset for SOC operations

كل مختبر عملي مثل هذا يضيف فهمًا أعمق لكيفية عمل المهاجمين وكيف يمكن للمدافعين تحديد وتحليل التهديدات بفعالية.

---

## Defense Recommendations

### Preventive Measures:

1. **Endpoint Protection**
   - Deploy EDR (Endpoint Detection and Response) solutions
   - Keep antivirus signatures updated
   - Enable application whitelisting

2. **Network Monitoring**
   - Monitor for unusual outbound connections
   - Implement IDS/IPS systems
   - Analyze network traffic for C2 patterns

3. **User Awareness**
   - Security awareness training
   - Phishing simulation exercises
   - Reporting suspicious emails

4. **System Hardening**
   - Disable unnecessary services
   - Restrict administrative privileges
   - Regular patching and updates

5. **Incident Response Readiness**
   - Documented IR procedures
   - Regular tabletop exercises
   - Forensic tool availability

---

## Skills Applied

- Malware Analysis
- Threat Investigation
- Blue Team Defense
- DFIR Methodologies
- SOC Analysis
- Behavioral Analysis
- Network Traffic Analysis
- Registry Forensics
- Process Analysis
- Incident Timeline Reconstruction
- Indicator of Compromise (IOC) Extraction

---

## Lab Classification

**Classification**: Training Exercise  
**Handling**: Public (Portfolio/Educational Use)  
**Distribution**: Unlimited

---

**Lab Completed By**:  
Badi Alosaimi  
SOC Analyst | Blue Team & Incident Response  
GitHub: [@bedochi1996](https://github.com/bedochi1996)  
LinkedIn: [/in/badi-alosaimi/](https://www.linkedin.com/in/badi-alosaimi/)

**Date**: May 4, 2026  
**Version**: 1.0
