# Lab Report LAB-2026-001
## PoisonedCredentials Lab Investigation
## Blue Team Lab | CyberDefenders

---

### Lab Information

| Field | Details |
|-------|----------|
| **Lab ID** | LAB-2026-001 |
| **Lab Title** | PoisonedCredentials - LLMNR/NBT-NS Poisoning Attack Investigation |
| **Platform** | CyberDefenders |
| **Track** | Blue Team / DFIR / SOC |
| **Analyst** | Badi Alosaimi |
| **Date of Analysis** | May 3, 2026 |
| **Status** | Completed |

---

## Executive Summary

أتممت مختبر **PoisonedCredentials** من منصة **CyberDefenders** ضمن مسار Blue Team / DFIR / SOC.

في هذا المختبر العملي، قمت بتحليل سيناريو هجوم يعتمد على **LLMNR / NBT-NS Poisoning**، واستخدمت **Wireshark** لفحص الترافيك الشبكي، تتبع النشاط العدائي، واستخراج الأدلة الفنية المرتبطة بالهجوم.

كان التركيز الأساسي على فهم كيف يمكن للمهاجم استغلال بروتوكولات **Name Resolution** داخل الشبكة للحصول على بيانات اعتماد، ثم تتبع تسلسل الأحداث من بداية التسميم إلى مرحلة استغلال بيانات الاعتماد.

---

## Key Highlights

### أبرز ما طبّقته في المختبر:

✅ **تحليل الترافيك الشبكي باستخدام Wireshark**  
قمت بفتح ملف PCAP وتحليل البروتوكولات المختلفة المستخدمة في الشبكة

✅ **اكتشاف هجوم LLMNR / NBT-NS Poisoning**  
تحديد نقاط الهجوم عبر تحليل استعلامات LLMNR و NBT-NS غير الطبيعية

✅ **تحديد الجهاز المهاجم والأجهزة المتأثرة**  
استخراج عناوين IP وأسماء الأجهزة من الترافيك الشبكي

✅ **تتبع اتصال SMB وتحليل NTLM Authentication**  
فحص عمليات المصادقة وتحديد محاولات السرقة

✅ **استخراج اسم المستخدم واسم الجهاز المتأثر**  
تحليل البيانات المستخرجة من الـ SMB sessions

✅ **فهم تسلسل الهجوم من البداية حتى استغلال بيانات الاعتماد**  
إعادة بناء timeline الهجوم الكامل

---

## Technical Analysis

### Attack Flow Analysis:

1. **LLMNR Broadcast Requests**  
   - Victim machine broadcasts LLMNR queries looking for network resources
   - Normal behavior when DNS resolution fails

2. **Attacker Response (Poisoning)**  
   - Malicious actor responds to LLMNR/NBT-NS queries
   - Directs victim to attacker-controlled machine

3. **SMB Connection Establishment**  
   - Victim attempts SMB connection to fake resource
   - Server Message Block (SMB) negotiation begins

4. **NTLM Authentication**  
   - NTLM challenge-response authentication initiated
   - Credentials transmitted during authentication process

5. **Credential Extraction**  
   - Attacker captures NTLM hashes
   - Username and host information compromised

---

## Key Protocols Analyzed

### 🔹 LLMNR (Link-Local Multicast Name Resolution)
- Fallback protocol when DNS fails
- Vulnerable to poisoning attacks
- No authentication mechanism

### 🔹 NBT-NS (NetBIOS Name Service)
- Legacy Windows name resolution protocol  
- Broadcasts name queries across network
- Easy target for MitM attacks

### 🔹 SMB (Server Message Block)
- File sharing and network resource access protocol
- Used for establishing connections to network shares

### 🔹 NTLM (NT LAN Manager Authentication)
- Challenge-response authentication protocol
- Transmits credential hashes over network
- Can be captured and cracked offline

---

## Lessons Learned

### الخلاصة:

تحليل الشبكات في بيئة **SOC** لا يعتمد فقط على معرفة الأداة، بل على القدرة على:

- **قراءة الترافيك** وفهم البروتوكولات المختلفة
- **ربط الأحداث** وبناء timeline متكامل
- **فهم سلوك المهاجم** داخل الشبكة
- **استخراج الأدلة** الفنية بدقة

كل مختبر عملي مثل هذا يضيف فهمًا أعمق لكيفية:
- التحقيق في الحوادث الأمنية
- استخراج الأدلة من الترافيك الشبكي  
- بناء عقلية تحليلية أقوى في مجال Blue Team

---

## Remediation Recommendations

### Defense Strategies:

1. **Disable LLMNR and NBT-NS**  
   - Group Policy: Computer Configuration → Administrative Templates → Network → DNS Client
   - Set "Turn off multicast name resolution" to Enabled

2. **Implement SMB Signing**  
   - Enforce SMB packet signing to prevent tampering
   - Configure via Group Policy

3. **Network Segmentation**  
   - Isolate critical systems from general network
   - Implement VLANs and access controls

4. **Monitor for Poisoning Attacks**  
   - SIEM rules for abnormal LLMNR/NBT-NS traffic
   - Alert on multiple responses to name resolution queries

5. **Use Kerberos Authentication**  
   - Prefer Kerberos over NTLM where possible
   - More secure authentication mechanism

---

## Skills Applied

- Wireshark Network Traffic Analysis
- LLMNR/NBT-NS Protocol Analysis  
- SMB Protocol Investigation
- NTLM Authentication Forensics
- Blue Team Defense
- DFIR Methodologies
- SOC Analysis
- Incident Timeline Reconstruction

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

**Date**: May 3, 2026  
**Version**: 1.0
