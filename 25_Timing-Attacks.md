
## Overview

Timing attacks exploit observable differences in response times to extract sensitive information or discover hidden functionality. The fundamental principle involves measuring time variations in server responses to similar requests to answer complex questions or detect hidden features.

### Key Concepts

- **Goal**: Extract information or discover hidden functionality by analyzing response time differences
- **Traditional Challenge**: Network latency and jitter made timing attacks difficult and unreliable
- **Modern Breakthrough**: The HTTP/2 Single Packet Attack technique removes network delays, leaving only server-side timing differences visible
- **Typical Time Differences**: As small as 5ms can be significant and exploitable
- **Root Causes**: DNS lookups, logging operations, input validation checks, or conditional processing

### Why Timing Differences Occur

Time variations in responses can be caused by:

- **DNS resolution requests** triggered by specific parameters
- **Logging operations** when invalid or specific input is received
- **Validation checks** performed only when certain parameters are present
- **Database queries** of varying complexity
- **Cryptographic operations** with non-constant time implementations
- **Backend service calls** to different internal systems
- **File system operations** or cache misses

## Exploitation Methods

### 1. Hidden Parameter Discovery

**Objective**: Find undocumented parameters, headers, or endpoints by detecting timing differences when they are present.

**Technique**:
1. Send baseline requests without the suspected parameter
2. Send requests including the suspected parameter with various values
3. Measure response time differences (look for consistent ~5ms+ differences)
4. Use statistical analysis to confirm findings across multiple samples

**Tools**:
- **Param Miner** (Burp Suite extension) - Automated discovery using timing analysis
- **Turbo Intruder** - For high-volume timing measurements

**Steps**:
```

1. Identify target endpoint
2. Generate wordlist of potential parameter/header names
3. Send 50-100 baseline requests (without parameter)
4. For each candidate parameter:
    - Send 50-100 requests with parameter present
    - Calculate mean and standard deviation
    - Compare against baseline
5. Parameters showing consistent >5ms difference are candidates
6. Verify findings with additional testing

```

### 2. Scoped SSRF Discovery (Reverse Proxy Misconfigurations)

**Objective**: Discover open proxies that only allow requests to whitelisted domains/IPs.

**Technique**:
1. Identify endpoints that accept URL parameters (e.g., `url=`, `proxy=`, `fetch=`)
2. Test with allowed domain (e.g., company subdomain)
3. Test with blocked domain (e.g., external domain)
4. Compare response times - allowed domains typically show different timing
5. Even with identical responses, timing reveals the misconfiguration

**Detection Pattern**:
```http
# Request 1 - Allowed Domain
POST /api/fetch HTTP/2
Host: target.com

url=https://internal.target.com

# Timing: 150ms (DNS + Connection + Response)

# Request 2 - Blocked Domain
POST /api/fetch HTTP/2
Host: target.com

url=https://evil.com

# Timing: 50ms (Immediate rejection)
```

**Steps**:

```
1. Identify URL-accepting parameters
2. Test with known-good internal domains
3. Test with external domains
4. Measure consistent timing differences (>50ms typical)
5. Enumerate internal infrastructure using subdomain lists
6. Map accessible internal services
```

### 3. Front-End Impersonation Attacks

**Objective**: Leverage open proxies with header forwarding to access restricted internal resources.

**Attack Chain**:

1. Discover scoped SSRF via timing differences
2. Identify that proxy forwards headers like `X-Forwarded-For`, `X-Real-IP`
3. Inject internal IP addresses in these headers
4. Access internal-only domains/services through the proxy

**Example**:

```http
POST /api/proxy HTTP/2
Host: target.com
X-Forwarded-For: 10.0.0.1
X-Real-IP: 192.168.1.1

url=https://admin-internal.target.com
```

**Steps**:

```
1. Confirm open proxy existence via timing
2. Test header forwarding:
   - Send requests with X-Forwarded-For set to internal IPs
   - Monitor for different responses or timing
3. Enumerate internal IP ranges (RFC 1918 addresses)
4. Access internal-only services
5. Bypass firewall restrictions
```

### 4. Internal Subdomain Discovery

**Objective**: Find subdomains only accessible from internal networks.

**Technique**:

1. Use discovered open proxy as pivot point
2. Parse/generate potential internal subdomain names
3. Send requests through proxy for each subdomain
4. Timing differences reveal valid internal hosts
5. DNS resolution time indicates valid vs invalid subdomains

**Wordlist Sources**:

- Certificate Transparency logs
- Common subdomain patterns (admin-, internal-, vpn-, etc.)
- Previous reconnaissance data

### 5. Firewall Bypass

**Objective**: Access restricted subdomains by routing through internal open proxy.

**Attack Flow**:

```
Internet → Public Endpoint (Open Proxy) → Internal Network → Restricted Subdomain
```

**Benefits**:

- Bypass external firewall rules
- Access services only available to internal network
- Leverage proxy's trusted network position
- Avoid IP-based restrictions

### 6. HTTP/2 Single Packet Attack for Timing

**Objective**: Remove network jitter to achieve precise timing measurements.

**Technique**:

1. Use HTTP/2 multiplexing to send multiple requests in single TCP packet
2. Requests arrive at server simultaneously
3. Response timing differences reflect only server-side processing
4. Network latency affects all requests equally (can be subtracted)

**Implementation**:

```python
# Conceptual example - use specialized tools like Turbo Intruder
# Send 20 identical requests in single packet
# Measure response time variance - should be minimal
# Introduce variation (parameter present/absent)
# Time difference reveals server-side processing difference
```

## Bypasses

### Network Jitter Mitigation

**Challenge**: Network latency creates noise in timing measurements.

**Bypass**:

- Use HTTP/2 Single Packet Attack to send multiple requests simultaneously
- Measure relative timing differences between concurrent requests
- Statistical analysis with large sample sizes (50-100+ requests)
- Calculate median and filter outliers
- Use connection keep-alive to reduce connection establishment overhead

### Server-Side Caching

**Challenge**: Cached responses may mask timing differences.

**Bypass**:

- Add cache-busting parameters to each request
- Vary request body or URL path slightly
- Use unique identifiers in each request
- Test during low-traffic periods when cache is cold
- Force cache misses with unique headers (e.g., `Cache-Control: no-cache`)

### WAF/Rate Limiting

**Challenge**: Security controls may interfere with timing measurements.

**Bypass**:

- Distribute requests over time to avoid rate limits
- Use multiple source IPs via proxies
- Implement exponential backoff between request batches
- Target endpoints less likely to have strict rate limits
- Use valid session tokens to appear as legitimate user

### Load Balancer Distribution

**Challenge**: Different backend servers may have varying response times.

**Bypass**:

- Use session stickiness (cookies) to target same backend
- Increase sample size to average out variations
- Identify and track backend server (via response headers if exposed)
- Test during low-load periods for consistency

## Payloads

### Hidden Parameter Discovery Payloads

```http
# Test common hidden parameters
?debug=1
?admin=true
?internal=1
?test=1
?dev=1
?trace=1
?verbose=1
?proxy=http://localhost
?redirect=http://internal.local
?callback=http://burp-collaborator
```

### SSRF Detection Payloads

```http
# Timing-based SSRF detection
url=https://internal.company.com (expected slow/success)
url=https://attacker.com (expected fast/blocked)
url=http://169.254.169.254 (AWS metadata - timing reveals filtering)
url=http://localhost
url=http://127.0.0.1
url=http://[::1]
url=http://internal.local
url=http://192.168.1.1
url=http://10.0.0.1
url=http://172.16.0.1
```

### Header Injection for Bypass

```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 192.168.1.1
X-Originating-IP: 10.0.0.1
X-Remote-IP: 172.16.0.1
X-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Host: internal.company.com
X-Original-URL: /admin
X-Rewrite-URL: /internal
```

## Higher Impact Scenarios

### 1. Cloud Metadata Service Access

**Scenario**: Use timing-detected SSRF to access cloud metadata endpoints.

**Impact**:

- AWS: Access IAM credentials via `http://169.254.169.254/latest/meta-data/`
- Azure: Access instance metadata via `http://169.254.169.254/metadata/instance`
- GCP: Access metadata via `http://metadata.google.internal/`

**Attack Chain**:

```
1. Discover open proxy via timing attack
2. Test access to 169.254.169.254
3. Extract IAM roles and credentials
4. Escalate to full cloud environment compromise
```

### 2. Internal Admin Panel Access

**Scenario**: Bypass external firewall to access internal admin interfaces.

**Impact**:

- Full administrative control over internal systems
- Access to sensitive configuration data
- Ability to modify system settings
- Potential for lateral movement

**Attack Chain**:

```
1. Timing attack reveals open proxy
2. Enumerate internal admin subdomains (admin.internal.*, manage.internal.*)
3. Access admin panel through proxy
4. Authenticate using default credentials or further attacks
5. Gain administrative privileges
```

### 3. Database Access via Internal APIs

**Scenario**: Access internal database APIs not exposed to internet.

**Impact**:

- Direct database query capabilities
- Data exfiltration
- Potential for SQL injection on internal endpoints
- Access to sensitive customer data

### 4. Internal Service Enumeration

**Scenario**: Map entire internal infrastructure through timing-based discovery.

**Impact**:

- Complete network topology mapping
- Identification of vulnerable internal services
- Discovery of sensitive internal applications
- Foundation for comprehensive internal penetration

### 5. Multi-Tenant Isolation Bypass

**Scenario**: Use timing attacks to infer information about other tenants in SaaS environment.

**Impact**:

- Determine existence of specific tenant accounts
- Infer tenant configuration details
- Identify shared resources
- Potential for tenant-to-tenant attacks

## Mitigations

### For Developers

**Constant-Time Operations**:

- Implement constant-time string comparison for secrets and tokens
- Use timing-safe comparison functions (e.g., `crypto.timingSafeEqual()` in Node.js)
- Ensure authentication and authorization checks take constant time regardless of outcome

**Rate Limiting**:

- Implement aggressive rate limiting on sensitive endpoints
- Use adaptive rate limiting based on request patterns
- Apply per-IP and per-session limits

**Response Time Normalization**:

```python
# Add random delay to normalize response times
import time
import random

def normalize_response_time(response, base_time=0.1):
    processing_time = time.time() - request_start
    remaining = base_time - processing_time
    if remaining > 0:
        time.sleep(remaining + random.uniform(0, 0.01))
    return response
```

**Input Validation**:

- Perform all validation checks regardless of early failures
- Avoid short-circuit evaluation that creates timing differences
- Log validation failures without creating observable timing variations

**Disable or Restrict Proxying**:

- Remove URL-fetching functionality if not essential
- Implement strict allowlists for permitted domains
- Use network-level controls to restrict proxy destinations
- Validate and sanitize all URL parameters

**Header Handling**:

- Do not blindly forward client-provided headers like `X-Forwarded-For`
- Implement header validation and sanitization
- Use trusted sources for client IP determination
- Document which headers are trusted and why

### For Security Teams

**Monitoring and Detection**:

- Monitor for repeated similar requests from same source
- Alert on unusual timing patterns in request logs
- Implement anomaly detection for response time distributions
- Track requests to internal IP ranges or metadata endpoints

**Network Segmentation**:

- Isolate internal services from DMZ
- Implement strict firewall rules between network zones
- Use separate VLANs for different security zones
- Restrict outbound connections from web servers

**Regular Security Assessments**:

- Include timing attack testing in penetration tests
- Audit all URL-accepting parameters
- Review header forwarding configurations
- Test for SSRF vulnerabilities regularly

**Web Application Firewall (WAF)**:

- Configure WAF rules to detect SSRF attempts
- Block requests to internal IP ranges
- Monitor for timing-based enumeration patterns
- Implement request throttling

### Infrastructure Hardening

**Reverse Proxy Configuration**:

```nginx
# Nginx example - restrict proxy targets
location /api/proxy {
    # Only allow specific domains
    if ($arg_url !~ "^https://allowed-domain\.com") {
        return 403;
    }
    # Don't forward dangerous headers
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Real-IP $remote_addr;
}
```

**DNS Configuration**:

- Use DNS sinkhole for internal domains
- Implement split-horizon DNS
- Block resolution of internal names from DMZ
- Monitor DNS queries for suspicious patterns

**Metadata Service Protection**:

```bash
# AWS: Require IMDSv2 (session-based)
# Prevents simple SSRF to metadata service
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

## References

- [PortSwigger Research: Listen to the Whispers - Web Timing Attacks That Actually Work](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work)