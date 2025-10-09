## **STAGE 0: Initial Notes**

### **Testing Methodology Reminders**

- Always test with different user roles (guest, user, admin)
- Test with different HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
- Test with different content types (application/json, application/xml, multipart/form-data, text/plain)
- Test with both authenticated and unauthenticated requests
- Check for verbose error messages
- Monitor out-of-band interactions (Burp Collaborator, webhook.site)
- Test mobile vs web implementations
- Test API vs web interface
- Review all requests in proxy history
- Analyze JavaScript thoroughly
- Check for information disclosure in headers, cookies, responses

### **Documentation**

- Document all findings with steps to reproduce
- Include HTTP request/response evidence
- Note the impact and exploitability
- Suggest remediation steps
- Classify severity (Critical, High, Medium, Low, Informational)



## **STAGE 1: Reconnaissance & Asset Discovery**

### **1.1 Subdomain & Domain Intelligence**

- [ ] Subdomain enumeration (passive + active)
- [ ] Subdomain takeover testing
- [ ] DNS zone transfer testing
- [ ] ASN & IP space enumeration (ipinfo)
- [ ] Reverse DNS lookup
- [ ] Leaked subdomain certificates (crt.sh)

### **1.2 Technology Fingerprinting**

- [ ] Identify technologies (Wappalyzer, Whatruns, BuiltWith)
- [ ] Identify WAF/firewall presence
- [ ] Identify web server (Apache, Nginx, IIS)
- [ ] Identify frameworks (Django, Flask, Laravel, Ruby on Rails, React)
- [ ] Identify CMS (WordPress, Drupal, Joomla, Magento, Confluence, Jira)
- [ ] Port scanning (80, 443, 8080, 8443, 8000, 3000, 5000, common services)

### **1.3 Content Discovery**

- [ ] Directory and file enumeration
- [ ] Important file exposure (.bak, .old, .git, .svn, .env, .DS_Store)
- [ ] Configuration files (config.php, web.config, settings.py)
- [ ] Backup files exposure
- [ ] robots.txt analysis
- [ ] sitemap.xml analysis
- [ ] .well-known/ directory
- [ ] phpinfo.php exposure
- [ ] crossdomain.xml analysis
- [ ] clientaccesspolicy.xml analysis

### **1.4 JavaScript & API Discovery**

- [ ] JavaScript file analysis for endpoints, API keys, tokens
- [ ] JavaScript source mapping files (.map)
- [ ] API endpoint discovery
- [ ] Parameter discovery and fuzzing
- [ ] Hidden parameters discovery
- [ ] GraphQL endpoint discovery
- [ ] WebSocket endpoint discovery

### **1.5 External Intelligence**

- [ ] Shodan/Censys/Fofa/ZoomEye lookup
- [ ] Cloud storage enumeration (S3, Azure Blob, GCS)
- [ ] Google dorking for exposed files and credentials
- [ ] GitHub/GitLab recon for leaked secrets, tokens, API keys
- [ ] Pastebin/Trello/Slack leaks
- [ ] Wayback Machine and archive analysis
- [ ] Leaked credentials via breach databases (Have I Been Pwned)

### **1.6 Information Disclosure**

- [ ] Review source code comments
- [ ] Internal IP disclosure via headers or responses
- [ ] Email addresses disclosure
- [ ] Version disclosure (headers, error messages)
- [ ] Stack trace exposure
- [ ] Debug mode enabled

---

## **STAGE 2: Misconfigurations & Low-Hanging Fruits**

### **2.1 HTTP Security Headers**

- [ ] Missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)
- [ ] Weak CSP policy
- [ ] CSP bypass techniques
- [ ] Clickjacking vulnerabilities
- [ ] X-Frame-Options bypass

### **2.2 Access Control Issues**

- [ ] 403 Forbidden bypass techniques
- [ ] 401 Unauthorized bypass
- [ ] Directory listing enabled
- [ ] Forced browsing
- [ ] Missing function level access control

### **2.3 Server Misconfigurations**

- [ ] Default credentials
- [ ] Directory traversal via misconfiguration
- [ ] Server-status exposure
- [ ] Server-info exposure
- [ ] Tomcat manager exposed
- [ ] Jenkins exposed without auth
- [ ] Grafana anonymous access
- [ ] HAProxy stats page exposed
- [ ] IIS tilde enumeration
- [ ] Apache server-status/info pages

### **2.4 SSL/TLS Issues**

- [ ] Weak SSL/TLS versions
- [ ] Weak cipher suites
- [ ] Certificate validation issues
- [ ] Mixed content (HTTP resources on HTTPS)

---

## **STAGE 3: IDOR & Authorization Flaws**

### **3.1 Direct Object Reference**

- [ ] Numeric ID enumeration
- [ ] UUID/GUID predictability or leakage
- [ ] IDOR in API endpoints
- [ ] IDOR in file download/upload
- [ ] IDOR in profile, orders, invoices, messages
- [ ] IDOR via HTTP headers (X-User-ID, X-Account-ID)
- [ ] IDOR via body parameter manipulation
- [ ] IDOR in billing/statements
- [ ] IDOR from cart/shipment/ticket details
- [ ] IDOR in GraphQL queries
- [ ] IDOR via encoded IDs (base64, hex)
- [ ] IDOR in WebSocket messages

### **3.2 Privilege Escalation**

- [ ] Horizontal privilege escalation
- [ ] Vertical privilege escalation (user to admin)
- [ ] Role manipulation in requests
- [ ] Bypass authorization in admin panels
- [ ] JWT token manipulation for privilege escalation
- [ ] Cookie tampering for privilege escalation
- [ ] Parameter pollution for privilege escalation
- [ ] Mass assignment for privilege escalation

---

## **STAGE 4: Authentication & Session Management**

### **4.1 Registration Flaws**

- [ ] Duplicate registration/account overwrite
- [ ] Overwrite default pages via username (e.g., /admin, /images)
- [ ] Add only spaces in password field
- [ ] Unicode/homograph attack in registration
- [ ] Email verification bypass
- [ ] Race condition in registration

### **4.2 Authentication Bypass**

- [ ] Authentication bypass via logical flaws
- [ ] SQL injection in login
- [ ] NoSQL injection in login
- [ ] LDAP injection authentication bypass
- [ ] Rate-limiting bypass (IP rotation, headers, null bytes)
- [ ] Auto-complete enabled on sensitive fields
- [ ] Credential transmission over HTTP
- [ ] Weak login function over HTTP and HTTPS if both available
- [ ] Remember me functionality issues
- [ ] Login CSRF
- [ ] Username enumeration
- [ ] Account lockout bypass

### **4.3 Password Reset & Recovery**

- [ ] Analyze password reset token
- [ ] Token brute-force or prediction
- [ ] Token expiration testing
- [ ] Token reuse after successful reset
- [ ] Token sent over HTTP
- [ ] Token in URL (Referer leakage)
- [ ] Password reset link manipulation (user ID tampering)
- [ ] Password reset poisoning (Host header injection)
- [ ] Security question bypass
- [ ] Weak security questions
- [ ] Session invalidation after reset
- [ ] Old password disclosure
- [ ] Account takeover via email parameter tampering
- [ ] Password reset token leaked in response
- [ ] Multiple password reset tokens active
- [ ] No rate limiting on password reset

### **4.4 Two-Factor Authentication (2FA/MFA)**

- [ ] 2FA/OTP bypass (code reuse, response manipulation, null/000000)
- [ ] 2FA/OTP code brute-force
- [ ] 2FA/OTP code leakage in response
- [ ] Missing 2FA code integrity validation
- [ ] Enable 2FA without email confirmation
- [ ] 2FA bypass via backup codes
- [ ] 2FA bypass via remember device
- [ ] 2FA bypass via race condition
- [ ] 2FA code in URL/Referer
- [ ] 2FA implementation on client-side only
- [ ] Lack of rate limiting on 2FA

### **4.5 OAuth/SSO Vulnerabilities**

- [ ] OAuth misconfigurations (open redirect, token reuse, state bypass)
- [ ] redirect_uri validation bypass
- [ ] OAuth code reuse
- [ ] OAuth token prediction/brute-force
- [ ] Missing state parameter
- [ ] CSRF in OAuth flow
- [ ] Open redirect in OAuth callback
- [ ] Pre-account takeover via OAuth
- [ ] Account linking vulnerabilities
- [ ] OAuth token leakage

### **4.6 SAML Vulnerabilities**

- [ ] SAML response tampering
- [ ] SAML signature bypass
- [ ] XML signature wrapping (XSW) attacks
- [ ] SAML replay attacks
- [ ] Missing signature validation

### **4.7 JWT Vulnerabilities**

- [ ] JWT none algorithm
- [ ] JWT weak secret (HS256 brute-force)
- [ ] JWT algorithm confusion (RS256 to HS256)
- [ ] JWT token manipulation
- [ ] JWT kid parameter injection
- [ ] JWT jku/x5u header injection
- [ ] JWT expiration not validated
- [ ] JWT signature not verified

### **4.8 Session Management**

- [ ] Decode and analyze session tokens
- [ ] Predictable session tokens
- [ ] Session token in URL (Referer leakage)
- [ ] Session invalidation on logout
- [ ] Session invalidation on password change
- [ ] Concurrent login testing
- [ ] Session expiration testing
- [ ] Session fixation
- [ ] Cookie security attributes (Secure, HttpOnly, SameSite)
- [ ] Cookie scope and domain issues
- [ ] Cross-device session hijacking
- [ ] Session persistence across browser restarts
- [ ] Session not invalidated after account deletion
- [ ] Improper session management on password reset
- [ ] Lack of concurrent session limit
- [ ] Session token leakage in logs/analytics

### **4.9 Cookie Security**

- [ ] Cookie without Secure flag
- [ ] Cookie without HttpOnly flag
- [ ] Missing SameSite attribute
- [ ] Cookie tossing attack
- [ ] Cookie injection
- [ ] Cookie jar overflow
- [ ] Subdomain cookie hijacking

---

## **STAGE 5: XSS (Cross-Site Scripting)**

### **5.1 XSS Types**

- [ ] Reflected XSS
- [ ] Stored XSS
- [ ] DOM-based XSS
- [ ] Blind XSS
- [ ] Self-XSS with social engineering
- [ ] Mutation XSS (mXSS)
- [ ] Universal XSS (UXSS)

### **5.2 XSS Contexts**

- [ ] XSS in HTML context
- [ ] XSS in attribute context
- [ ] XSS in JavaScript context
- [ ] XSS in CSS context
- [ ] XSS in JSON responses
- [ ] XSS via SVG upload
- [ ] XSS in file upload (filename, metadata, EXIF)
- [ ] XSS via Markdown/Rich Text editors
- [ ] XSS in PDF generation
- [ ] XSS via dangling markup
- [ ] XSS in error messages
- [ ] XSS in redirection URLs
- [ ] XSS in third-party libraries
- [ ] XSS in hidden fields
- [ ] XSS via cookies
- [ ] XSS in email templates

### **5.3 XSS Bypass Techniques**

- [ ] Filter bypass with encoding
- [ ] Filter bypass with obfuscation
- [ ] Filter bypass with polyglots
- [ ] CSP bypass
- [ ] WAF bypass for XSS
- [ ] Event handler XSS
- [ ] XSS via protocol handlers
- [ ] XSS in AngularJS templates
- [ ] XSS in Vue.js templates
- [ ] XSS in React components

### **5.4 Advanced XSS**

- [ ] Stored XSS via database
- [ ] XSS in API responses
- [ ] XSS chained with CSRF
- [ ] XSS to cookie theft
- [ ] XSS to account takeover
- [ ] XSS to keylogging

---

## **STAGE 6: Injection Vulnerabilities**

### **6.1 SQL Injection**

- [ ] Error-based SQLi
- [ ] Union-based SQLi
- [ ] Blind SQLi (Boolean-based)
- [ ] Time-based blind SQLi
- [ ] Second-order SQLi
- [ ] SQLi in login page
- [ ] SQLi in search functionality
- [ ] SQLi in HTTP headers (User-Agent, Referer, X-Forwarded-For, Cookie)
- [ ] SQLi in JSON/XML payloads
- [ ] SQLi in ORDER BY clause
- [ ] SQLi in INSERT/UPDATE statements
- [ ] Out-of-band SQLi
- [ ] WAF bypass techniques for SQLi

### **6.2 NoSQL Injection**

- [ ] MongoDB injection
- [ ] NoSQL authentication bypass
- [ ] NoSQL operator injection ($ne, $gt, $regex)
- [ ] NoSQL timing attacks
- [ ] NoSQL blind injection

### **6.3 Command Injection**

- [ ] OS command injection
- [ ] Blind command injection (time-based)
- [ ] Out-of-band command injection
- [ ] Command injection in file operations
- [ ] Command injection in CSV export
- [ ] Command injection via image processing
- [ ] Filter bypass techniques

### **6.4 LDAP Injection**

- [ ] LDAP authentication bypass
- [ ] LDAP blind injection
- [ ] LDAP data exfiltration

### **6.5 XPath Injection**

- [ ] XPath authentication bypass
- [ ] XPath blind injection

### **6.6 Template Injection**

- [ ] Server-Side Template Injection (SSTI)
- [ ] SSTI in Jinja2
- [ ] SSTI in Twig
- [ ] SSTI in Freemarker
- [ ] SSTI in Velocity
- [ ] SSTI in Smarty
- [ ] SSTI in Pug/Jade
- [ ] Client-Side Template Injection (CSTI)
- [ ] AngularJS template injection
- [ ] Vue.js template injection

### **6.7 HTML Injection**

- [ ] HTML injection in profile fields
- [ ] HTML injection in comments
- [ ] HTML injection leading to phishing
- [ ] HTML injection via email

### **6.8 CRLF Injection**

- [ ] HTTP response splitting
- [ ] CRLF in headers
- [ ] CRLF for XSS
- [ ] CRLF for open redirect
- [ ] CRLF in log injection

### **6.9 Email Injection**

- [ ] SMTP header injection
- [ ] Email parameter injection
- [ ] Email spoofing
- [ ] BCC injection
- [ ] Email content injection

### **6.10 Server-Side Includes (SSI) Injection**

- [ ] SSI command execution
- [ ] SSI file inclusion
- [ ] SSI information disclosure

---

## **STAGE 7: XXE (XML External Entity)**

### **7.1 XXE Types**

- [ ] Classic XXE (file disclosure)
- [ ] Blind XXE (out-of-band)
- [ ] XXE via file upload (SVG, DOCX, XLSX, PDF)
- [ ] XXE in SAML
- [ ] XXE in SOAP requests
- [ ] XInclude injection
- [ ] XXE in RSS feeds

### **7.2 XXE Exploitation**

- [ ] Local file disclosure
- [ ] SSRF via XXE
- [ ] Port scanning via XXE
- [ ] DoS via billion laughs attack
- [ ] Remote code execution via expect wrapper

---

## **STAGE 8: SSRF (Server-Side Request Forgery)**

### **8.1 SSRF Discovery**

- [ ] Basic localhost/127.0.0.1 access
- [ ] Internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- [ ] SSRF via URL parameters
- [ ] SSRF via file upload
- [ ] SSRF via webhooks
- [ ] SSRF via PDF generators
- [ ] SSRF via XML processors
- [ ] Blind SSRF (out-of-band interaction)

### **8.2 Cloud Metadata**

- [ ] AWS metadata (169.254.169.254)
- [ ] GCP metadata
- [ ] Azure metadata
- [ ] DigitalOcean metadata
- [ ] Oracle Cloud metadata

### **8.3 SSRF Bypass Techniques**

- [ ] Decimal IP encoding
- [ ] Octal IP encoding
- [ ] Hex IP encoding
- [ ] IPv6 localhost (::1)
- [ ] URL encoding
- [ ] Double URL encoding
- [ ] DNS rebinding
- [ ] Redirect-based SSRF bypass
- [ ] Protocol smuggling
- [ ] SSRF via open redirect

### **8.4 SSRF Impact**

- [ ] Port scanning internal network
- [ ] Access internal services
- [ ] Read local files via file://
- [ ] RCE via gopher://
- [ ] Cloud credential theft

---

## **STAGE 9: CSRF (Cross-Site Request Forgery)**

### **9.1 CSRF Testing**

- [ ] Missing CSRF tokens
- [ ] CSRF token not validated
- [ ] CSRF token reuse
- [ ] CSRF token in GET request
- [ ] CSRF token partial validation
- [ ] CSRF token not tied to user session

### **9.2 CSRF Bypass Techniques**

- [ ] Bypass via method tampering (POST to GET)
- [ ] Bypass via removing token parameter
- [ ] Bypass via null/empty token value
- [ ] Bypass via content-type manipulation
- [ ] Bypass via custom headers removal
- [ ] SameSite cookie bypass

### **9.3 CSRF Contexts**

- [ ] CSRF in state-changing actions
- [ ] CSRF in JSON APIs
- [ ] CSRF in logout functions
- [ ] CSRF in account deletion
- [ ] CSRF in password change
- [ ] CSRF in email change
- [ ] Blind CSRF
- [ ] Login CSRF

### **9.4 Related Attacks**

- [ ] On-Site Request Forgery (OSRF)
- [ ] Cross-Site WebSocket Hijacking (CSWSH)

---

## **STAGE 10: Business Logic Vulnerabilities**

### **10.1 Payment & Transaction Logic**

- [ ] Price manipulation
- [ ] Quantity manipulation (negative values)
- [ ] Amount manipulation in payment
- [ ] Currency manipulation
- [ ] Payment gateway bypass
- [ ] Transaction replay attacks
- [ ] Transaction tampering
- [ ] Unauthorized fund transfer
- [ ] Refund manipulation
- [ ] Double spending

### **10.2 Discount & Promotion Abuse**

- [ ] Coupon/voucher reuse
- [ ] Coupon code brute-force
- [ ] Referral code abuse
- [ ] Discount stacking
- [ ] Free trial abuse
- [ ] Subscription downgrade without refund

### **10.3 E-commerce Logic**

- [ ] Add to cart ID manipulation
- [ ] Order ID enumeration and tampering
- [ ] Shipping address tampering
- [ ] Booking/reservation tampering
- [ ] Inventory manipulation
- [ ] Out-of-stock bypass

### **10.4 Race Conditions**

- [ ] Race condition in payment processing
- [ ] Race condition in coupon usage
- [ ] Race condition in limited quantity items
- [ ] Race condition in fund transfer
- [ ] Parallel request exploitation
- [ ] Time-of-check to time-of-use (TOCTOU)

### **10.5 Access Control Logic**

- [ ] Privilege escalation via role manipulation
- [ ] Forced browsing to admin functions
- [ ] Multi-stage process bypass
- [ ] Workflow manipulation
- [ ] State transition exploitation

### **10.6 Account Logic**

- [ ] Change email without verification
- [ ] Change password without current password
- [ ] Account deletion and recovery testing
- [ ] Missing re-authentication for sensitive actions
- [ ] Account linking vulnerabilities
- [ ] Profile takeover

### **10.7 Other Logic Flaws**

- [ ] Parameter tampering
- [ ] Missing validation
- [ ] Handling of incomplete input
- [ ] Trust boundary violations
- [ ] Time manipulation
- [ ] Inconsistent validation
- [ ] Process flow manipulation

---

## **STAGE 11: File Upload Vulnerabilities**

### **11.1 File Upload Bypass**

- [ ] Unrestricted file upload (webshell)
- [ ] Extension blacklist bypass (double extension, case variation)
- [ ] MIME type/magic byte bypass
- [ ] Null byte injection
- [ ] Content-Type manipulation
- [ ] Filename manipulation

### **11.2 File Upload Exploitation**

- [ ] Path traversal in filename
- [ ] File overwrite
- [ ] Zip slip vulnerability
- [ ] XXE via file upload (SVG, XML, DOCX)
- [ ] XSS via file upload (SVG, HTML)
- [ ] SSRF via file upload
- [ ] RCE via file upload
- [ ] Stored XSS via filename

### **11.3 File Processing Vulnerabilities**

- [ ] ImageMagick exploits
- [ ] ImageTragick (CVE-2016-3714)
- [ ] Metadata injection (EXIF)
- [ ] CSV injection / Formula injection
- [ ] XLSX/Excel macro injection
- [ ] PDF malicious code
- [ ] File inclusion via upload

### **11.4 File Download Vulnerabilities**

- [ ] Arbitrary file download
- [ ] Path traversal in download
- [ ] IDOR in file download

---

## **STAGE 12: API Security**

### **12.1 API Authentication & Authorization**

- [ ] Missing authentication on API endpoints
- [ ] Weak API key generation
- [ ] API key leakage
- [ ] API key in URL
- [ ] Lack of rate limiting
- [ ] IDOR in APIs
- [ ] Broken object level authorization (BOLA)
- [ ] Broken function level authorization

### **12.2 API Vulnerabilities**

- [ ] Mass assignment
- [ ] Excessive data exposure
- [ ] API versioning issues (v1 vs v2 differences)
- [ ] API parameter tampering
- [ ] HTTP verb tampering
- [ ] Missing security headers in API

### **12.3 GraphQL Security**

- [ ] GraphQL introspection enabled
- [ ] GraphQL batching attacks
- [ ] GraphQL depth/complexity DoS
- [ ] GraphQL IDOR
- [ ] GraphQL injection
- [ ] GraphQL CSRF
- [ ] GraphQL field suggestion

### **12.4 REST API Testing**

- [ ] REST API IDOR
- [ ] REST API SQL injection
- [ ] REST API XXE
- [ ] REST API SSRF
- [ ] REST parameter pollution

### **12.5 API Rate Limiting**

- [ ] No rate limiting
- [ ] Rate limit bypass techniques
- [ ] GraphQL query cost exploitation

---

## **STAGE 13: CORS (Cross-Origin Resource Sharing)**

### **13.1 CORS Misconfigurations**

- [ ] CORS with wildcard (*) and credentials
- [ ] Null origin reflection
- [ ] Trusted subdomain exploitation
- [ ] Pre-domain wildcard bypass
- [ ] Post-domain wildcard bypass
- [ ] Origin reflection vulnerability
- [ ] CORS and JSONP combination

### **13.2 CORS Exploitation**

- [ ] Sensitive data exposure via CORS
- [ ] CSRF via CORS misconfiguration
- [ ] Subdomain takeover + CORS

---

## **STAGE 14: WebSockets Security**

### **14.1 WebSocket Vulnerabilities**

- [ ] WebSocket hijacking (missing origin check)
- [ ] WebSocket message tampering
- [ ] WebSocket CSRF
- [ ] WebSocket injection
- [ ] Missing authentication on WebSocket
- [ ] WebSocket MITM
- [ ] Content smuggling via WebSockets

---

## **STAGE 15: HTTP Request Smuggling & Advanced HTTP**

### **15.1 Request Smuggling**

- [ ] CL.TE (Content-Length, Transfer-Encoding)
- [ ] TE.CL (Transfer-Encoding, Content-Length)
- [ ] TE.TE (obfuscated Transfer-Encoding)
- [ ] HTTP/2 request smuggling
- [ ] Request smuggling to bypass security controls
- [ ] Request smuggling for cache poisoning
- [ ] Request smuggling for web cache deception

### **15.2 HTTP Parameter Pollution**

- [ ] HPP in GET parameters
- [ ] HPP in POST parameters
- [ ] HPP for authentication bypass
- [ ] HPP for CSRF bypass
- [ ] HPP for WAF bypass

### **15.3 Host Header Attacks**

- [ ] Host header injection
- [ ] Password reset poisoning via Host header
- [ ] SSRF via Host header
- [ ] Web cache poisoning via Host header
- [ ] Virtual host bypass

### **15.4 H2C Smuggling**

- [ ] HTTP/1.1 to HTTP/2 upgrade smuggling
- [ ] H2C smuggling to bypass security

### **15.5 Hop-by-Hop Headers**

- [ ] Connection header manipulation
- [ ] Hop-by-hop header abuse

---

## **STAGE 16: Cache Attacks**

### **16.1 Web Cache Poisoning**

- [ ] Cache poisoning via headers
- [ ] Cache poisoning via Host header
- [ ] Cache poisoning via unkeyed parameters
- [ ] Cache poisoning for XSS
- [ ] Cache poisoning for open redirect
- [ ] Fat GET request smuggling

### **16.2 Web Cache Deception**

- [ ] Cache deception for sensitive data exposure
- [ ] Path confusion for cache deception

---

## **STAGE 17: Client-Side Attacks**

### **17.1 Clickjacking**

- [ ] Basic clickjacking
- [ ] Clickjacking with form input
- [ ] Double clickjacking
- [ ] Clickjacking for sensitive actions

### **17.2 postMessage Vulnerabilities**

- [ ] Unrestricted postMessage origin
- [ ] postMessage XSS
- [ ] postMessage data leakage
- [ ] postMessage for authentication bypass

### **17.3 Prototype Pollution**

- [ ] Client-side prototype pollution
- [ ] Prototype pollution to XSS
- [ ] Prototype pollution in Node.js

### **17.4 Tabnabbing**

- [ ] Reverse tabnabbing (window.opener)
- [ ] Target="_blank" without rel="noopener"

### **17.5 DOM Clobbering**

- [ ] DOM clobbering for XSS
- [ ] DOM clobbering for authorization bypass

### **17.6 Cross-Site Script Inclusion (XSSI)**

- [ ] XSSI via JSONP
- [ ] XSSI via JavaScript resources
- [ ] XSSI for data leakage

### **17.7 XS-Leaks (Cross-Site Leaks)**

- [ ] Timing-based XS-Leaks
- [ ] Error-based XS-Leaks
- [ ] Cache-based XS-Leaks
- [ ] Frame counting
- [ ] postMessage-based leaks

---

## **STAGE 18: Open Redirect**

### **18.1 Open Redirect Discovery**

- [ ] Open redirect via URL parameters
- [ ] Open redirect via Referer/Host headers
- [ ] Open redirect in OAuth callbacks
- [ ] Open redirect in SAML
- [ ] Open redirect for phishing

### **18.2 Open Redirect Bypass**

- [ ] Filter bypass with URL encoding
- [ ] Filter bypass with double encoding
- [ ] Bypass with protocol handlers (javascript:, data:)
- [ ] Bypass with @ symbol
- [ ] Bypass with backslash ()
- [ ] Bypass with ///
- [ ] Bypass with whitespace

---

## **STAGE 19: Deserialization Vulnerabilities**

### **19.1 Insecure Deserialization**

- [ ] Java deserialization (ysoserial)
- [ ] PHP deserialization (unserialize)
- [ ] Python pickle deserialization
- [ ] .NET deserialization
- [ ] Ruby deserialization (Marshal, YAML)
- [ ] Node.js deserialization

### **19.2 Exploitation**

- [ ] RCE via deserialization
- [ ] Object injection
- [ ] Type confusion attacks

---

## **STAGE 20: Directory Traversal & LFI/RFI**

### **20.1 Path Traversal**

- [ ] Basic path traversal (../)
- [ ] Path traversal with encoding
- [ ] Path traversal with null bytes
- [ ] Path traversal in file uploads
- [ ] Path traversal in file downloads
- [ ] Windows path traversal (..)

### **20.2 Local File Inclusion (LFI)**

- [ ] LFI to read sensitive files
- [ ] LFI with PHP wrappers (php://filter, data://)
- [ ] LFI to RCE (log poisoning, /proc/self/environ)
- [ ] LFI via path truncation
- [ ] LFI via zip wrapper

### **20.3 Remote File Inclusion (RFI)**

- [ ] RFI to code execution
- [ ] RFI via allow_url_include

---

## **STAGE 21: Rate Limiting & CAPTCHA**

### **21.1 Rate Limiting Bypass**

- [ ] IP rotation bypass
- [ ] Header manipulation (X-Forwarded-For, X-Originating-IP)
- [ ] Method tampering (POST to GET)
- [ ] Null byte in parameters
- [ ] Rate limit bypass via race conditions
- [ ] User-Agent manipulation

### **21.2 CAPTCHA Bypass**

- [ ] CAPTCHA reuse
- [ ] CAPTCHA missing validation
- [ ] CAPTCHA OCR bypass
- [ ] Missing CAPTCHA on critical actions
- [ ] CAPTCHA on client-side only
- [ ] CAPTCHA response manipulation

---

## **STAGE 22: Subdomain Takeover**

### **22.1 Subdomain Takeover Types**

- [ ] AWS S3 bucket takeover
- [ ] GitHub Pages takeover
- [ ] Heroku takeover
- [ ] Azure takeover
- [ ] AWS CloudFront takeover
- [ ] Fastly takeover
- [ ] Shopify takeover
- [ ] Tumblr takeover
- [ ] WordPress.com takeover
- [ ] Ghost.io takeover

---

## **STAGE 23: Broken Link Hijacking**

### **23.1 Detection**

- [ ] Expired domain in external links
- [ ] Expired domain in JavaScript resources
- [ ] Expired domain in CSS resources
- [ ] Dead social media links

---

## **STAGE 24: Technology-Specific Vulnerabilities**

### **24.1 CMS Vulnerabilities**

- [ ] WordPress plugin vulnerabilities
- [ ] WordPress theme vulnerabilities
- [ ] Drupal vulnerabilities
- [ ] Joomla vulnerabilities
- [ ] Magento vulnerabilities
- [ ] Moodle vulnerabilities

### **24.2 Framework Vulnerabilities**

- [ ] Django debug mode
- [ ] Flask debug mode
- [ ] Laravel debug mode
- [ ] PHP info disclosure
- [ ] .NET debug mode
- [ ] Ruby on Rails mass assignment

### **24.3 Server Vulnerabilities**

- [ ] Apache vulnerabilities
- [ ] Nginx vulnerabilities
- [ ] IIS vulnerabilities
- [ ] Tomcat vulnerabilities
- [ ] HAProxy vulnerabilities

### **24.4 Application-Specific**

- [ ] Jenkins vulnerabilities
- [ ] Jira vulnerabilities
- [ ] Confluence vulnerabilities
- [ ] Grafana vulnerabilities
- [ ] Adobe Experience Manager (AEM) vulnerabilities

---

## **STAGE 25: Advanced Topics**

### **25.1 Unicode & Encoding Attacks**

- [ ] Unicode normalization attacks
- [ ] Unicode bypass for filters
- [ ] Homograph attacks
- [ ] Best-fit character mapping
- [ ] UTF-7 XSS

### **25.2 Timing Attacks**

- [ ] Timing attack for user enumeration
- [ ] Timing attack for authentication
- [ ] Blind SQLi via timing
- [ ] Race condition via timing

### **25.3 UUID Security**

- [ ] UUID v1 predictability
- [ ] UUID enumeration
- [ ] UUID information disclosure

### **25.4 MIME Sniffing**

- [ ] MIME sniffing for XSS
- [ ] Missing X-Content-Type-Options

### **25.5 Reflected File Download (RFD)**

- [ ] RFD via content reflection
- [ ] RFD via JSONP

### **25.6 Response Manipulation**

- [ ] Response splitting
- [ ] Response tampering

### **25.7 Denial of Service (DoS)**

- [ ] Application-level DoS
- [ ] Resource exhaustion
- [ ] Regular expression DoS (ReDoS)
- [ ] XML bomb (Billion Laughs)
- [ ] Zip bomb
- [ ] Algorithmic complexity attacks
- [ ] Account lockout DoS

### **25.8 Dependency Issues**

- [ ] Dependency confusion attack
- [ ] Typosquatting in dependencies
- [ ] Outdated dependencies with known CVEs

### **25.9 Web3/DApps Security**

- [ ] Smart contract vulnerabilities
- [ ] Wallet connection hijacking
- [ ] Transaction manipulation
- [ ] Reentrancy attacks
- [ ] Front-running attacks

### **25.10 gRPC-Web Security**

- [ ] gRPC reflection enabled
- [ ] gRPC authentication bypass
- [ ] gRPC injection attacks

---

## **STAGE 26: WAF Bypass Techniques**

### **26.1 Generic WAF Bypass**

- [ ] Encoding bypass (URL, HTML, Unicode)
- [ ] Case variation bypass
- [ ] Comment injection
- [ ] Null byte injection
- [ ] HPP for WAF bypass
- [ ] Chunked encoding
- [ ] Header manipulation
- [ ] Multipart form-data bypass
- [ ] JSON vs Form-data toggle

### **26.2 Specific Attack WAF Bypass**

- [ ] SQLi WAF bypass
- [ ] XSS WAF bypass
- [ ] Command injection WAF bypass
- [ ] Path traversal WAF bypass
