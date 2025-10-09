# Notes-X 

---

## 🎯 **1. Target Overview**

- **Main domain:** example.com
- **Scope:** *.example.com, api.example.com, etc.
- **Out of scope:** Don't waste time here
- **Program type:** Public/Private/VDP
- **Payout range:** Know your motivation

---

## 🌐 **2. Subdomains & Assets**

Track everything:

- **Live subdomains:** admin.example.com, dev.example.com, staging.example.com
- **Dead/unresponsive subdomains:** For future monitoring
- **Takeover candidates:** Dangling CNAMEs, unclaimed S3 buckets
- **IPs & ASN:** Group by network blocks
- **CDN/WAF detected:** Cloudflare, Akamai, AWS Shield?

**Pro tip:** Note patterns like `staging-`, `dev-`, `test-`, `backup-` — these are goldmines.

---

## 🔍 **3. Technologies Detected**

- **Web server:** Nginx, Apache, IIS
- **Backend:** PHP, Node.js, Python (Flask/Django), Ruby, Java
- **Framework:** Laravel, Express, Spring Boot, Rails
- **CMS:** WordPress, Joomla, Drupal (+ version!)
- **Frontend:** React, Vue, Angular
- **Database hints:** MySQL, PostgreSQL, MongoDB
- **Cloud provider:** AWS, GCP, Azure
- **JS libraries:** jQuery, Lodash, Moment.js (check for outdated versions)

**Why this matters:** Known CVEs, default configs, common misconfigs.

---

## 🚪 **4. Ports & Services**

- **Open ports:** 22 (SSH), 80/443 (HTTP/HTTPS), 3306 (MySQL), 8080, etc.
- **Service versions:** OpenSSH 7.4, Apache 2.4.29
- **Unusual ports:** 8888, 9090, 4444 → potential admin panels or debug endpoints
- **Banner info:** Anything leaking version/OS details

---

## 📂 **5. Directories & Endpoints**

Group by type:

- **Interesting dirs:** `/admin`, `/backup`, `/api`, `/v1`, `/v2`, `/dev`, `/test`, `/config`
- **Exposed files:** `.git`, `.env`, `config.php`, `backup.zip`, `.DS_Store`, `phpinfo.php`
- **API endpoints:** `/api/v1/users`, `/graphql`, `/swagger.json`
- **Upload endpoints:** `/upload`, `/media/upload`, `/avatar`
- **Login pages:** `/login`, `/admin/login`, `/wp-admin`

**Color code:** High-value targets (red), medium (yellow), low (gray).

---

## 🔑 **6. Credentials & Leaks**

- **GitHub leaks:** API keys, AWS secrets, DB passwords
- **Pastebin/Trello/Jira dumps:** Search target name + "password", "API key"
- **Breach databases:** Check emails from domain
- **Default creds:** Admin:admin, root:root, test:test

---

## 📜 **7. JavaScript Analysis**

JS files reveal SO much:

- **API endpoints:** Hidden or undocumented routes
- **Hardcoded secrets:** API keys, tokens, internal URLs
- **Logic flaws:** Client-side validation you can bypass
- **Debug code:** Console logs, commented-out features
- **Internal IPs/domains:** `api-internal.example.com`

**Tools:** LinkFinder, JSParser, or manual grep for keywords like `api`, `token`, `password`, `secret`.

---

## 📧 **8. Emails & Users**

- **Email format:** firstname.lastname@example.com or flastname@example.com?
- **Found emails:** List for password reset testing, phishing scope, LinkedIn recon
- **User enumeration:** Possible via login, registration, forgot password?

---

## 🧩 **9. Parameters & Forms**

Track every input:

- **GET params:** `?id=`, `?user=`, `?file=`, `?redirect=`
- **POST params:** From forms, API calls
- **Hidden params:** Discovered via fuzzing (Arjun, ParamSpider)
- **Interesting params:** Anything with `admin`, `debug`, `test`, `internal`, `callback`, `url`

**Why:** These are your injection points for SQLi, XSS, IDOR, SSRF.

---

## 🛡️ **10. WAF & Security Measures**

- **WAF detected:** Cloudflare, AWS WAF, Akamai, Sucuri
- **Rate limiting:** How many requests before block?
- **CAPTCHA:** Where is it enforced? Where is it missing?
- **Security headers:** Missing CSP, X-Frame-Options, HSTS?

**Strategy:** Know your limits, rotate IPs if needed, craft payloads that bypass WAF.

---

## 📸 **11. Screenshots & Evidence**

- **Interesting pages:** Admin panels, debug info, error messages
- **Evidence for reports:** Always screenshot before reporting

---

## 🗂️ **12. Wayback Machine Findings**

- **Old endpoints:** Deprecated APIs, removed admin panels
- **Parameter history:** Old params that might still work
- **Backup files:** `.bak`, `.old`, `.backup` that were exposed before

---

## 🧠 **13. Attack Surface Summary**

After recon, summarize your **top targets**:

1. **File upload on** `/upload` (no validation?)
2. **API endpoint** `/api/v1/users` (IDOR potential?)
3. **Admin panel** `admin.example.com` (default creds?)
4. **Forgot password** (weak token? user enum?)