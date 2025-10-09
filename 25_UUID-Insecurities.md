## Overview

Universally Unique Identifiers (UUIDs) are **128-bit numbers used to uniquely identify information** in computer systems. They are essential in applications where unique identifiers are necessary without central coordination. UUIDs are commonly used as database keys and can refer to various elements like documents, sessions, and other resources.

### UUID Structure

UUIDs are structured in a specific format, divided into five groups represented as 32 hexadecimal digits:

```
xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx
```

**Example:**

```
12345678-abcd-1a56-a539-103755193864
```

- The **position of M** indicates the UUID **version** (e.g., `1` for UUID v1)
- The **position of N** indicates the UUID **variant**

### UUID Versions

UUIDs are designed to be unique and hard to guess, but different versions have varying security characteristics:

- **UUID v1**: Time-based, incorporating timestamp, clock sequence, and node ID (MAC address). Can potentially expose system information and is predictable.
- **UUID v2**: Similar to v1 but includes modifications for local domains (not widely used).
- **UUID v3**: Generated using MD5 hash values from namespace and name.
- **UUID v4**: Generated almost entirely randomly, providing high anonymity but with slight risk of duplicates.
- **UUID v5**: Generated using SHA-1 hash values from namespace and name.

## Exploitation Methods

### Sandwich Attack

The Sandwich Attack exploits the **predictability of UUID v1 generation**, particularly in time-sensitive features like password resets. Since UUID v1 is generated based on time, clock sequence, and the node's MAC address, an attacker can predict UUIDs generated close in time.

#### Attack Steps

**1. Initial Setup**

- Attacker controls two email accounts: `attacker1@acme.com` and `attacker2@acme.com`
- Target account: `victim@acme.com`

**2. Execution Phase**

- Trigger password reset for first attacker account (`attacker1@acme.com`)
- Receive reset link with UUID: `99874128-7592-11e9-8201-bb2f15014a14`
- Immediately trigger password reset for victim account (`victim@acme.com`)
- Quickly trigger password reset for second attacker account (`attacker2@acme.com`)
- Receive reset link for second account with UUID: `998796b4-7592-11e9-8201-bb2f15014a14`

**3. Analysis Phase**

- Two UUIDs generated close in time are now known
- The victim's UUID will likely fall between these two values due to sequential time-based generation

**4. Brute Force Attack**

- Generate all possible UUIDs between the two known values
- Test each generated UUID by attempting to access password reset links
- Format: `https://www.acme.com/reset/<generated-UUID>`
- If rate limiting is absent or insufficient, quickly test all possibilities

**5. Access Gained**

- Once correct UUID is discovered, reset victim's password
- Gain unauthorized access to victim's account

#### Detection Checks

**Identify UUID Version:**

```
Check the version digit (M position) in the UUID format
xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx

If M = 1, the application uses UUID v1 (vulnerable to sandwich attack)
```

**Verify Predictability:**

1. Request multiple tokens/UUIDs in quick succession
2. Analyze the timestamp component
3. Check if UUIDs are sequential or time-based
4. Calculate the gap between consecutive UUIDs

**Test for Rate Limiting:**

1. Attempt multiple password reset requests
2. Try accessing multiple UUID-based URLs rapidly
3. Check if the application blocks or throttles requests

### Tools

**Automated Sandwich Attack:**

- [Sandwich Attack Tool](https://github.com/Lupin-Holmes/sandwich) - Automates the sandwich attack process

**UUID Detection:**

- [UUID Detector (Burp Suite Extension)](https://portswigger.net/bappstore/65f32f209a72480ea5f1a0dac4f38248) - Identifies UUID types in HTTP traffic

## Higher Impact Scenarios

### Password Reset Takeover

- Exploit UUID v1 in password reset tokens to gain unauthorized account access
- No user interaction required beyond initial reset request
- Complete account compromise possible

### Session Hijacking

- Predict session tokens based on UUID v1
- Take over active user sessions
- Bypass authentication mechanisms

### API Key Prediction

- Guess API keys generated using UUID v1
- Access protected endpoints and sensitive data
- Perform actions on behalf of other users

### Document/Resource Access

- Predict UUIDs used as document identifiers
- Access confidential files and resources
- Enumerate all resources in the system

### Multi-Tenant Data Leakage

- In multi-tenant applications, predict UUIDs to access other tenants' data
- Cross-tenant data breaches
- Complete isolation bypass

## Mitigations

### Use Secure UUID Versions

- **Prefer UUID v4**: Cryptographically random generation eliminates predictability
- Avoid UUID v1 for security-sensitive identifiers
- Consider UUID v5 with proper namespace and name salting for deterministic but secure UUIDs

### Implement Rate Limiting

- Limit password reset requests per IP/account
- Throttle access attempts to UUID-based resources
- Implement progressive delays after failed attempts

### Add Additional Security Layers

- Use UUID in combination with other authentication factors
- Implement HMAC signatures alongside UUIDs
- Add time-based expiration for sensitive tokens
- Require email confirmation for critical actions

### Access Control Validation

- Always validate user permissions server-side
- Never rely solely on UUID secrecy for authorization
- Implement proper session management

### Monitoring and Detection

- Log and monitor unusual patterns of UUID access attempts
- Alert on rapid sequential UUID guessing attempts
- Implement anomaly detection for brute force attacks

### Token Complexity

- For critical operations, use longer tokens (256-bit or more)
- Combine multiple random components
- Use cryptographically secure random number generators (CSPRNG)

## References

- [VerSprite: Universally Unique Identifiers](https://versprite.com/blog/universally-unique-identifiers/)