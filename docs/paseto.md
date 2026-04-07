# PASETO – Platform‑Agnostic Security Tokens

## What is PASETO?
PASETO (Platform‑Agnostic Security Tokens) is a **secure alternative to JWT**, designed to prevent common security mistakes.

> PASETO focuses on **safe defaults** instead of flexibility.

---

## Why PASETO Was Created
JWT allows:
- Too many algorithms
- Optional insecure modes
- Easy misconfiguration

PASETO was designed to:
- Remove insecure options
- Enforce modern cryptography
- Make misuse difficult by design

---

## PASETO Token Types

### Local Tokens (Encrypted)
- Symmetric encryption
- Payload is **not readable**
- Used when confidentiality is required

Example:
```text
v4.local.<encrypted-payload>
````

***

### Public Tokens (Signed)

*   Asymmetric cryptography
*   Payload is readable but secure

Example:

```text
v4.public.<signed-payload>
```

***

## PASETO Versions

Each version locks cryptographic choices.

Examples:

```text
v1
v2
v3
v4
```

✅ No algorithm confusion  
✅ No weak cryptography  
✅ Versioned security guarantees

***

## How PASETO Works

1.  Server issues token
2.  Token is encrypted or signed
3.  Client stores token
4.  Server validates token using strict rules

***

## Key Takeaway

✅ Secure by default  
✅ Hard to misuse  
❌ Less configurable than JWT  
❌ Smaller ecosystem (growing)
