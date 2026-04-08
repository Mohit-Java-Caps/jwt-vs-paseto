
# PASETO Example – Secure by Default Token

This example shows how **PASETO** handles tokens using **safe defaults** and **modern cryptography**.

---

## Scenario
A user logs in successfully.  
The server issues a **PASETO token** which is safe by design.

---

## Example PASETO (Local Token)

```text
v4.local.QWxhZGRpbjpvcGVuIHNlc2FtZQ
````

*   `v4` → Token version
*   `local` → Encrypted token
*   Payload is **confidential**

***

## What Makes This Secure?

✅ Payload is **encrypted**, not readable  
✅ Algorithm is fixed (no confusion)  
✅ Strong cryptography enforced

Developers **cannot choose insecure options**.

***

## PASETO Token Types

### Local (Encrypted)

*   Used when payload secrecy is required
*   Uses symmetric encryption

### Public (Signed)

*   Uses asymmetric cryptography
*   Payload readable, but cannot be tampered with

***

## How PASETO Is Used

1.  Client logs in
2.  Server creates PASETO token
3.  Token is encrypted or signed
4.  Client stores token
5.  Server validates token safely

No algorithm selection.  
No insecure mode.

***

## PASETO vs JWT (in Practice)

✅ No algorithm confusion  
✅ No weak crypto  
✅ Safe defaults enforce best practices

❌ Less flexibility (by design)

***

## Key Takeaway

✅ PASETO removes crypto foot‑guns  
✅ Security is enforced by design

➡️ **PASETO is ideal for new, security‑critical systems**
