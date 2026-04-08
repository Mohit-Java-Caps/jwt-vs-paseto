
# JWT Example – Stateless Authentication Token

This example shows how a **JWT is created, sent, and validated** in a typical authentication flow.

---

## Scenario
A user logs in successfully.  
The server issues a JWT, which the client sends with every subsequent request.

---

## Example JWT Format

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJzdWIiOiIxMjMiLCJ1c2VybmFtZSI6Im1vaGl0IiwiZXhwIjoxNzEwMDAwMDAwfQ
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
````

JWT has **three parts**, separated by dots.

***

## JWT Header (Decoded)

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

✅ Defines the signing algorithm  
❌ Algorithm choice depends on developer

***

## JWT Payload (Decoded)

```json
{
  "sub": "123",
  "username": "mohit",
  "exp": 1710000000
}
```

⚠️ Payload is **Base64‑encoded, NOT encrypted**  
Anyone possessing the token can **read this data**.

***

## JWT Signature

*   Created using secret or private key
*   Ensures token integrity
*   Prevents tampering

But security depends on:

*   Correct algorithm validation
*   Proper key management

***

## How JWT Is Used

1.  Client logs in
2.  Server returns JWT
3.  Client stores token (cookie / memory)
4.  Client sends token in header:

```http
Authorization: Bearer <JWT>
```

5.  Server verifies signature
6.  Request is authorized

***

## JWT Risks (Very Important)

❌ Algorithm confusion  
❌ Misconfigured validation  
❌ Token stored insecurely  
❌ Payload mistaken as encrypted

JWT is **powerful but dangerous if misused**.

***

## Key Takeaway

✅ JWT enables stateless authentication  
❌ JWT allows insecure configurations

➡️ These risks led to **PASETO**
