# JWT – JSON Web Token

## What is JWT?
JWT (JSON Web Token) is a **compact, URL-safe token format** used to securely transmit information between parties.

JWT is widely used for:
- Authentication
- Authorization
- Stateless sessions

---

## JWT Structure
A JWT consists of **three Base64URL-encoded parts**, separated by dots (`.`):

```text
Header.Payload.Signature
````

***

### Header

The header defines the token type and signing algorithm.

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

***

### Payload

The payload contains **claims** (information).

```json
{
  "sub": "123",
  "username": "mohit",
  "iat": 1700000000,
  "exp": 1710000000
}
```

⚠️ Payload is **readable**, not encrypted.

***

### Signature

The signature ensures:

*   Data integrity
*   Token authenticity

The signature is created using:

*   Header
*   Payload
*   Secret key or private key

***

## How JWT Works

1.  User logs in successfully
2.  Server generates a JWT
3.  Token is signed
4.  Client stores the token
5.  Client sends token with every request
6.  Server verifies the signature

JWT is **stateless** — no server-side session storage.

***

## Common JWT Security Problems

JWT is not broken, but **easy to misuse**.

❌ Algorithm confusion attacks  
❌ Weak signature validation  
❌ Insecure storage (localStorage misuse)  
❌ Payload often mistaken as encrypted

Security depends entirely on **correct implementation**.

***

## Key Takeaway

✅ JWT is powerful and flexible  
❌ JWT allows dangerous configurations

➡️ These risks motivated the creation of **PASETO**
