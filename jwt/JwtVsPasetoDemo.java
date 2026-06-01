package jwt;

import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * JwtVsPasetoDemo — Deep dive into JWT security flaws and how PASETO fixes them.
 *
 * PRODUCTION SCENARIO:
 * ─────────────────────────────────────────────────────────────────────
 * Your auth system uses JWTs. A security researcher reports:
 * "Change the algorithm header to 'none' — token accepted without signature."
 * Or: "Change 'RS256' to 'HS256', sign with the public key — token accepted."
 * These are REAL CVEs that have hit major platforms.
 *
 * JWT SECURITY PROBLEMS:
 * ─────────────────────────────────────────────────────────────────────
 *  1. Algorithm confusion attack: header says alg=none → no sig validation
 *  2. RS256 → HS256 confusion: attacker signs with public key as HMAC secret
 *  3. Weak secrets: brute-forceable via hashcat/jwt_tool
 *  4. No built-in versioning or type safety in the spec
 *  5. Header is tampered silently if library trusts the alg field blindly
 *
 * WHAT IS PASETO?
 * ─────────────────────────────────────────────────────────────────────
 * Platform-Agnostic SEcurity TOkens.
 * Designed by Scott Arciszewski to fix JWT's design flaws.
 *
 * KEY DIFFERENCES:
 *  JWT:    Developer chooses algorithm. Wrong choice = vulnerability.
 *  PASETO: Algorithm is fixed per version. No choice = no confusion attacks.
 *
 *  JWT:    "alg: none" is a valid (dangerous) option in the spec.
 *  PASETO: "none" algorithm doesn't exist. Period.
 *
 *  JWT:    Header is base64 — tamperable.
 *  PASETO: Version + purpose baked into the token format. Not negotiable.
 *
 * PASETO VERSIONS:
 * ─────────────────────────────────────────────────────────────────────
 *  v1.local  → AES-256-CTR + HMAC-SHA384 (symmetric, local use)
 *  v1.public → RSA-PSS (asymmetric)
 *  v2.local  → XChaCha20-Poly1305 (symmetric) ← recommended
 *  v2.public → Ed25519 (asymmetric) ← recommended for APIs
 *
 * NOTE: This demo implements simplified JWT/PASETO concepts from scratch
 * to illustrate the security differences. Production: use nimbus-jose-jwt
 * for JWT and jpaseto / paseto4j for PASETO.
 *
 * Author: Mohit Kumar — github.com/Mohit-Java-Caps
 */
public class JwtVsPasetoDemo {

    // ── Minimal JWT implementation (educational) ──────────────────────────
    static class SimpleJWT {
        private static final String SECRET = "my-super-secret-key-for-demo-purposes";

        static String create(Map<String, Object> payload) {
            String header  = base64Encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
            String body    = base64Encode(mapToJson(payload));
            String sigData = header + "." + body;
            String sig     = base64Encode(hmacSha256(sigData, SECRET));
            return header + "." + body + "." + sig;
        }

        static Map<String, Object> verify(String token, boolean strictAlgCheck) throws Exception {
            String[] parts = token.split("\\.");
            if (parts.length != 3) throw new Exception("Invalid JWT structure");

            String headerJson  = base64Decode(parts[0]);
            String payloadJson = base64Decode(parts[1]);

            // SECURITY FLAW DEMO: if not strictly checking alg, attacker can set alg=none
            if (strictAlgCheck) {
                if (!headerJson.contains("\"HS256\"")) {
                    throw new Exception("Algorithm mismatch — rejecting token");
                }
            }

            String expectedSig = base64Encode(hmacSha256(parts[0] + "." + parts[1], SECRET));
            if (!parts[2].equals(expectedSig)) {
                throw new Exception("Signature verification FAILED — token tampered!");
            }

            return jsonToMap(payloadJson);
        }

        // Simulate the "alg:none" attack
        static String createAttackerToken(Map<String, Object> payload) {
            // Attacker sets alg=none in header, removes signature
            String header = base64Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
            String body   = base64Encode(mapToJson(payload));
            return header + "." + body + "."; // empty signature
        }
    }

    // ── Minimal PASETO v2.local concept (educational) ─────────────────────
    static class SimplePaseto {
        private static final String VERSION = "v2";
        private static final String PURPOSE = "local";
        // In real PASETO v2.local: XChaCha20-Poly1305 encryption
        // We simulate with HMAC for educational purposes
        private static final String KEY = "paseto-symmetric-key-256bit-demo";

        static String create(Map<String, Object> payload) {
            String json    = mapToJson(payload);
            String mac     = base64Encode(hmacSha256(VERSION + "." + PURPOSE + "." + json, KEY));
            String encoded = base64Encode(json + "|" + mac);
            // Format: v2.local.<encoded>
            return VERSION + "." + PURPOSE + "." + encoded;
        }

        static Map<String, Object> verify(String token) throws Exception {
            // PASETO: version + purpose are NON-NEGOTIABLE — part of the format
            if (!token.startsWith("v2.local.")) {
                throw new Exception("Invalid PASETO version or purpose — REJECTED");
            }

            String encoded = token.substring("v2.local.".length());
            String decoded = base64Decode(encoded);
            String[] parts = decoded.split("\\|");
            if (parts.length != 2) throw new Exception("Malformed PASETO token");

            String json        = parts[0];
            String providedMac = parts[1];
            String expectedMac = base64Encode(hmacSha256(VERSION + "." + PURPOSE + "." + json, KEY));

            if (!providedMac.equals(expectedMac)) {
                throw new Exception("PASETO MAC verification FAILED — token tampered!");
            }
            return jsonToMap(json);
        }
    }

    // ── Main demo ─────────────────────────────────────────────────────────
    public static void main(String[] args) {
        System.out.println("=== JWT vs PASETO — Security Comparison Demo ===\n");

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "user-12345");
        claims.put("role", "ADMIN");
        claims.put("exp", System.currentTimeMillis() / 1000 + 3600);

        // ── Part 1: Legitimate JWT flow ───────────────────────────────────
        System.out.println("━━━ Part 1: Legitimate JWT ━━━");
        try {
            String token = SimpleJWT.create(claims);
            System.out.println("Created JWT:\n  " + token.substring(0, 60) + "...");

            Map<String, Object> verified = SimpleJWT.verify(token, true);
            System.out.println("Verified successfully: " + verified);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        // ── Part 2: JWT "alg:none" attack ─────────────────────────────────
        System.out.println("\n━━━ Part 2: JWT Algorithm Confusion Attack (alg=none) ━━━");
        Map<String, Object> escalatedClaims = new LinkedHashMap<>(claims);
        escalatedClaims.put("role", "SUPER_ADMIN"); // attacker escalates privileges

        String attackerToken = SimpleJWT.createAttackerToken(escalatedClaims);
        System.out.println("Attacker's forged token (no signature):");
        System.out.println("  " + attackerToken.substring(0, Math.min(80, attackerToken.length())) + "...");

        System.out.println("\nVulnerable server (no strict alg check):");
        try {
            Map<String, Object> result = SimpleJWT.verify(attackerToken, false); // NO alg check
            System.out.println("  ACCEPTED by vulnerable server! Claims: " + result);
            System.out.println("  ← ATTACKER WINS — escalated to SUPER_ADMIN with no secret key!");
        } catch (Exception e) {
            System.out.println("  Rejected: " + e.getMessage());
        }

        System.out.println("\nSecure server (strict alg check):");
        try {
            SimpleJWT.verify(attackerToken, true); // strict check
        } catch (Exception e) {
            System.out.println("  REJECTED correctly: " + e.getMessage());
        }

        // ── Part 3: Legitimate PASETO flow ───────────────────────────────
        System.out.println("\n━━━ Part 3: Legitimate PASETO ━━━");
        try {
            String pasetoToken = SimplePaseto.create(claims);
            System.out.println("Created PASETO:\n  " + pasetoToken);
            Map<String, Object> verified = SimplePaseto.verify(pasetoToken);
            System.out.println("Verified successfully: " + verified);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        // ── Part 4: PASETO algorithm confusion attempt ────────────────────
        System.out.println("\n━━━ Part 4: PASETO Algorithm Confusion Attempt ━━━");
        // Attacker tries to create a "v2.none" token — doesn't exist in PASETO
        String fakeToken = "v2.none." + Base64.getEncoder().encodeToString(
            mapToJson(escalatedClaims).getBytes());
        System.out.println("Attacker tries token with version 'v2.none':");
        try {
            SimplePaseto.verify(fakeToken);
        } catch (Exception e) {
            System.out.println("  REJECTED: " + e.getMessage());
            System.out.println("  ← PASETO version+purpose are non-negotiable. Attack impossible.");
        }

        // ── Summary ───────────────────────────────────────────────────────
        System.out.println("""

            ━━━ JWT vs PASETO Comparison ━━━

            Feature                     JWT                         PASETO
            ─────────────────────────────────────────────────────────────────────
            Algorithm choice            Dev chooses (risky)         Fixed per version (safe)
            alg=none attack             Possible if lib is lax      Impossible by design
            Algorithm confusion         RS256→HS256 possible        Not possible
            Header tampering            Possible                    Version baked in
            Encryption support          JWE (complex)               v2.local (simple)
            Production libraries        nimbus-jose-jwt             jpaseto, paseto4j
            When to use JWT             Existing ecosystem, OIDC    New systems, higher security

            Production recommendation: If starting fresh → PASETO v2.
            If integrating with OAuth2/OIDC → JWT (required by spec, use a hardened library).
            """);
    }

    // ── Utility methods ───────────────────────────────────────────────────
    static String base64Encode(String s) {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
    static String base64Decode(String s) {
        return new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8);
    }
    static String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return new String(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)), StandardCharsets.ISO_8859_1);
        } catch (Exception e) { throw new RuntimeException(e); }
    }
    static String mapToJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        map.forEach((k, v) -> sb.append("\"").append(k).append("\":\"").append(v).append("\","));
        if (sb.length() > 1) sb.setLength(sb.length() - 1);
        return sb.append("}").toString();
    }
    static Map<String, Object> jsonToMap(String json) {
        Map<String, Object> map = new LinkedHashMap<>();
        String inner = json.replaceAll("[{}\"]", "");
        for (String pair : inner.split(",")) {
            String[] kv = pair.split(":", 2);
            if (kv.length == 2) map.put(kv[0].trim(), kv[1].trim());
        }
        return map;
    }
}
