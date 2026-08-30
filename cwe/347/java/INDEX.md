# CWE-347: Improper Verification of Cryptographic Signature - Java

## LLM Guidance

Java JWT libraries are vulnerable to algorithm confusion when verification code lets the token's own header (`alg`) pick the algorithm or key type used to verify it - an attacker can switch a token from RS256 to HS256 and sign it with the server's RSA public key treated as an HMAC secret. Prevent this by pinning the expected algorithm and key type explicitly, using Nimbus JOSE+JWT's `JWSKeySelector` (or `io.jsonwebtoken`/jjwt's strongly-typed `verifyWith(PublicKey)`/`verifyWith(SecretKey)` overloads), never a generic `Key` resolved from the header. For non-JWT signatures such as webhook payloads, compute the expected HMAC and compare it with a constant-time function (`MessageDigest.isEqual()`), never `String.equals()` or `Arrays.equals()`.

## Key Principles

- Pin the exact verification algorithm and key type; never let the token header, a custom `SigningKeyResolver`, or a JWKS lookup select the algorithm family based on attacker input
- With Nimbus JOSE+JWT, configure `ConfigurableJWTProcessor.setJWSKeySelector()` (implementation `DefaultJWTProcessor`) with a `SingleKeyJWSKeySelector` (or `JWSVerificationKeySelector` for a JWKS) bound to one algorithm; with jjwt **0.12.0+**, call `Jwts.parser().verifyWith(rsaPublicKey)` using a strongly-typed `PublicKey`/`SecretKey`, never a raw byte array cast to satisfy both
- jjwt before 0.12.0 used `Jwts.parserBuilder().setSigningKey(key)`, where the library picked the verification algorithm from the key's byte length rather than pinning it (jjwt issue #707) - upgrading the dependency is part of the fix, not just switching call syntax
- `verifyWith()` pins the *key*, not the algorithm - jjwt still reads which algorithm to run from the token's own header and only requires that the resolved key suit it, so a token re-signed RS512 verifies against a `verifyWith(rsaPublicKey)` handler that only ever issues RS256. Keep the parsed `Jws<Claims>` and assert `getHeader().getAlgorithm()` equals the one expected algorithm after parsing, the same way the other libraries in this CWE need the algorithm pinned independently of the key
- Never build a key resolver that reads `header.getAlgorithm()` and returns HMAC secret bytes when the header claims HS256, or an RSA key when it claims RS256, without first checking the algorithm against a fixed expectation
- Reject `alg: none` and weak algorithms (MD5/SHA-1 based); only accept RS256/PS256/ES256 or the specific algorithm your issuer uses
- Use `MessageDigest.isEqual(byte[], byte[])` for any raw signature or HMAC comparison - never `String.equals()`, `==`, or `Arrays.equals()`, none of which are constant-time (this method itself was only made constant-time in JDK 6u17, fixing CVE-2009-3875 - irrelevant on any currently supported JDK, but a reason to distrust the same pattern on an unrelated hand-rolled comparison)
- Validate issuer, audience, and expiration in addition to the signature
- Fix the key before parsing: `parseClaimsJws()`/`parseSignedClaims()` with a key set in the builder verifies, while a `SigningKeyResolver` that picks the key from the token's own header lets the token choose how it is verified
- Pin the algorithm rather than reading it from the header, and treat `UnsupportedJwtException`/`SignatureException` as rejection paths rather than as conditions to log and continue
- For XML, `XMLSignature.validate()` returning true is not the end of it: confirm the validated `Reference` covers the element you go on to read, or a signature over a different part of the document passes while the data you use is unsigned
- `Signature.verify()` returns a boolean rather than throwing - an unchecked call is indistinguishable from a successful verification

## Taint Sinks

`Jwts.parser()` without pinned `verifyWith()`, `Jwts.parser().verifyWith()` whose result is trusted without a follow-up `getHeader().getAlgorithm()` check, `SignedJWT.verify()`, `SigningKeyResolver` branching on header `alg`, `String.equals()`/`Arrays.equals()` on signatures

## Remediation Steps

- Locate - find `Jwts.parser()`/`JwtParserBuilder`, `SignedJWT.verify()`, `ConfigurableJWTProcessor`, or custom `Mac`/`Signature` verification code
- Trace data flow - identify anywhere the token header or an attacker-controlled field selects the verification algorithm or key type
- Replace the unsafe pattern - remove custom `SigningKeyResolver`/key-selection logic that branches on the header's `alg`; configure a fixed `JWSKeySelector` (Nimbus) or typed key (jjwt) instead
- Bind, encode, validate, or authorize - resolve signing keys by `kid` only against a trusted, server-side keystore or JWKS, and pin the algorithm the resolved key is allowed to use; with jjwt, add the post-parse `getHeader().getAlgorithm()` check even after switching to `verifyWith()`, since that call alone pins the key but not the algorithm
- Harden configuration - explicitly reject `none` and disallow mixing symmetric and asymmetric algorithms for the same endpoint
- Test - craft a token re-signed as HS256 using the known RSA public key as the HMAC secret and confirm verification fails; add a test for the webhook comparison path
