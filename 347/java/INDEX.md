# CWE-347: Improper Verification of Cryptographic Signature - Java

## LLM Guidance

Java JWT libraries are vulnerable to algorithm confusion when verification code lets the token's own header (`alg`) pick the algorithm or key type used to verify it - an attacker can switch a token from RS256 to HS256 and sign it with the server's RSA public key treated as an HMAC secret. Prevent this by pinning the expected algorithm and key type explicitly, using Nimbus JOSE+JWT's `JWSKeySelector` (or `io.jsonwebtoken`/jjwt's strongly-typed `verifyWith(PublicKey)`/`verifyWith(SecretKey)` overloads), never a generic `Key` resolved from the header. For non-JWT signatures such as webhook payloads, compute the expected HMAC and compare it with a constant-time function (`MessageDigest.isEqual()`), never `String.equals()` or `Arrays.equals()`.

## Key Principles

- Pin the exact verification algorithm and key type; never let the token header, a custom `SigningKeyResolver`, or a JWKS lookup select the algorithm family based on attacker input
- With Nimbus JOSE+JWT, configure `ConfigurableJWTProcessor.setJWSKeySelector()` with a `SingleKeyJWSKeySelector` (or `JWSVerificationKeySelector` for a JWKS) bound to one algorithm; with jjwt, call `Jwts.parser().verifyWith(rsaPublicKey)` using a strongly-typed `PublicKey`/`SecretKey`, never a raw byte array cast to satisfy both
- Never build a key resolver that reads `header.getAlgorithm()` and returns HMAC secret bytes when the header claims HS256, or an RSA key when it claims RS256, without first checking the algorithm against a fixed expectation
- Reject `alg: none` and weak algorithms (MD5/SHA-1 based); only accept RS256/PS256/ES256 or the specific algorithm your issuer uses
- Use `MessageDigest.isEqual(byte[], byte[])` for any raw signature or HMAC comparison - never `String.equals()`, `==`, or `Arrays.equals()`, none of which are constant-time
- Validate issuer, audience, and expiration in addition to the signature

## Remediation Steps

- Locate - find `Jwts.parser()`/`JwtParserBuilder`, `SignedJWT.verify()`, `ConfigurableJWTProcessor`, or custom `Mac`/`Signature` verification code
- Trace data flow - identify anywhere the token header or an attacker-controlled field selects the verification algorithm or key type
- Replace the unsafe pattern - remove custom `SigningKeyResolver`/key-selection logic that branches on the header's `alg`; configure a fixed `JWSKeySelector` (Nimbus) or typed key (jjwt) instead
- Bind, encode, validate, or authorize - resolve signing keys by `kid` only against a trusted, server-side keystore or JWKS, and pin the algorithm the resolved key is allowed to use
- Harden configuration - explicitly reject `none` and disallow mixing symmetric and asymmetric algorithms for the same endpoint
- Test - craft a token re-signed as HS256 using the known RSA public key as the HMAC secret and confirm verification fails; add a test for the webhook comparison path

## Safe Pattern

```java
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// SAFE: algorithm and key are pinned server-side, not read from the token header
ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
JWSKeySelector<SecurityContext> keySelector =
    new SingleKeyJWSKeySelector<>(JWSAlgorithm.RS256, rsaPublicKey);
jwtProcessor.setJWSKeySelector(keySelector);
JWTClaimsSet claims = jwtProcessor.process(token, null); // throws BadJOSEException on any mismatch

// SAFE: webhook HMAC-SHA256 verification with constant-time comparison
Mac mac = Mac.getInstance("HmacSHA256");
mac.init(new SecretKeySpec(webhookSecret, "HmacSHA256"));
byte[] expected = mac.doFinal(requestBody);
byte[] provided = hexDecode(signatureHeader);
if (!MessageDigest.isEqual(expected, provided)) {
    throw new SecurityException("Invalid webhook signature");
}
```
