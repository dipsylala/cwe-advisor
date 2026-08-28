# CWE-502: Deserialization of Untrusted Data - Java

## LLM Guidance

Insecure deserialization occurs when untrusted data is used to create objects, potentially allowing attackers to execute arbitrary code, manipulate application logic, or achieve denial of service. Java's native serialization is particularly dangerous because it can invoke methods during deserialization.

**Primary Defence:** Use JSON (Jackson, Gson) instead of Java serialization, or if Java serialization is required, implement `ObjectInputFilter` (Java 9+) to allowlist permitted classes, or `ValidatingObjectInputStream` (Apache Commons IO) for earlier versions.

## Key Principles

- Prefer data-only formats: Replace Java serialization with JSON, Protocol Buffers, or other data-only formats that don't execute code during deserialization
- Jackson's `ObjectMapper` is safe by default, but not unconditionally: enabling polymorphic typing (`@JsonTypeInfo`, `ObjectMapper.enableDefaultTyping()`) reintroduces gadget-chain risk by letting the input dictate the concrete class to instantiate - avoid it for untrusted input, or pair it with a strict base-type allowlist
- Allowlist classes explicitly: If Java serialization is unavoidable, use `ObjectInputFilter` (Java 9+) or `ValidatingObjectInputStream` (Apache Commons IO) to allow only specific, known-safe classes. The filter callback returns one of three values: `Status.ALLOWED` for a permitted class, `Status.REJECTED` for anything else, and `Status.UNDECIDED` only for the calls where `filterInfo.serialClass()` is null - those carry the array-length, depth, and stream-size limits rather than a class
- Never trust serialized data: Treat all serialized input as untrusted, even from seemingly secure sources
- Avoid known-unsafe libraries: `XMLDecoder` has no safe configuration and must be replaced. XStream's allowlist framework (`XStream.addPermission()` / `setupDefaultSecurity()`) is available from v1.4.7 but must be explicitly configured; it is only enabled by default from v1.4.18 onward. Versions before 1.4.7, or later versions left unconfigured, are exploitable. 1.4.18 is where the default changed, not the version to land on: the operative floor is 1.4.21, which fixes CVE-2024-47072, a stack-overflow denial of service reachable through `BinaryStreamDriver`
- Apply defence in depth: Combine multiple controls including input validation, least privilege, and monitoring
- An `ObjectInputFilter` allowlist must include the container types the payload legitimately uses (`java.util.ArrayList`, `[Ljava.lang.Object;`), or valid traffic is rejected while the filter looks correct
- `setRegistrationRequired(true)` in Kryo (and the equivalent in other binary serializers) refuses any class not explicitly registered, which is the same allowlist idea one layer up
- `readResolve()`/`readObject()` run during reconstruction, so validation placed in a constructor never executes on a deserialized instance

## Taint Sinks

`ObjectInputStream.readObject()`, `XMLDecoder.readObject()`, `XStream.fromXML()`, `ObjectMapper.enableDefaultTyping()`/`@JsonTypeInfo`

## Remediation Steps

- Replace `ObjectInputStream` with JSON parsers like Jackson or Gson for data transfer
- If Java serialization is unavoidable, implement `ObjectInputFilter` (Java 9+) with an explicit per-class allowlist; use `ValidatingObjectInputStream` (Apache Commons IO) for pre-Java-9 environments
- Validate and sanitize all input before deserialization
- Replace `XMLDecoder` immediately - it has no safe configuration. For XStream, upgrade to 1.4.21 (the current floor, and the release fixing CVE-2024-47072); 1.4.18 is only where allowlisting became the default. On a pinned 1.4.7-1.4.17 that cannot move, explicitly call `setupDefaultSecurity()`/`addPermission()` as an interim measure rather than a fix
- Update dependencies regularly to patch known deserialization gadgets
- Monitor and log all deserialization activity for anomaly detection
