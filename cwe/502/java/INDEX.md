# CWE-502: Deserialization of Untrusted Data - Java

## LLM Guidance

Insecure deserialization occurs when untrusted data is used to create objects, potentially allowing attackers to execute arbitrary code, manipulate application logic, or achieve denial of service. Java's native serialization is particularly dangerous because it can invoke methods during deserialization.

**Primary Defence:** Where every producer of the stream is in the same change, move to JSON (Jackson, Gson). Where it is not - a queue, cache or RMI peer that still emits native serialization - keep `ObjectInputStream` and attach an `ObjectInputFilter` allowlist to it; switching only the consumer's format rejects every legitimate message rather than closing the finding. Its floor is not JDK 9: JEP 290 was backported to 8u121, so `ValidatingObjectInputStream` (Apache Commons IO) is needed only below that.

## Key Principles

- Prefer data-only formats: Replace Java serialization with JSON, Protocol Buffers, or other data-only formats that don't execute code during deserialization - where the producers can move with it
- Jackson's `ObjectMapper` is safe by default, but not unconditionally: enabling polymorphic typing (`@JsonTypeInfo`, `ObjectMapper.enableDefaultTyping()`, deprecated since Jackson 2.10 in favour of `activateDefaultTyping(PolymorphicTypeValidator)` - the validator is the security-relevant argument, and allowing all subtypes through it restores the weakness) reintroduces gadget-chain risk by letting the input dictate the concrete class to instantiate - avoid it for untrusted input, or pair it with a strict base-type allowlist
- Allowlist classes explicitly: If Java serialization is unavoidable, use `ObjectInputFilter` (8u121 and later) to allow only specific, known-safe classes. The callback returns `Status.ALLOWED`, `Status.REJECTED` or `Status.UNDECIDED`; return `UNDECIDED` whenever the filter cannot decide, not only when `filterInfo.serialClass()` is null. A null class with `arrayLength` of -1 is how the array-length, depth and stream-size limits arrive, so handle those calls rather than falling through them. On JDK 17 and later, `ObjectInputFilter.allowFilter`, `rejectFilter`, `merge` and `rejectUndecidedClass` (JEP 415) build this without a hand-written callback
- Attach the filter to the stream being read: `ois.setObjectInputFilter(filter)` before the first `readObject()`, once per `ObjectInputStream`. `ObjectInputFilter.Config.setSerialFilter(filter)` is the process-wide default and can be set only once per JVM - a second call throws `IllegalStateException: Serial filter can only be set once` - so placed in a request, message or job handler it fails on every invocation after the first. Set the process-wide filter, if at all, once at startup, or with `-Djdk.serialFilter=...` on the command line; `System.setProperty("jdk.serialFilter", ...)` after startup has no effect because the value is read once at class initialisation
- Never trust serialized data: Treat all serialized input as untrusted, even from seemingly secure sources
- Avoid known-unsafe libraries: `XMLDecoder` has no safe configuration and must be replaced. XStream's allowlist framework (`XStream.addPermission()` / `setupDefaultSecurity()`) is available from v1.4.7 but must be explicitly configured; it is only enabled by default from v1.4.18 onward. Versions before 1.4.7, or later versions left unconfigured, are exploitable. 1.4.18 is where the default changed, not the version to land on: the operative floor is 1.4.21, which fixes CVE-2024-47072, a stack-overflow denial of service reachable through `BinaryStreamDriver`
- Apply defence in depth: Combine multiple controls including input validation, least privilege, and monitoring
- An `ObjectInputFilter` allowlist must include the container types the payload legitimately uses (`java.util.ArrayList`, `[Ljava.lang.Object;`), or valid traffic is rejected while the filter looks correct
- `setRegistrationRequired(true)` in Kryo (and the equivalent in other binary serializers) refuses any class not explicitly registered, which is the same allowlist idea one layer up
- `readResolve()`/`readObject()` run during reconstruction, so validation placed in a constructor never executes on a deserialized instance

## Taint Sinks

`ObjectInputStream.readObject()`, `XMLDecoder.readObject()`, `XStream.fromXML()`, `ObjectMapper.enableDefaultTyping()`, deprecated since Jackson 2.10 in favour of `activateDefaultTyping(PolymorphicTypeValidator)` - the validator is the security-relevant argument, and allowing all subtypes through it restores the weakness/`@JsonTypeInfo`

## Remediation Steps

- Replace `ObjectInputStream` with JSON parsers like Jackson or Gson for data transfer when the producers change with it; when they do not, the filter below is the fix, and a format change is a breaking change to state separately
- If Java serialization is unavoidable, implement `ObjectInputFilter` with an explicit per-class allowlist and attach it per stream with `ois.setObjectInputFilter(filter)` - not `Config.setSerialFilter()` inside a handler, which throws on the second call; `ValidatingObjectInputStream` (Apache Commons IO) is the fallback only below 8u121
- Validate and sanitize all input before deserialization
- Replace `XMLDecoder` immediately - it has no safe configuration. For XStream, upgrade to 1.4.21 (the current floor, and the release fixing CVE-2024-47072); 1.4.18 is only where allowlisting became the default. On a pinned 1.4.7-1.4.10, the range XStream documents for it that cannot move, explicitly call `setupDefaultSecurity()`/`addPermission()` as an interim measure rather than a fix
- Update dependencies regularly to patch known deserialization gadgets
- Monitor and log all deserialization activity for anomaly detection
