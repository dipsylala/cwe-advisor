# CWE-502: Insecure Deserialization - Java

## LLM Guidance

Insecure deserialization occurs when untrusted data is used to create objects, potentially allowing attackers to execute arbitrary code, manipulate application logic, or achieve denial of service. Java's native serialization is particularly dangerous because it can invoke methods during deserialization.

**Primary Defence:** Use JSON (Jackson, Gson) instead of Java serialization, or if Java serialization is required, implement `ObjectInputFilter` (Java 9+) to allowlist permitted classes, or `ValidatingObjectInputStream` (Apache Commons IO) for earlier versions.

## Key Principles

- Prefer data-only formats: Replace Java serialization with JSON, Protocol Buffers, or other data-only formats that don't execute code during deserialization
- Allowlist classes explicitly: If Java serialization is unavoidable, use `ObjectInputFilter` (Java 9+) or `ValidatingObjectInputStream` (Apache Commons IO) to allow only specific, known-safe classes
- Never trust serialized data: Treat all serialized input as untrusted, even from seemingly secure sources
- Avoid known-unsafe libraries: `XMLDecoder` and `XStream < v1.4.17` have no safe configuration and must be replaced
- Apply defence in depth: Combine multiple controls including input validation, least privilege, and monitoring

## Remediation Steps

- Replace `ObjectInputStream` with JSON parsers like Jackson or Gson for data transfer
- If Java serialization is unavoidable, implement `ObjectInputFilter` (Java 9+) with an explicit per-class allowlist; use `ValidatingObjectInputStream` (Apache Commons IO) for pre-Java-9 environments
- Validate and sanitize all input before deserialization
- Replace `XMLDecoder` and `XStream < v1.4.17` immediately — these have no safe configuration
- Update dependencies regularly to patch known deserialization gadgets
- Monitor and log all deserialization activity for anomaly detection

## Safe Pattern

```java
// SAFE: ObjectInputFilter allowlist approach (Java 9+)
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
ois.setObjectInputFilter(filterInfo -> {
    Class<?> clazz = filterInfo.serialClass();
    if (clazz != null) {
        if (clazz == User.class || clazz == String.class) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.UNDECIDED;
});
Object obj = ois.readObject();

// SAFE: JSON with Jackson (preferred — no serialization callbacks)
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonData, User.class);
```
