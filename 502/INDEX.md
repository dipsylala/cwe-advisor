# CWE-502: Deserialization of Untrusted Data

## LLM Guidance

Insecure Deserialization occurs when applications deserialize untrusted data without validation, allowing attackers to manipulate serialized objects to execute arbitrary code, modify logic, or access unauthorized data. Formats like Java ObjectInputStream, Python pickle, PHP serialize(), and .NET BinaryFormatter can instantiate arbitrary classes during deserialization. Never allow untrusted data to be deserialized into executable objects; enforce integrity and type safety before object creation.

## Key Principles

- Replace native deserialization with safe data formats (JSON, XML with schema validation)
- Implement cryptographic integrity checks (HMAC signatures) on all serialized data
- Enforce strict type whitelisting and class instantiation controls
- Isolate deserialization operations in sandboxed, low-privilege environments
- Apply defence-in-depth: validation, monitoring, and runtime restrictions
- The test that separates this from mass assignment is what the attacker controls: *which fields of an expected type* get set is CWE-915, while *what type is constructed* - or code reached during reconstruction - is this weakness. MITRE notes the boundary needs further exploration, so expect scanners to disagree
- In JavaScript the finding survives its own fix: replacing `eval`-based deserialization with `JSON.parse` removes the code execution and leaves the payload intact as data, so a later deep merge or path write can still reach `Object.prototype` (CWE-1321)

## Remediation Steps

- Identify the deserialization call location, serialized data source, and format used
- Trace complete data flow from origin to deserialization operation
- Verify if attacker-controlled data reaches deserialization without integrity checks
- Replace unsafe formats with JSON/XML and implement schema validation
- Add HMAC signature verification before any deserialization attempts
- Apply type whitelisting to restrict instantiable classes
