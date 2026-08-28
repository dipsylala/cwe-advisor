# CWE-502: Deserialization of Untrusted Data - JavaScript

## LLM Guidance

JavaScript deserialization vulnerabilities occur when `eval()`, `Function()`, `vm.runInNewContext()`, or vulnerable libraries (node-serialize, serialize-javascript) parse untrusted data, allowing attackers to execute arbitrary code. Node.js applications are particularly vulnerable when deserializing from cookies, external APIs, or user uploads.

**Primary Defence**: Use `JSON.parse()` exclusively for deserialization and validate input against strict schemas.

## Key Principles

- Replace `eval()`, `Function()`, and `vm` module usage with `JSON.parse()` for all data deserialization
- Validate deserialized data with schema validation libraries (Joi, Ajv, Zod) before use
- Remove dependencies on libraries that deserialize by evaluating, such as `node-serialize` (whose `unserialize()` executes an embedded IIFE) and `funcster`
- `serialize-javascript` is the opposite direction and is not a deserialization sink - it has no `unserialize`. It writes JS intended to be evaluated later, so its weakness is injection into that output (CVE-2019-16769, CVE-2020-7660); take its minimum version from advisory or SCA data, since fixes landed across several releases
- Implement allowlists for expected object types and reject unexpected properties - in an Ajv/JSON Schema this is `additionalProperties: false` plus an explicit `required` list
- `JSON.parse()` itself is safe, but merging its output into an existing object with `Object.assign()`, bracket-notation assignment (`target[key] = value`), or a recursive deep-merge library can still cause prototype pollution if `__proto__`/`constructor`/`prototype` keys are not rejected - validate keys before merging, or use `Object.create(null)`/`Map` for untrusted data
- Use Content Security Policy and strict input validation at API boundaries
- `JSON.parse` removes the code execution and leaves the payload intact as data: a later `_.merge`, `_.defaultsDeep` or `_.set` walking that object can still reach `Object.prototype`, which is CWE-1321 - current lodash refuses the three prototype keys, an old vendored copy does not

## Taint Sinks

`eval()`, `Function()`, `vm.runInNewContext()`, `node-serialize.unserialize()`, `funcster.deepDeserialize()`

## Remediation Steps

- Audit codebase for `eval()`, `Function()`, `vm.runInNewContext()`, and unsafe deserialization libraries
- Replace all unsafe deserialization with `JSON.parse()` and add try-catch error handling
- Implement JSON schema validation immediately after deserialization
- Add integrity checks (HMAC signatures) to serialized data from untrusted sources
- Configure CSP headers to prevent inline script execution
- Test with malicious payloads to verify protections
