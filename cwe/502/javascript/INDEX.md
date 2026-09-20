# CWE-502: Deserialization of Untrusted Data - JavaScript

## LLM Guidance

JavaScript deserialization vulnerabilities occur when `eval()`, `Function()`, `vm.runInNewContext()`, or vulnerable libraries (node-serialize, serialize-javascript) parse untrusted data, allowing attackers to execute arbitrary code. Node.js applications are particularly vulnerable when deserializing from cookies, external APIs, or user uploads.

**Primary Defence**: Use `JSON.parse()` exclusively for deserialization and validate input against strict schemas.

## Key Principles

- Replace `eval()`, `Function()`, and `vm` module usage with `JSON.parse()` for all data deserialization
- Validate deserialized data with schema validation libraries (Joi, Ajv, Zod) before use
- Remove dependencies on libraries that deserialize by evaluating, such as `node-serialize` (whose `unserialize()` executes an embedded IIFE) and `funcster`
- `serialize-javascript` is the opposite direction and is not a deserialization sink - it has no `unserialize`. It writes JS intended to be evaluated later, so its weakness is injection into that output. The floor is 7.0.5: CVE-2020-7660's fix in 3.1.0 was incomplete and GHSA-5c6j-r48x-rmvq bypasses it in every release up to 7.0.2, while CVE-2026-34043 (CPU-exhaustion denial of service) is fixed in 7.0.5
- Implement allowlists for expected object types and reject unexpected properties - in an Ajv/JSON Schema this is `additionalProperties: false` plus an explicit `required` list
- `JSON.parse()` itself is safe, but merging its output into an existing object with `Object.assign()`, bracket-notation assignment (`target[key] = value`), or a recursive deep-merge library can still cause prototype pollution if `__proto__`/`constructor`/`prototype` keys are not rejected - validate keys before merging, or use `Object.create(null)`/`Map` for untrusted data
- Validate the decoded value against a strict schema at API boundaries. A Content Security Policy is not part of this fix: every sink above runs in the Node process, where it has no effect
- `JSON.parse` removes the code execution and leaves the payload intact as data: a later `_.merge`, `_.defaultsDeep` or `_.set` walking that object can still reach `Object.prototype`, which is CWE-1321 - current lodash refuses the three prototype keys, an old vendored copy does not

## Taint Sinks

`eval()`, `Function()`, `vm.runInNewContext()`, `node-serialize.unserialize()`, `funcster.deepDeserialize()`

## Remediation Steps

- Audit codebase for `eval()`, `Function()`, `vm.runInNewContext()`, and unsafe deserialization libraries
- Replace all unsafe deserialization with `JSON.parse()` and add try-catch error handling. Check what wrote the stored values first: `node-serialize` output is JSON and survives the swap, but anything written as a JS literal - `serialize-javascript` output, single quotes, trailing commas, `undefined`, `new Date(...)` - makes `JSON.parse` throw on every legitimate value, so the producer moves to `JSON.stringify` in the same change or the reader dual-reads during the migration
- Implement JSON schema validation immediately after deserialization
- Add integrity checks (HMAC signatures) to serialized data from untrusted sources
- Test with malicious payloads to verify protections
