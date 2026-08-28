# CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')

## LLM Guidance

Every JavaScript object literal inherits from `Object.prototype`, so a property written onto that one object is visible from every other object in the process that does not shadow it. Pollution happens when a key from untrusted input is walked into an object graph and one of the keys along the way is `__proto__`, `constructor`, or `prototype`. Parsing is not the pollution step: `JSON.parse` creates an ordinary *own* `__proto__` property and leaves `Object.prototype` untouched. The payload is inert until a recursive merge, a `set(obj, path, value)` helper, or a config loader walks it - that walk is the sink. This is the JavaScript variant of CWE-915; a request that sets `isAdmin` on one record is CWE-915, and the same request setting it on `Object.prototype` is this entry.

## Key Principles

- The sink is the walker, not the parser: look for code that does `node = node[key]` and then assigns one level deeper, not for `JSON.parse`
- Denylisting `__proto__` is not enough - `{"constructor":{"prototype":{"isAdmin":true}}}` reaches the same object by another route, and a top-level key filter misses a payload nested one level down
- Validate against a schema and use the *parsed* result; spreading the original body after validating it puts the payload straight back
- Hold caller-supplied keys in a `Map` (keys are values, not property names) or an `Object.create(null)` object where a plain object is required
- That null-prototype protection is exactly one level deep: a walker that creates intermediate objects with `target[key] || {}` produces ordinary objects and pollutes through them, so it is hardening for a flat dictionary rather than a fix for a walker
- Prefer a maintained deep-merge or path-set implementation, which refuses the three keys internally at every level, over writing one - and keep it current, since those protections were added in response to CVEs
- A single dynamic write (`target[key] = value` where `key` is `__proto__`) replaces *that object's* prototype instead of polluting the global one - still a defect, since the value is silently not stored and later reads resolve against attacker-supplied data, and it becomes pollution as soon as anything indexes one level deeper
- `Object.freeze(Object.prototype)` at startup and `--disable-proto=throw` are process-wide hardening, not the fix: freezing fails silently in sloppy mode, and disabling the accessor leaves the `constructor.prototype` route open
- Exploitability depends on a gadget - code that reads a property it never set (`opts.timeout ?? 30`, a template engine resolving an inherited field). No gadget today is a reason to prioritise lower, not to close: one can arrive with the next dependency update

## Remediation Steps

- Locate - find every deep merge, path-set helper, query-string expander, and config loader that walks keys from a request body, not only the one the finding names
- Trace data flow - follow the parsed body to the walk, and note that the dangerous key can be at any depth
- Identify the unsafe pattern - an intermediate `node = node[key]` step reached with an attacker-controlled key, or an allowlisted path prefix concatenated with an attacker-controlled suffix
- Replace with the safe pattern - validate with a schema and use the parsed object, switch caller-keyed data to a `Map` or null-prototype object, and delegate deep merges to a maintained library
- Break taint after allowlist validation - spread the schema's output, never the original body
- Add secondary controls - freeze `Object.prototype` after the module graph has loaded, and consider `--disable-proto=throw`
- Test - after sending `__proto__`, `constructor.prototype`, and a nested variant, assert `({}).isAdmin` is undefined on a *freshly created* object, and again from a later unauthenticated request since pollution outlives the request that caused it; assert a legitimate nested update still merges without dropping sibling keys
