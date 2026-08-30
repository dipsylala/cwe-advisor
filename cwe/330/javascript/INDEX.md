# CWE-330: Use of Insufficiently Random Values - JavaScript

## LLM Guidance

`Math.random()` is unsuitable for session tokens, CSRF tokens, API keys or key material: ECMA-262 promises only an "implementation-defined algorithm or strategy" with approximately uniform distribution and no unpredictability at all. V8 implements it as xorshift128+, whose internal state is recoverable from a modest run of consecutive outputs, and its seed cannot be set or reset by the caller - so reseeding is not available as a fix even in principle. Replace the generator with `node:crypto` on the server or the Web Crypto API in the browser, and take care that the encoding step matches whichever one you chose.

## Key Principles

- `crypto.randomBytes(size)` returns a Node `Buffer`, so `.toString('base64url')` and `.toString('hex')` work on it. `crypto.getRandomValues(typedArray)` writes into and returns the caller's TypedArray, which has no encoding-aware `toString` - calling `.toString('base64url')` on it yields a comma-separated list of decimal byte values. Convert through `Uint8Array` explicitly in the browser rather than reusing the Node idiom
- `crypto.getRandomValues` throws `QuotaExceededError` above 65536 bytes and `TypeMismatchError` for a float-typed array; it takes only the integer TypedArrays. It is also the one member of `Crypto` usable from an insecure context, so its availability says nothing about the page being served over HTTPS
- `crypto.randomInt([min, ]max)` (Node 14.10.0) is the bounded-integer API, documented as "Return a random integer `n` such that `min <= n < max`. This implementation avoids modulo bias." The range must be under 2^48. Reach for it instead of reducing `randomBytes` output with `%`, which biases the low end of the alphabet
- `crypto.randomUUID()` (Node 15.6.0 / 14.17.0) is CSPRNG-backed, but a v4 UUID carries 122 random bits - ASVS notes explicitly that UUIDs do not meet its 128-bit floor. Sound as an identifier, short for a secret
- `crypto.pseudoRandomBytes` is **not** a weaker generator. Node's DEP0115 states "there is no difference between `crypto.randomBytes()` and `crypto.pseudoRandomBytes()`", and in `lib/crypto.js` it is an alias bound to the same function. The name is a fossil of OpenSSL's `RAND_pseudo_bytes`, deprecated in OpenSSL 1.1.0. A scanner hit here is a false positive on the source: rename the call, keep the bytes
- Generate at least 128 bits (16 bytes) for tokens, per ASVS; size keys by their algorithm. Remember hex doubles the character count, so a 32-character hex token carries 128 bits
- The `'base64url'` Buffer encoding arrived in Node 15.7.0 / 14.18.0. Below that it is not an error but a silently wrong encoding

## Taint Sinks

`Math.random()`, `Math.random().toString(36)`, `Date.now()` used as an identifier or token, `new Date().getTime()`, `performance.now()`, `nanoid/non-secure`

## Remediation Steps

- Locate every `Math.random()` in token, key, nonce, OTP and identifier code, and widen the search to the idioms that hide it: `Math.random().toString(36).substring(2)`, and the `'xxxxxxxx-xxxx-4xxx-yxxx'.replace(/[xy]/g, ...)` UUID polyfill, which is this weakness wearing a UUID's shape
- Confirm the value's unpredictability is load-bearing before converting it - `Math.random()` is the right choice for jitter, sampling, animation and test fixtures
- Replace server-side generation with `crypto.randomBytes(16).toString('base64url')`, `crypto.randomInt()` for bounded values, or `crypto.randomUUID()` where an identifier rather than a secret is wanted. Note that `node:crypto` must be imported, while the browser's `crypto` is an ambient global; `globalThis.crypto` also exists in Node from 17.6.0, and Node documents its own `crypto.getRandomValues` as not spec-compliant, pointing to `crypto.webcrypto.getRandomValues` for portable code
- Move any token minted in the browser to the server. Client-side code is public and the attacker controls the runtime, so `getRandomValues` makes the bytes unpredictable without making the issuance trustworthy; the Web Crypto spec's own note also directs key generation to `generateKey` rather than `getRandomValues`
- Audit the ID libraries rather than assuming them. `uuid` v4 draws from `crypto.getRandomValues` and delegates to `crypto.randomUUID()` where available, and `nanoid` uses the same source - but `nanoid/non-secure` is a documented, shipped export that does not, and an import of it on a security path is the finding
- Rotate values the weak generator already issued, and check that the migration reached every caller - these conversions are done call site by call site, so a shared client-side helper or an older utility function still building IDs from `Math.random()` keeps producing predictable values for whatever still calls it. Then verify by reading which generator the security path reaches. Do not verify by inspecting output: xorshift128+ output is uniformly distributed and looks entirely random, so any check for "non-sequential" or "unpredictable-looking" values passes against the unfixed code
