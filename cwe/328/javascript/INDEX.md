# CWE-328: Use of Weak Hash - JavaScript

## LLM Guidance

The finding is `crypto.createHash('md5')` or `'sha1'`, or a password stored as a bare
`createHash('sha256')` digest. Establish the purpose first: for integrity move to `'sha256'`; for
passwords use `argon2`, `bcrypt`, or Node's own `crypto.scrypt`. Two Node-specific details decide
whether the fix works: `crypto.pbkdf2` requires an explicit digest argument, and
`crypto.timingSafeEqual` throws rather than returning false when the two buffers differ in length -
so the naive constant-time comparison fails closed by crashing.

## Key Principles

- `crypto.timingSafeEqual(a, b)` throws a `RangeError` if the buffers are not the same length. A
  comparison against attacker-supplied input must therefore equalise first - hash both sides and
  compare the digests, or check the length separately and accept that the length itself leaks
- Always pass the digest to `crypto.pbkdf2`/`pbkdf2Sync`. The form that defaulted the digest to SHA-1
  was deprecated and removed, so older code carried a SHA-1 KDF invisibly, and copied snippets still
  omit it
- Prefer `argon2` for new work; where a native dependency is unacceptable, Node's built-in
  `crypto.scrypt` needs no compilation. `bcryptjs` is the pure-JavaScript fallback for `bcrypt` and is
  meaningfully slower, which changes the cost calibration rather than removing the need for it
- bcrypt in JavaScript truncates at 72 bytes silently, unlike Go's implementation which rejects. A
  long passphrase therefore has its tail ignored with no error anywhere
- The async forms exist for a reason: `scryptSync`, `pbkdf2Sync` and synchronous bcrypt block the
  event loop for the whole work factor, so a correctly-tuned cost applied synchronously turns the
  password endpoint into a denial-of-service vector against the whole process
- `createHash('md5')` computing an ETag, a cache key, or a content fingerprint is not this finding.
  Node has no "not for security" flag, so record the intent at the call site
- A FIPS-enabled Node build refuses MD5 outright, so code that hashes unconditionally throws at
  runtime there rather than producing a weak digest
- `crypto.createHash('sha256')` on a password with a per-user salt is still this finding: the defect
  is the speed of the function, which is CWE-916, and no amount of salting changes it
- In the browser, `crypto.subtle` deliberately offers no MD5 at all, so a Web Crypto migration that
  needs it is a sign the value is being used to interoperate with something that must also change

## Taint Sinks

`crypto.createHash('md5')`, `crypto.createHash('sha1')`, `crypto.createHmac('md5'|'sha1', ...)`,
`crypto.pbkdf2()`/`pbkdf2Sync()` without a digest argument, `createHash('sha256')` applied to a
password, `md5` and `js-md5` npm packages, `object-hash` with a weak algorithm option

## Remediation Steps

- Locate - find `createHash` and `createHmac` calls with a weak algorithm, `pbkdf2` calls missing the
  digest, and any password compared with `===` against a digest
- Determine the purpose - password storage, a MAC, a signature, file integrity, or a non-security
  identifier; only the last is resolved without changing the algorithm
- Replace the unsafe pattern - `'sha256'` for integrity; `argon2`, `bcrypt`, or `crypto.scrypt` for
  passwords, with an explicit cost
- Bind, encode, validate, or authorize - use the async form so the work factor does not block the
  event loop, and let the password library generate and embed its own salt
- Plan the migration - verify against the legacy scheme at login and rehash on success, and widen the
  stored column, since an argon2 or bcrypt string is longer than a hex digest
- Harden configuration - replace digest comparisons with `crypto.timingSafeEqual` over equal-length
  buffers, and confirm behaviour on a FIPS build if one is in scope
- Test - confirm a legacy user logs in once and is rehashed, that a password over 72 bytes behaves as
  intended under bcrypt, and that the comparison path does not throw on a wrong-length input
