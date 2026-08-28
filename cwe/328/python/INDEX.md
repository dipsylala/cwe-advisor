# CWE-328: Use of Weak Hash - Python

## LLM Guidance

The finding is `hashlib.md5()` or `hashlib.sha1()`, or a password stored with a bare
`hashlib.sha256()`. Establish the purpose before changing anything, because Python has a first-class
way to say "this hash is not security-relevant": every `hashlib` constructor accepts
`usedforsecurity=False` (Python 3.9+), which both documents the intent and lets the call keep working
on a FIPS-restricted build. For a real integrity need use `hashlib.sha256`; for passwords use Argon2
or bcrypt through a library, or `hashlib.scrypt`/`pbkdf2_hmac` from the standard library.

## Key Principles

- Check the purpose first. `hashlib.md5(data, usedforsecurity=False)` is the correct resolution for a
  cache key, an ETag, a shard selector, or a content-dedup fingerprint - the algorithm does not need
  to change, and the flag is what tells the next scanner and the next reader that
- `usedforsecurity` is a keyword-only argument added in Python 3.9. On 3.8 it does not exist and
  passing it raises `TypeError`, so confirm the minimum supported version before proposing it
- For passwords prefer `argon2-cffi` (Argon2id) or `bcrypt`; both store the parameters inside the hash
  string and both expose a check for whether a stored hash needs upgrading. Where a dependency is not
  acceptable, `hashlib.scrypt` (3.6+) and `hashlib.pbkdf2_hmac` are in the standard library
- `pbkdf2_hmac` needs an explicit digest name and a current iteration count - `pbkdf2_hmac('sha256',
  ...)` with hundreds of thousands of iterations. It is only available when Python is built against
  OpenSSL, which became a hard requirement in 3.12 but is not guaranteed on an older custom build
- bcrypt silently truncates the password at 72 bytes. A passphrase longer than that has its tail
  ignored, and pre-hashing to work around it introduces a null-byte truncation problem of its own
  unless the pre-hash output is base64-encoded first
- Compare digests and MACs with `hmac.compare_digest`, never `==`
- A salt must be per-record and random; `os.urandom`/`secrets.token_bytes` for a hand-rolled scheme,
  and nothing at all for `bcrypt`/`argon2`, which generate and embed their own
- `md5` may be absent entirely on a FIPS-compliant build even though `algorithms_guaranteed` still
  lists it, so code that imports it unconditionally can fail at runtime on a hardened host

## Taint Sinks

`hashlib.md5()`, `hashlib.sha1()`, `hashlib.new('md5')`/`hashlib.new('sha1')`, `hashlib.sha256()` used
on a password, `Crypto.Hash.MD5`, `django.utils.crypto.salted_hmac` with a weak algorithm,
`hashlib.pbkdf2_hmac` with a low iteration count

## Remediation Steps

- Locate - find `hashlib.md5`, `hashlib.sha1`, `hashlib.new` with a weak name, and any password
  comparison built on a plain digest
- Determine the purpose - password storage, a MAC, a signature, file integrity, or a non-security
  identifier; only the last is resolved without changing the algorithm
- Replace the unsafe pattern - `hashlib.sha256` for integrity; `argon2-cffi` or `bcrypt` for
  passwords, or `hashlib.scrypt`/`pbkdf2_hmac('sha256', ...)` with a current iteration count where a
  dependency cannot be added
- Mark the non-security uses - pass `usedforsecurity=False` where the digest is an identifier rather
  than a control, provided the minimum Python version is 3.9 or later
- Bind, encode, validate, or authorize - let the password library generate and embed the salt, and use
  its needs-rehash check at login to upgrade stored hashes without forcing a reset
- Plan the migration - a password hash cannot be recomputed from the stored value, so verify against
  the old scheme and rehash on successful login; state that the change invalidates any offline tooling
  that verifies hashes independently
- Harden configuration - compare with `hmac.compare_digest`, and where Django or Flask-Login is in
  use configure the framework's password hasher list rather than hashing by hand
- Test - confirm an existing user logs in and is rehashed transparently, that a 72-byte-plus password
  behaves as intended under bcrypt, and that the non-security call sites still run under a FIPS build
