# CWE-328: Use of Weak Hash - Go

## LLM Guidance

The finding is an import of `crypto/md5` or `crypto/sha1`, or a password stored with a bare
`sha256.Sum256`. Establish the purpose first: for integrity move to `crypto/sha256`; for passwords Go
has nothing in the standard library, so use `golang.org/x/crypto/bcrypt`, `argon2` or `scrypt`. The
Go-specific detail worth knowing is that its bcrypt does not behave like everyone else's - it rejects
an over-long password rather than truncating it, which changes what the fix has to handle.

## Key Principles

- `bcrypt.GenerateFromPassword` returns `ErrPasswordTooLong` for input over 72 bytes rather than
  silently truncating, which is a deliberate divergence from the reference implementation. Check the
  dependency version before relying on it: the rejection landed in `golang.org/x/crypto` v0.5.0, and
  v0.4.0 and earlier truncate silently like every other implementation. A fix that adds bcrypt without
  handling that error turns a long passphrase into a failed registration
- The asymmetry matters as much as the error: `CompareHashAndPassword` still accepts passwords over 72
  bytes and compares only the first 72, because rejecting them would break already-stored hashes. So
  login keeps working for a legacy long password that registration would now refuse
- Pass a deliberate cost rather than accepting `bcrypt.DefaultCost`, which is 10, and measure it on
  the production hardware
- Prefer `argon2.IDKey` (Argon2id) for new work and record the parameters alongside the hash, since
  `x/crypto/argon2` returns raw bytes and does not encode them for you the way a PHC-string library
  would - without storing memory, time and parallelism you cannot verify later or raise them
- Compare digests and MACs with `hmac.Equal`, never `bytes.Equal` or `==` on strings
- `crypto.MD5.New()` and the other `crypto.Hash` values panic unless the implementing package is
  linked into the binary, which is why code that dispatches on a `crypto.Hash` carries blank imports
  such as `_ "crypto/sha256"`. Removing a weak algorithm's blank import can therefore turn a runtime
  panic into the actual behaviour change, so check for dispatch tables as well as direct calls
- `md5.Sum` computing a cache key, an ETag, or a content fingerprint is not this finding. Go has no
  "not for security" flag, so record the intent at the call site and prefer `hash/fnv` or
  `hash/maphash` where a non-cryptographic digest is what is wanted - `maphash` is seeded per process
  and is not stable across runs, so use `fnv` where the value is persisted
- `hmac.New(sha1.New, key)` is a separate judgement from a bare SHA-1 digest: HMAC-SHA1 has no
  practical break, so a flagged construction interoperating with a peer is not automatically the same
  fix

## Taint Sinks

`md5.New()`, `md5.Sum()`, `sha1.New()`, `sha1.Sum()`, `crypto.MD5`/`crypto.SHA1` in a dispatch table,
`hmac.New(md5.New, ...)`, `sha256.Sum256` applied to a password, `bcrypt.GenerateFromPassword` with an
unchecked error

## Remediation Steps

- Locate - find imports of `crypto/md5` and `crypto/sha1` and their call sites, plus any `crypto.Hash`
  dispatch that can select them
- Determine the purpose - password storage, a MAC, a signature, file integrity, or a non-security
  identifier; only the last is resolved without changing the algorithm
- Replace the unsafe pattern - `crypto/sha256` for integrity; `x/crypto/bcrypt` or `x/crypto/argon2`
  for passwords
- Bind, encode, validate, or authorize - handle `bcrypt.ErrPasswordTooLong` explicitly at registration
  and password change, deciding whether to reject with a clear message or to cap the accepted length
  in the form; store Argon2 parameters alongside the hash so they can be raised later
- Plan the migration - a password hash cannot be recomputed from the stored value, so verify against
  the legacy scheme at login and rehash on success; note that a stored hash created before the switch
  may hold a password longer than 72 bytes that registration would now refuse
- Harden configuration - compare with `hmac.Equal`, and confirm the blank imports the binary needs
  after a weak algorithm is removed from a dispatch table
- Test - confirm a legacy user logs in and is rehashed, that a password over 72 bytes produces the
  intended outcome at both registration and login, and that removing the weak algorithm does not panic
  a dispatch path
