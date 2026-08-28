# CWE-328: Use of Weak Hash - PHP

## LLM Guidance

The finding is `md5()`, `sha1()`, or `hash('md5', ...)`, most often storing a password. PHP has the
best built-in answer of the common languages: `password_hash()` and `password_verify()` choose the
algorithm, generate the salt, and encode the algorithm, cost and salt into the stored string, so the
scheme can be upgraded later without a schema change. Use them for passwords, `hash('sha256', ...)`
for integrity, and `hash_hmac()` for a keyed MAC. Do not reach for `crypt()` or a hand-rolled
salt-and-md5 scheme.

## Key Principles

- Use `password_hash($password, PASSWORD_DEFAULT)` and never store the algorithm choice yourself.
  `PASSWORD_DEFAULT` is explicitly allowed to change between PHP releases, which is the point - the
  stored string records what was actually used, so verification keeps working across an upgrade
- Because the default can change, pair it with `password_needs_rehash($hash, PASSWORD_DEFAULT)` after
  a successful `password_verify()`, and rehash there. Without that call the codebase silently keeps
  producing whatever the algorithm was when it was written
- Never compare a stored hash with `==` or `===`, and never re-hash the candidate and compare
  strings. `password_verify()` does a constant-time comparison and parses the parameters out of the
  stored value; for a non-password digest use `hash_equals()`
- `PASSWORD_BCRYPT` truncates the password at 72 bytes. That matters for passphrase-friendly login
  forms, and pre-hashing to work around it must base64-encode the digest first, or a null byte in the
  binary hash truncates the password again
- Set the cost deliberately - `['cost' => 12]` or higher for bcrypt, or `PASSWORD_ARGON2ID` with
  explicit `memory_cost`/`time_cost` where the build has libargon2 - and measure it on the production
  hardware rather than accepting the default
- `md5()` and `sha1()` for a cache key, an ETag, or a file fingerprint are not this finding. PHP has
  no "not for security" flag, so state the intent in a comment at the call site, and prefer
  `hash('xxh3', ...)` (PHP 8.1+) where a non-cryptographic digest is what is wanted
- `hash('md5', ...)` and `md5()` are the same finding written two ways; a scanner rule matching only
  the function name misses the `hash()` form, so search for both
- `crypt()` with a weak or missing salt format falls back to DES-based output that is limited to eight
  significant characters; treat any surviving `crypt()` call as a finding in its own right

## Taint Sinks

`md5()`, `sha1()`, `md5_file()`, `sha1_file()`, `hash('md5'|'sha1', ...)`, `crypt()`,
`hash_hmac('md5'|'sha1', ...)`, a password compared with `===` against a stored digest

## Remediation Steps

- Locate - find `md5(`, `sha1(`, `hash('md5'`, `hash('sha1'` and `crypt(` calls, plus any place a
  candidate password is hashed and string-compared
- Determine the purpose - password storage, a MAC, a signature, file integrity, or a non-security
  identifier; only the last is resolved without changing the algorithm
- Replace the unsafe pattern - `password_hash()`/`password_verify()` for passwords,
  `hash('sha256', ...)` for integrity, `hash_hmac('sha256', ...)` for a keyed MAC
- Bind, encode, validate, or authorize - widen the stored password column to at least 255 characters
  before deploying, since the encoded string is longer than a hex md5 and a silently truncated hash
  fails verification for every user
- Plan the migration - verify against the legacy scheme at login, and on success rehash with
  `password_hash()` and store; add `password_needs_rehash()` so future default changes are picked up
  the same way
- Harden configuration - compare non-password digests with `hash_equals()`, and confirm the PHP build
  has the Argon2 algorithms if the guidance depends on them
- Test - confirm a legacy user logs in once and is stored under the new scheme, that the column holds
  the full hash, and that a password over 72 bytes behaves as intended under bcrypt
