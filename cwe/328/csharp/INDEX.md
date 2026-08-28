# CWE-328: Use of Weak Hash - C#

## LLM Guidance

The finding is usually `MD5.Create()`, `SHA1.Create()`, or a legacy `MD5CryptoServiceProvider`/
`SHA1Managed` feeding an integrity check or a password store. Decide the purpose first: for integrity
move to `SHA256`/`SHA512`; for a password use ASP.NET Core Identity's `PasswordHasher<TUser>`, or
`Rfc2898DeriveBytes.Pbkdf2` with an explicit `HashAlgorithmName`. The trap in .NET is that the
obvious PBKDF2 route defaults to SHA-1: `Rfc2898DeriveBytes` is documented as using a PRF based on
`HMACSHA1`, so a constructor called without a `HashAlgorithmName` produces a SHA-1-based KDF while
looking like the fix.

## Key Principles

- Pass `HashAlgorithmName.SHA256` explicitly to any PBKDF2 call. The `Rfc2898DeriveBytes`
  constructors that omit it derive with HMAC-SHA1, and the legacy default iteration count is 1000 -
  both far below current guidance, and neither is visible at the call site
- Prefer the static `Rfc2898DeriveBytes.Pbkdf2(...)` methods over constructing the class. The
  constructors taking no `HashAlgorithmName` are obsolete from .NET 7, and from .NET 10 every
  constructor is obsolete, so on a current target framework the constructor route produces build
  warnings as well as a weak PRF
- For a web application's user passwords, prefer Identity's `PasswordHasher<TUser>` over hand-rolled
  PBKDF2: it encodes the algorithm, iteration count and salt into the stored string and gives you
  `PasswordVerificationResult.SuccessRehashNeeded`, which is the mechanism for upgrading a stored
  hash on next login without a password reset
- Compare digests and MACs with `CryptographicOperations.FixedTimeEquals`, not `SequenceEqual` or
  `==`; a correct hash compared in variable time is still an oracle
- `MD5.Create()` for a cache key, an ETag, or a shard selector is not a security finding. .NET has no
  "not for security" flag equivalent to Python's, so record the intent in a comment at the call site
  and, where it is easy, move to `System.IO.Hashing.XxHash64` so no scanner reads it as crypto again
- Do not use `GetHashCode()` as a substitute for any of this - it is unsalted, unstable across
  processes and runtime versions, and not a cryptographic function
- `HMACSHA1` is a separate judgement from `SHA1`: HMAC-SHA1 has no practical break and is not the
  same finding as a bare SHA-1 digest, so check whether the flagged call is a keyed MAC before
  proposing a change that breaks compatibility with a peer

## Taint Sinks

`MD5.Create()`, `SHA1.Create()`, `MD5CryptoServiceProvider`, `SHA1Managed`, `MD5.HashData()`,
`SHA1.HashData()`, `new Rfc2898DeriveBytes(...)` without a `HashAlgorithmName`,
`HashAlgorithm.Create("MD5")`

## Remediation Steps

- Locate - find `MD5`/`SHA1` creation or `HashData` calls, and any `Rfc2898DeriveBytes` construction
- Determine the purpose - password storage, a MAC, a signature, file integrity, or a non-security
  identifier such as a cache key; the fix differs for each and only the last is not a finding
- Replace the unsafe pattern - `SHA256`/`SHA512` for integrity; `PasswordHasher<TUser>` or
  `Rfc2898DeriveBytes.Pbkdf2` with `HashAlgorithmName.SHA256` and a current iteration count for
  passwords
- Bind, encode, validate, or authorize - store the algorithm, iteration count and salt alongside the
  hash so the parameters can be raised later without invalidating existing records
- Plan the migration - a changed password hash cannot be recomputed from the stored value, so verify
  against the old scheme at login and rehash on success; state that outstanding sessions and any
  cached credential material are unaffected but that offline verification tooling is not
- Harden configuration - compare with `CryptographicOperations.FixedTimeEquals`, and treat a build
  warning about an obsolete `Rfc2898DeriveBytes` constructor as part of this finding rather than noise
- Test - verify an existing user can still log in and is transparently rehashed, and that a digest
  comparison rejects a near-miss value
