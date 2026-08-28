# CWE-328: Use of Weak Hash - Java

## LLM Guidance

The finding is `MessageDigest.getInstance("MD5")` or `"SHA-1"`, or a password stored as a bare
SHA-256 digest. Decide the purpose first: for integrity move to `MessageDigest.getInstance("SHA-256")`;
for passwords the JDK has no password hasher, so use Spring Security's `BCryptPasswordEncoder` or
`Argon2PasswordEncoder`, or `SecretKeyFactory` with `PBKDF2WithHmacSHA256` where a dependency cannot
be added. Note that the JDK's own PBKDF2 algorithm name carries the PRF, so the digest is chosen by
the string you pass rather than by a default.

## Key Principles

- `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")` is a weak choice hiding in an algorithm name -
  request `PBKDF2WithHmacSHA256` explicitly. There is no separate parameter to get wrong, which also
  means a copied-in string is the whole configuration
- `MessageDigest` instances are not thread-safe. A `static final MessageDigest` shared across request
  threads interleaves `update()` calls and produces wrong digests non-deterministically - a
  correctness bug that presents as intermittent verification failures rather than as a security one
- For passwords prefer Spring Security's `DelegatingPasswordEncoder`, which prefixes the stored value
  with the encoder id such as `{bcrypt}`. That prefix is what lets the application verify old formats
  and write new ones without a migration flag, and `upgradeEncoding()` tells you when to rehash
- `BCryptPasswordEncoder` truncates at 72 bytes like every bcrypt implementation, so a passphrase
  longer than that has its tail ignored
- Compare digests and MACs with `MessageDigest.isEqual`, not `Arrays.equals` or `String.equals` -
  `isEqual` is the constant-time comparison. Note it must also cover any lookup that precedes the
  comparison, since selecting *which* stored hash to compare against with a variable-time string
  comparison reintroduces the oracle one step earlier
- `MD5` or `SHA-1` computing a cache key, an ETag, or a shard selector is not this finding. Java has
  no "not for security" flag, so record the intent at the call site, and prefer Guava's
  `Hashing.murmur3_128()` or a `String.hashCode`-free explicit choice where a non-cryptographic digest
  is what is wanted
- `HmacSHA1` is a separate judgement from `SHA-1`: it has no practical break, so a flagged
  `Mac.getInstance("HmacSHA1")` interoperating with a peer is not automatically the same fix
- Salts must be per-record from `SecureRandom`; the password encoders generate and embed their own, so
  a separate salt column alongside them is a sign of a hand-rolled scheme still in place

## Taint Sinks

`MessageDigest.getInstance("MD5")`, `MessageDigest.getInstance("SHA-1")`, `DigestUtils.md5Hex()`,
`DigestUtils.sha1Hex()`, `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")`,
`Mac.getInstance("HmacMD5")`, a password digest compared with `String.equals`

## Remediation Steps

- Locate - find `MessageDigest.getInstance` and Apache Commons `DigestUtils` calls with a weak
  algorithm, plus any `SecretKeyFactory` PBKDF2 name ending in SHA1
- Determine the purpose - password storage, a MAC, a signature, file integrity, or a non-security
  identifier; only the last is resolved without changing the algorithm
- Replace the unsafe pattern - `SHA-256` for integrity, `PBKDF2WithHmacSHA256` or a Spring Security
  encoder for passwords
- Bind, encode, validate, or authorize - adopt `DelegatingPasswordEncoder` so the stored value records
  its own scheme, and widen the password column before deploying, since the encoded form is longer
  than a hex digest and a truncating column fails verification for every user
- Plan the migration - verify against the legacy scheme at login and rehash on success using
  `upgradeEncoding()`; state that the change breaks any offline tooling that recomputes hashes
- Harden configuration - compare with `MessageDigest.isEqual`, and create `MessageDigest` per use
  rather than sharing a static instance across threads
- Test - confirm a legacy user logs in once and is stored under the new scheme, that concurrent
  requests produce correct digests, and that the column holds the full encoded value
