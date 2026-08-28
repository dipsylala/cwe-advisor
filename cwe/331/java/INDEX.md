# CWE-331: Insufficient Entropy - Java

## LLM Guidance

Insufficient entropy in Java is not about `SecureRandom` versus a non-cryptographic generator (that is CWE-338) - it is about whether `SecureRandom` draws from a properly seeded entropy source. The default `new SecureRandom()` resolves through the provider preference order, which on Linux puts `NativePRNG` first - its `nextBytes()` draws from `/dev/urandom`, so output can be produced before the OS pool is fully seeded. `SecureRandom.getInstanceStrong()` instead selects from the `securerandom.strongAlgorithms` property in `java.security`; what that resolves to is configuration rather than a language guarantee, and is worth reading off the deployed `java.security` rather than assumed. This matters most for values generated early in a process's or VM's lifecycle, or in cloned VM/container images.

## Key Principles

- `SecureRandom` is the correct algorithm; the defect is drawing from an entropy source that isn't seeded yet, or from a cloned instance sharing seed state - not the choice of class
- For security-critical values generated at process/container/VM startup, prefer `SecureRandom.getInstanceStrong()`, which resolves to a blocking entropy source on typical Linux JVM configurations rather than the default non-blocking `SecureRandom()`
- Generate sufficient entropy regardless of correct algorithm: 16+ bytes (128+ bits) for tokens/IVs, 32+ bytes (256+ bits) for keys
- Be cautious of VM/container images built via templating or snapshotting; JVM/OS entropy or seed state captured at image-build time can be duplicated across clones unless reseeded
- On embedded or virtualized hosts, verify the underlying OS entropy source is healthy - Java delegates entirely to the platform and does not generate its own entropy
- Do not reach for `SecureRandom.getInstance("SHA1PRNG")` to get a "strong" instance - that names a specific legacy algorithm rather than the platform's choice; `new SecureRandom()` or `getInstanceStrong()` (or `"DRBG"`, added in JDK 9 by JEP 273, where a NIST DRBG is required - it throws `NoSuchAlgorithmException` on JDK 8) is what to ask for
- `setSeed()` supplements rather than replaces the existing seed, and the Javadoc guarantees repeated calls never reduce randomness - so a caller-supplied seed is not by itself the defect. The documented trap is narrower and easier to miss: a PRNG `SecureRandom` will not seed itself automatically if `setSeed` is called before any `nextBytes` or `reseed` call, so seeding first with a predictable value leaves the instance relying on exactly what the caller supplied
- `UUID.randomUUID()` draws from `SecureRandom` and carries 122 random bits - fine as an identifier, short of the usual bar for key material
- `Math.random()`, `java.util.Random` and `ThreadLocalRandom.current()` are not CSPRNGs at all; using one for a secret is CWE-338 rather than this weakness

## Taint Sinks

`new SecureRandom()` (default constructor) and `SecureRandom.getInstance()` calls used for key/token generation during process, container, or VM startup, or in image build scripts, before entropy-source health is confirmed

## Remediation Steps

- Locate where `SecureRandom` generates keys, tokens, or IVs, and identify whether generation happens during image build, container/VM startup, or normal runtime
- Confirm output length: 16+ bytes for tokens/IVs, 32+ bytes for keys
- For startup-time or boot-time generation, use `SecureRandom.getInstanceStrong()` instead of the default constructor so the call draws from a blocking, entropy-aware source
- Do not generate long-lived keys as part of an image/template build step; defer generation to first real boot of each deployed instance
- On embedded or virtualized JVM hosts, verify the OS-level entropy source (`/dev/random`, hardware RNG) is healthy
- Verify unpredictability across multiple instances launched from the same image, not only across repeated calls within one instance
