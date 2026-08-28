# CWE-331: Insufficient Entropy - Java

## LLM Guidance

Insufficient entropy in Java is not about `SecureRandom` versus a non-cryptographic generator (that is CWE-338) - it is about whether `SecureRandom` draws from a properly seeded entropy source. The default `new SecureRandom()` typically resolves to a non-blocking algorithm (e.g. `NativePRNGNonBlocking`, backed by `/dev/urandom` on Linux) that can return output before the OS pool is fully seeded. `SecureRandom.getInstanceStrong()` instead selects from `securerandom.strongAlgorithms` in `java.security`, which on typical Linux JVM configurations resolves to `NativePRNGBlocking` (backed by `/dev/random`) - deliberately blocking until sufficient entropy is available. This matters most for values generated early in a process's or VM's lifecycle, or in cloned VM/container images.

## Key Principles

- `SecureRandom` is the correct algorithm; the defect is drawing from an entropy source that isn't seeded yet, or from a cloned instance sharing seed state - not the choice of class
- For security-critical values generated at process/container/VM startup, prefer `SecureRandom.getInstanceStrong()`, which resolves to a blocking entropy source on typical Linux JVM configurations rather than the default non-blocking `SecureRandom()`
- Generate sufficient entropy regardless of correct algorithm: 16+ bytes (128+ bits) for tokens/IVs, 32+ bytes (256+ bits) for keys
- Be cautious of VM/container images built via templating or snapshotting; JVM/OS entropy or seed state captured at image-build time can be duplicated across clones unless reseeded
- On embedded or virtualized hosts, verify the underlying OS entropy source is healthy - Java delegates entirely to the platform and does not generate its own entropy
- Do not reach for `SecureRandom.getInstance("SHA1PRNG")` to get a "strong" instance - that names a specific legacy algorithm rather than the platform's choice; `new SecureRandom()` or `getInstanceStrong()` (or `"DRBG"` where a NIST DRBG is required) is what to ask for
- `setSeed()` is not a way to improve output: in the SUN provider it supplements the existing seed, in others it replaces it, so a caller-supplied seed can only reduce entropy
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
