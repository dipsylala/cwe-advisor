# CWE-331: Insufficient Entropy - C#

## LLM Guidance

Insufficient entropy in .NET is not about `RandomNumberGenerator` being the wrong algorithm - it is the correct CSPRNG API (contrast with CWE-338's `System.Random`/`Guid.NewGuid()` problem). The risk is whether the underlying OS entropy source is ready and whether cloned VM/container images share seed state. On Windows, `RandomNumberGenerator` is backed by CNG's default provider, which Microsoft documents only as compliant with NIST SP 800-90's CTR_DRBG construction - the manual makes no claim about pool persistence or a reseed schedule, so do not cite one. On Linux, .NET's `RandomNumberGenerator` implementation changed source: before .NET 11 it read `/dev/urandom` directly, which returns output even before the kernel considers itself fully seeded; from .NET 11 it calls the blocking `getrandom()` syscall instead, matching native Linux callers. Either way, a VM/container image cloned or snapshotted before its first unique boot can duplicate pre-clone seed state.

## Key Principles

- `RandomNumberGenerator` is the correct API; the defect is generating values before the host's entropy source is properly seeded, or from a cloned image sharing seed state - not the choice of RNG type
- Generate sufficient entropy regardless of correct API: 16+ bytes (128+ bits) for tokens, 32+ bytes (256+ bits) for keys
- Be cautious of VM/container images created via templating, snapshotting, or "golden image" pipelines; entropy/seed state captured at image-build time can be duplicated across clones unless the platform reseeds on first unique boot
- On Windows, `RandomNumberGenerator` needs no manual blocking logic of its own - there is no separate "strong" or blocking variant to choose between, unlike Java's `SecureRandom` - but confirm cloned instances are not sharing pre-clone seed state
- On Linux hosts or containers running .NET 11 or later, a startup-time call can genuinely wait on the kernel CSPRNG the first time it runs; on earlier .NET versions the call reads `/dev/urandom` and does not wait, so verify which behavior the deployed runtime version has before assuming either one

## Taint Sinks

`RandomNumberGenerator` instances used for key or token generation during process, container, or VM startup, or in image/template build scripts, before confirming entropy-source health or that the instance isn't a stale clone

## Remediation Steps

- Locate where `RandomNumberGenerator.GetBytes()`/`Fill()` generate tokens or keys, and identify whether it runs during image/template build, container/VM startup, or normal runtime
- Confirm output length: 16+ bytes for tokens, 32+ bytes for keys
- Do not generate long-lived secrets during image/template build; generate at first real startup of each deployed instance
- For VM/container images produced by cloning or snapshotting, confirm the platform reseeds its entropy source on first unique boot rather than assuming inherited state is safe
- On Linux-hosted .NET or minimal container base images, verify the OS entropy source is healthy, since .NET delegates entirely to the platform CSPRNG
- Verify unpredictability across multiple instances launched from the same image, not only across repeated calls within one instance
