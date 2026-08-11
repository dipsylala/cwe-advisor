# CWE-331: Insufficient Entropy - C#

## LLM Guidance

Insufficient entropy in .NET is not about `RandomNumberGenerator` being the wrong algorithm - it is the correct CSPRNG API (contrast with CWE-338's `System.Random`/`Guid.NewGuid()` problem). The risk is whether the underlying OS entropy source is ready and whether cloned VM/container images share seed state. On Windows, `RandomNumberGenerator` is backed by CNG's `BCryptGenRandom`, which draws from a system-wide entropy pool that persists and is continuously reseeded across reboots - making cold-boot entropy starvation less of a concern than on some Linux/embedded systems. On Linux, .NET's `RandomNumberGenerator` delegates to the platform CSPRNG and inherits the same early-boot considerations as native Linux callers. Either way, a VM/container image cloned or snapshotted before its first unique boot can duplicate pre-clone seed state.

## Key Principles

- `RandomNumberGenerator` is the correct API; the defect is generating values before the host's entropy source is properly seeded, or from a cloned image sharing seed state - not the choice of RNG type
- Generate sufficient entropy regardless of correct API: 16+ bytes (128+ bits) for tokens, 32+ bytes (256+ bits) for keys
- Be cautious of VM/container images created via templating, snapshotting, or "golden image" pipelines; entropy/seed state captured at image-build time can be duplicated across clones unless the platform reseeds on first unique boot
- On Windows, `RandomNumberGenerator` does not need manual blocking logic - CNG's persisted, continuously-reseeded pool design already addresses classic cold-boot starvation - but confirm cloned instances are not sharing pre-clone seed state
- On Linux hosts or containers, verify the OS-level entropy source is healthy, especially in minimal or embedded deployments, since .NET does not manage entropy itself

## Taint Sinks

`RandomNumberGenerator` instances used for key or token generation during process, container, or VM startup, or in image/template build scripts, before confirming entropy-source health or that the instance isn't a stale clone

## Remediation Steps

- Locate where `RandomNumberGenerator.GetBytes()`/`Fill()` generate tokens or keys, and identify whether it runs during image/template build, container/VM startup, or normal runtime
- Confirm output length: 16+ bytes for tokens, 32+ bytes for keys
- Do not generate long-lived secrets during image/template build; generate at first real startup of each deployed instance
- For VM/container images produced by cloning or snapshotting, confirm the platform reseeds its entropy source on first unique boot rather than assuming inherited state is safe
- On Linux-hosted .NET or minimal container base images, verify the OS entropy source is healthy, since .NET delegates entirely to the platform CSPRNG
- Verify unpredictability across multiple instances launched from the same image, not only across repeated calls within one instance

## Safe Pattern

```csharp
using System.Security.Cryptography;

// Generate cryptographically secure random bytes
byte[] randomBytes = new byte[32];
RandomNumberGenerator.Fill(randomBytes);

// Convert to token string
string secureToken = Convert.ToBase64String(randomBytes);

// For random integers in a range
int secureValue = RandomNumberGenerator.GetInt32(0, 100);
```
