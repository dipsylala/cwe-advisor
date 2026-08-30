# CWE-331: Insufficient Entropy - PHP

## LLM Guidance

Insufficient entropy in PHP is not about `random_bytes()`/`random_int()` being the wrong function - they are the correct CSPRNG APIs (contrast with CWE-338's `rand()`/`mt_rand()` problem). The risk is whether the OS-level source those functions draw from is properly seeded and unique per instance. `random_bytes()` sources from the platform CSPRNG - `getrandom()`/`/dev/urandom` on Linux, the CNG API on Windows since PHP 7.2 (`CryptGenRandom` on older builds), and `CCRandomGenerateBytes()` on current macOS builds (PHP 8.0.22/8.1.9/8.2+, `arc4random_buf()`/`/dev/urandom` on older macOS and on NetBSD/OpenBSD) - and is documented to throw on failure rather than silently return weak output: a plain `Exception` before PHP 8.2, `Random\RandomException` (a subclass of `Exception`) from 8.2. A genuinely under-seeded Linux host does not take either of those paths, though - `getrandom()` blocks until the kernel CSPRNG is initialized, so the failure mode there is a hang, not an exception, and that guarantee doesn't protect against an entropy pool that has simply been cloned across VM/container images.

## Key Principles

- `random_bytes()`/`random_int()` are correct APIs; the defect is the underlying OS entropy source being unseeded, exhausted, or duplicated across cloned instances - not the choice of function
- Generate sufficient entropy regardless of correct API: 16+ bytes (128+ bits) for tokens, 32+ bytes (256+ bits) for keys
- Be cautious of PHP running in containers/VMs built from a shared image or snapshot; secret or seed material generated at build time can be duplicated across clones unless generation is deferred to first real runtime
- On embedded or minimal container systems, verify the OS-level entropy source is healthy, since PHP relies entirely on the platform CSPRNG and does not manage entropy itself
- Treat an `Exception`/`Random\RandomException` from `random_bytes()`/`random_int()` as a signal that the platform's entropy source is unavailable and needs fixing - never catch it and silently fall back to a weaker function. On Linux, a genuinely unseeded pool does not throw at all; the call blocks until the kernel CSPRNG initializes, so a hang at process startup is the symptom to look for there instead
- Size the request as well as choosing the API: `random_bytes(4)` is 32 bits and guessable regardless of how good the source is - 16 bytes for a token, 32 for key material
- `uniqid()`, `lcg_value()`, `str_shuffle()` and `md5(time())` are not CSPRNGs and no amount of hashing repairs them; using one for a secret is CWE-338

## Taint Sinks

`random_bytes()`, `random_int()` calls used for key/token generation during process, container, or VM startup, or in image build scripts, before confirming entropy-source health or that the instance isn't a stale clone

## Remediation Steps

- Locate where `random_bytes()`/`random_int()` generate tokens, keys, or nonces, and identify whether generation happens during image build, container/VM startup, or normal request handling
- Confirm output length: 16+ bytes for tokens, 32+ bytes for keys
- Do not generate long-lived secrets during image/template build; generate at first real startup of each deployed instance
- Do not catch and suppress exceptions from `random_bytes()`/`random_int()`, or fall back to `rand()`/`mt_rand()` on failure - fix the underlying entropy-source problem instead
- On embedded or minimal container hosts, verify the OS entropy source is healthy, since PHP has no independent entropy source
- Verify unpredictability across multiple instances launched from the same image or container, not only across repeated calls within one instance
