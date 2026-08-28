# CWE-331: Insufficient Entropy - PHP

## LLM Guidance

Insufficient entropy in PHP is not about `random_bytes()`/`random_int()` being the wrong function - they are the correct CSPRNG APIs (contrast with CWE-338's `rand()`/`mt_rand()` problem). The risk is whether the OS-level source those functions draw from is properly seeded and unique per instance. `random_bytes()` sources from the platform CSPRNG (`arc4random_buf()` on BSD/macOS, the `getrandom()` syscall or `/dev/urandom` on Linux, `CryptGenRandom`/`BCryptGenRandom` on Windows) and is documented to throw an `Exception` rather than silently return weak output if no adequate randomness source is available - but that guarantee doesn't protect against an entropy pool that has simply been cloned across VM/container images or is genuinely under-seeded on embedded systems.

## Key Principles

- `random_bytes()`/`random_int()` are correct APIs; the defect is the underlying OS entropy source being unseeded, exhausted, or duplicated across cloned instances - not the choice of function
- Generate sufficient entropy regardless of correct API: 16+ bytes (128+ bits) for tokens, 32+ bytes (256+ bits) for keys
- Be cautious of PHP running in containers/VMs built from a shared image or snapshot; secret or seed material generated at build time can be duplicated across clones unless generation is deferred to first real runtime
- On embedded or minimal container systems, verify the OS-level entropy source is healthy, since PHP relies entirely on the platform CSPRNG and does not manage entropy itself
- Treat an `Exception` from `random_bytes()`/`random_int()` as a signal that the platform's entropy source is unavailable and needs fixing - never catch it and silently fall back to a weaker function
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
