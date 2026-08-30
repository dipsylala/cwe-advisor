# CWE-331: Insufficient Entropy - Python

## LLM Guidance

Insufficient entropy in Python is not about picking the wrong random API - `secrets` and `os.urandom()` are already correct CSPRNG calls (contrast with CWE-338, which covers replacing the `random` module). The risk here is generating security-critical values before the OS entropy source is properly seeded, or in a cloned VM/container image that duplicated PRNG seed state. On Linux and Solaris specifically, `os.urandom()` (which `secrets` uses internally) calls the `getrandom()` syscall, and since Python 3.6 (PEP 524, whose rationale is explicitly scoped to those two platforms) that call blocks until the kernel CSPRNG has been seeded at least once - so standard `secrets` calls already wait out an unseeded pool rather than silently returning weak output. This is a documented, intentional tradeoff rather than a purely theoretical one: an earlier attempt to use `getrandom()` unconditionally caused real early-boot hangs (Debian #822431), which is why PEP 524 reintroduced blocking deliberately rather than falling back to weaker output.

## Key Principles

- `secrets`/`os.urandom()` are the correct APIs; the defect is calling them before the OS entropy source is seeded, or from an image/instance that shares seed state with a clone - not the choice of function
- On Linux and Solaris, `os.urandom()` already blocks on `getrandom()` until the kernel CSPRNG is seeded (PEP 524), so no extra blocking logic is needed around `secrets` calls there; PEP 524 does not describe this guarantee for macOS or Windows
- Ensure sufficient entropy regardless of correct API: 16+ bytes (128+ bits) for tokens, 32+ bytes (256+ bits) for keys
- Never bake long-lived secrets into a VM/container image at build time; generate them at first real startup so cloned instances don't inherit identical secret or seed material
- On embedded or minimal container systems without a hardware RNG or entropy daemon (`rngd`, `haveged`), verify the OS entropy source is healthy before assuming `secrets` calls return strong output promptly
- Size the request as well as choosing the API: `secrets.token_hex(4)` is 32 bits - `token_hex(n)`/`token_urlsafe(n)` take a *byte* count, so pass 16 for a token and 32 for key material
- `uuid.uuid1()` is built from a timestamp and the MAC address rather than randomness, and `uuid.uuid4()` carries 122 random bits; `random.seed()`, `random.shuffle()` and `random.sample()` are not CSPRNG operations at all, and using one for a secret is CWE-338

## Taint Sinks

`secrets.token_bytes()`, `secrets.token_hex()`, `secrets.token_urlsafe()`, `os.urandom()` called during process/container/VM startup, image build scripts, or before OS entropy-source health is confirmed

## Remediation Steps

- Locate where `secrets`/`os.urandom()` generate keys, tokens, IVs, or nonces, and identify whether generation happens during image build, container/VM startup, or normal runtime
- Confirm output length meets the purpose: 16+ bytes for tokens, 32+ bytes for keys
- Do not generate long-lived secrets as part of an image/template build step; defer generation to first real boot of each deployed instance
- On Linux, rely on `os.urandom()`'s blocking `getrandom()` behavior rather than adding manual entropy checks; on other platforms, `secrets` already delegates to the OS CSPRNG
- On embedded or minimal systems, confirm a hardware or software entropy source is present so the OS CSPRNG seeds promptly at boot
- Verify unpredictability across multiple instances launched from the same image, not only across repeated calls within one instance
