# CWE-331: Insufficient Entropy - JavaScript

## LLM Guidance

Insufficient entropy here is not about `crypto.randomBytes()`/`crypto.getRandomValues()` being the wrong function - they are correct CSPRNG APIs (contrast with CWE-338's `Math.random()` problem). The risk is calling them before the platform's entropy source is ready, or from a cloned container/VM image sharing seed state. Node's own documentation says only that `crypto.randomBytes()` "will not complete until there is sufficient entropy available" and that this "should normally never take longer than a few milliseconds", with the one exception being "right after boot, when the whole system is still low on entropy" - it does not single out the synchronous form as the risk. Calling the synchronous form on the main thread does block whatever else is waiting on that thread during that wait, same as any synchronous Node API, so the asynchronous form is still the safer default for a boot-time call; `crypto.getRandomValues()` has no asynchronous form at all, so that mitigation is not available to it. Browsers' `crypto.getRandomValues()` relies entirely on the OS CSPRNG and offers no visibility into entropy-pool state.

## Key Principles

- `crypto.randomBytes()`/`crypto.getRandomValues()` are the correct APIs; the defect is calling them before the OS entropy source is seeded, or from an image/instance sharing seed state with a clone - not the choice of function
- For values generated during application or container startup, prefer the asynchronous `crypto.randomBytes(size, callback)` form so a boot-time entropy wait doesn't block whatever else is running on that thread; `crypto.getRandomValues()` has no async equivalent, so a boot-time caller using it has no such escape
- Generate sufficient entropy regardless of correct API: 16+ bytes (128+ bits) for tokens, 32+ bytes (256+ bits) for keys
- Be cautious of container/VM images that bake in secrets at build time; instances cloned or scaled from the same image can share identical secret or seed material unless generation is deferred to runtime
- On embedded or minimal container base images, verify the host's OS-level entropy source is healthy, especially at cold start, since Node.js has no independent entropy source of its own

## Taint Sinks

`crypto.randomBytes()` (synchronous form) and `crypto.getRandomValues()` calls used for key/token generation during process, container, or VM startup, or in image build scripts

## Remediation Steps

- Locate where `crypto.randomBytes()`/`crypto.getRandomValues()` generate tokens, keys, or session IDs, and identify whether generation happens at container/process startup, in a build script, or during normal request handling
- For startup-time or boot-time generation, use the asynchronous `crypto.randomBytes(size, callback)` form (or its promisified equivalent) instead of the synchronous variant
- Confirm output length: 16+ bytes for tokens, 32+ bytes for keys
- Do not bake long-lived secrets into a container/VM image at build time; generate them at first real runtime so cloned instances don't share seed or secret state
- On minimal or embedded container base images, verify the host's OS entropy source is healthy, since Node.js relies entirely on the platform CSPRNG
- Verify unpredictability across multiple instances launched from the same image or container, not only across repeated calls within one instance
