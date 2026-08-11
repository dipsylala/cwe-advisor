# CWE-331: Insufficient Entropy

## LLM Guidance

CWE-331 occurs when a security-sensitive value is generated with insufficient actual randomness even though the generator algorithm itself is cryptographically sound - the problem is entropy quantity or source, not algorithm choice (contrast with CWE-338, where the algorithm itself, e.g. a non-cryptographic PRNG, is the weakness). Common causes: seeding a CSPRNG from a low-entropy source, drawing from a hardware entropy pool that hasn't yet accumulated enough randomness at early boot on embedded or virtualized systems, generating a value with too few random bits for its security purpose, or cloning virtual machine images that then share identical PRNG seed state. The fix is to ensure the generator draws from a properly-seeded, sufficiently-entropic source and that generated values carry enough bits of randomness for their purpose.

## Key Principles

- Use the platform's blocking or entropy-aware random source (not just any CSPRNG API) when generating security-critical values early in a system's lifecycle, before the entropy pool is guaranteed to be filled
- Ensure generated values carry sufficient entropy for their purpose - 128+ bits for session tokens, 256+ bits for symmetric key material - even when using a correct CSPRNG algorithm
- Never seed a random generator from a low-entropy or guessable source (timestamp, process ID, MAC address), even if the generator's output function is itself cryptographically strong
- Be cautious of cloned or templated virtual machine/container images, which can share identical PRNG seed state unless explicitly re-seeded after cloning
- Verify entropy source health on embedded and virtualized systems, where hardware entropy may be scarce or slow to accumulate at boot

## Remediation Steps

- Identify the generation point - Locate where a security-sensitive random value (key, token, nonce, IV) is generated and how its underlying entropy source is obtained
- Determine usage context - Check if random values are used for encryption keys, IVs/nonces, session tokens, CSRF tokens, or API keys
- Assess entropy sufficiency - Confirm both the entropy source (a properly seeded OS/hardware entropy pool) and the output length carry enough randomness for the security purpose
- Replace with a properly-seeded CSPRNG - Use the platform's blocking or entropy-aware random API where early-boot or low-entropy environments are a concern (see the language-specific guidance's Safe Pattern for concrete APIs)
- Re-seed after cloning - For VM/container images, ensure the entropy pool is explicitly re-seeded on first boot after cloning rather than inheriting the template's state
- Test unpredictability - Verify that sequential calls, including immediately after boot or VM clone, produce non-repeating, non-predictable values
