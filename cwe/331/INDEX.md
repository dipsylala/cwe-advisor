# CWE-331: Insufficient Entropy

## LLM Guidance

The generator algorithm is sound and what feeds it is not - entropy quantity or source, rather than choice of algorithm. Where the algorithm itself is the weakness, such as a non-cryptographic PRNG standing in for a CSPRNG, use CWE-338.

## Key Principles

- Trust the platform's ordinary CSPRNG call rather than reaching for a separate "strong" or manually-blocking variant by default. Since Linux 5.6 (2020), the kernel CSPRNG blocks only once, at boot, before first being seeded, and never again - the old model of an entropy pool that can run dry is obsolete there. A language's own "strong" variant can carry a worse cost instead: Java's `SecureRandom.getInstanceStrong()` reads `/dev/random` on every call, not only while unseeded, and has caused production hangs (see the language-specific guidance for which call is which)
- Ensure generated values carry sufficient entropy for their purpose - 128+ bits for session tokens, 256+ bits for symmetric key material - even when using a correct CSPRNG algorithm
- Never seed a random generator from a low-entropy or guessable source (timestamp, process ID, MAC address), even if the generator's output function is itself cryptographically strong
- Be cautious of cloned or templated virtual machine/container images, which can share identical PRNG seed state unless explicitly re-seeded after cloning
- Verify entropy source health on embedded and virtualized systems, where hardware entropy may be scarce or slow to accumulate at boot
- Treat 128 bits as the floor for anything an attacker gains by guessing; below that, brute-force becomes a question about the attacker's budget rather than a settled no
- Prefer 256 bits for long-lived values such as password-reset tokens and API keys - the extra bits cost nothing and these end up in logs, referrer headers, and support tickets
- A v4 UUID carries 122 random bits whatever generator produced it, since 6 of its 128 bits are fixed version and variant markers: adequate as an identifier, below the usual minimum for key material
- A 6-digit out-of-band code carries about 20 bits and is defensible only behind a strict attempt limit, a short expiry, and single use - write those three controls down as part of the fix, because without them the code is the whole authenticator

## Remediation Steps

- Identify the generation point - Locate where a security-sensitive random value (key, token, nonce, IV) is generated and how its underlying entropy source is obtained
- Determine usage context - Check if random values are used for encryption keys, IVs/nonces, session tokens, CSRF tokens, or API keys
- Assess entropy sufficiency - Confirm both the entropy source (a properly seeded OS/hardware entropy pool) and the output length carry enough randomness for the security purpose
- Replace with a properly-seeded CSPRNG - Use the platform's ordinary CSPRNG call, established per the language-specific guidance; reach for a distinct "strong" or blocking variant only where that language's own documentation says the default does not wait for the OS source to be seeded
- Re-seed after cloning - For VM/container images, ensure the entropy pool is explicitly re-seeded on first boot after cloning rather than inheriting the template's state
- Test unpredictability - Verify that sequential calls, including immediately after boot or VM clone, produce non-repeating, non-predictable values
