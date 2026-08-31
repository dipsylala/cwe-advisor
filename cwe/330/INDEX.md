# CWE-330: Use of Insufficiently Random Values

## LLM Guidance

Insufficient randomness means a security-relevant value - a session ID, token, key, salt or nonce - came from a general-purpose PRNG rather than the platform's cryptographic generator. The fix is to change the source; changing the seed or the shape of the output does nothing. First confirm the value's unpredictability is what makes it work, because those same generators are correct for simulation, shuffling, jitter and test fixtures, where converting call sites costs throughput and buys nothing.

## Key Principles

- Replace the generator, not the seed. `random`, `Math.random()`, `rand()`, `java.util.Random`, `System.Random` and `math/rand` are unsuitable however they are seeded - Go's own documentation states that its outputs "might be easily predictable regardless of how it's seeded"
- Anything derived from a weak value stays weak. Hashing, encoding, appending a timestamp or truncating changes how the output looks without adding entropy - the result is still fully determined by the predictable input
- Do not seed a CSPRNG - but check that the API even permits it before writing that as a finding. Python's `secrets`, Node's `crypto.randomBytes` and Go's `crypto/rand` expose no seeding function at all. Java's `SecureRandom.setSeed` does, and its Javadoc states the seed "supplements, rather than replaces, the existing seed. Thus, repeated calls are guaranteed never to reduce randomness." The documented hazard there is ordering rather than entropy: a PRNG `SecureRandom` will not self-seed if `setSeed` is called before any `nextBytes`
- Size to a floor rather than by role: OWASP ASVS requires at least 128 bits of entropy for any value intended to be non-guessable, while key material is sized by its algorithm - a 256-bit key because the cipher takes one, not because keys are categorically larger than tokens. Check the length once the source is right, remembering that hex doubles the character count, so a 32-character hex token carries 128 bits and not 256. A JWT HMAC signing key is exactly this case: RFC 7518 requires a key at least as large as the hash output - 256 bits for HS256 - and most JWT libraries accept a shorter key silently rather than rejecting it, so the floor has to be enforced at generation, not by the library
- Prefer the platform's own token API over hand-rolled bytes-plus-encoding, and name it exactly - a helper cited under a name the framework does not use sends the remediation nowhere
- A generator cannot be validated by inspecting its output. NIST SP 800-22: "no set of statistical tests can absolutely certify a generator as appropriate for usage in a particular application, i.e., statistical testing cannot serve as a substitute for cryptanalysis"

## Remediation Steps

- Identify weak generators in security contexts (see the language-specific guidance's Taint Sinks for concrete names), asking of each hit what guessing the value would gain an attacker
- Replace with the platform's cryptographic generator, sized to purpose, establishing the language version first - several of these APIs changed what they do, not only what they are called
- Rotate what the old generator issued. Pointing new generation at a secure source leaves every previously issued token valid until it expires or is revoked - the half of the fix usually skipped
- Reject a fix that narrows the output through a biased mapping. A modulo into a short alphabet, or a truncation for readability, shrinks the keyspace the new source just supplied; use the platform's bounded-integer API, which discards and retries
- Do not verify by looking at the values. Mersenne Twister is non-sequential and among the most extensively tested generators in existence, so "output is not sequential and not obviously predictable" passes against the unfixed code. Verify which generator the path reaches, and assert the length it returns
