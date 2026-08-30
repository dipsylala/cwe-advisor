# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - PHP

## LLM Guidance

Use of Cryptographically Weak PRNG in PHP occurs when developers use non-cryptographic functions like `rand()`, `mt_rand()`, or `lcg_value()` for security-sensitive operations such as generating tokens, keys, or passwords. `uniqid()` produces predictable values by a different route worth distinguishing: its default form invokes no PRNG at all, it is `sprintf("%08x%05x", seconds, microseconds)` - a timestamp, not a generator with recoverable state - so the fix is the same (replace it) but the reasoning a developer needs to accept the fix differs from the `rand()` family.

**Primary Defence:** Use `random_bytes()` or `random_int()` for all security-critical random value generation.

## Key Principles

- Replace all `rand()`, `mt_rand()`, `uniqid()`, and `srand()` calls in security contexts with cryptographically secure alternatives
- Use `random_bytes()` for generating random binary data (tokens, keys, salts)
- Use `random_int()` for random integers within a specific range
- Never seed or predict CSPRNG output
- Ensure sufficient entropy (minimum 16 bytes for tokens, 32+ bytes for keys)
- PHP 8.2's `Random\Randomizer` takes an engine and defaults to `Random\Engine\Secure` when none is passed, so an explicit engine argument is only needed to pick a *non*-default (non-cryptographic) one
- `shuffle()`, `str_shuffle()` and `array_rand()` use the non-cryptographic generator, and `mt_srand()` makes the sequence reproducible on purpose
- `lcg_value()` is deprecated as of PHP 8.4 - the vendor's named replacement is `Random\Randomizer::getFloat()`, not `random_int()`, since `lcg_value()` returns a float in (0,1)

## Taint Sinks

`rand()`, `mt_rand()`, `uniqid()` (timestamp-based, not a PRNG call - see CWE-330 for its mechanism), `srand()`, `lcg_value()`

## Remediation Steps

- Identify all uses of weak PRNGs in authentication, session management, cryptography, and token generation
- Replace `rand()`/`mt_rand()` with `random_int()` for integer values
- Replace `uniqid()` with `bin2hex(random_bytes())` for unique identifiers
- Ensure proper encoding when converting binary random data (use `bin2hex()` or `base64_encode()`)
- Review and test all changes to verify randomness quality
- Remove any custom seeding logic for PRNGs
