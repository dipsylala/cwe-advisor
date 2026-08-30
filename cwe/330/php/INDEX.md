# CWE-330: Use of Insufficiently Random Values - PHP

## LLM Guidance

A CWE-330 finding in PHP is a session token, reset token, API key or CSRF token built from `rand()`, `mt_rand()`, `uniqid()` or a shuffle helper. Replace them with `random_bytes()` and `random_int()`, available since PHP 7.0, or with `Random\Randomizer` on PHP 8.2 and later - the manual's own warning on every weak function names `Random\Randomizer` with `Random\Engine\Secure` first. Several of these functions changed behaviour across 7.1, 7.4, 8.0, 8.2 and 8.4, so establish the PHP version before deciding what the finding is.

## Key Principles

- `rand()` has been an alias of `mt_rand()` since PHP 7.1 - they are one generator, not two separate weaknesses. Both use the global Mt19937 instance, and every function sharing that instance advances the same sequence
- `uniqid()` is not a PRNG. Its default form is the current time formatted as `sprintf("%08x%05x", seconds, microseconds)`, with no random draw at all; the manual describes it as "an identifier based on the current time with microsecond precision". Its weakness is that the value is derivable from the time rather than recoverable from generator state, so the remediation is to replace it, not to add entropy to it
- `random_bytes()` and `random_int()` fail closed, which is what makes them safe - never catch and fall back to `mt_rand()`. The exception class changed: a plain `Exception` before PHP 8.2 and `Random\RandomException` from 8.2, which extends `Exception`, so a `catch (Exception $e)` still catches it on every version. A `ValueError` from a bad length or range is a separate, non-randomness failure
- `openssl_random_pseudo_bytes()` no longer has a weak mode to detect. Since PHP 7.4 it throws on failure instead of returning `false`, and `strong_result` is set true on every successful return - the RFC's vote to deprecate that parameter failed, so it remains present but no longer discriminates. Treat a finding on it as a modernisation rather than an incident: the bytes it produced are sound and need no rotation. The live weakness is any `if (!$crypto_strong)` fallback, now unreachable, sitting in the codebase looking like defensive programming
- `array_rand()`, `str_shuffle()` **and `shuffle()`** all carry the manual's identical caution: they use the global Mt19937 and "must not be used for cryptographic purposes, or purposes that require returned values to be unguessable"
- `lcg_value()` is deprecated as of PHP 8.4 because, in php-src's words, "the function is broken in multiple ways". The vendor's named replacement is `Random\Randomizer::getFloat()`, not `random_int()` - `lcg_value()` returns a float in (0,1), which `random_int()` cannot produce
- `password_hash()` generates its own salt, and the `salt` option was **removed in PHP 8.0**, not merely discouraged: passing one now raises a warning and is ignored. On any supported PHP it cannot do harm, so a finding about a bad salt passed to `password_hash()` is stale

## Taint Sinks

`rand(`, `mt_rand(`, `uniqid(`, `lcg_value(`, `array_rand(`, `str_shuffle(`, `shuffle(`, `mt_srand(`, `srand(`

## Remediation Steps

- Identify the weak call and the PHP version together, then confirm the value's unpredictability is load-bearing - `mt_rand()` is the right choice for jitter, sampling or a shuffled result set, and converting those costs throughput for nothing
- Replace token generation with `bin2hex(random_bytes(16))` for 32 hex characters carrying 128 bits, or on PHP 8.3+ with `(new Random\Randomizer())->getBytesFromString($alphabet, $length)`, whose default engine is `Random\Engine\Secure`. Note that the same "32 characters" is only 128 bits under hex - `base64_encode(random_bytes(16))` yields 24 characters for the same entropy
- Replace bounded integers with `random_int($min, $max)` or `Random\Randomizer::getInt()`, rather than reducing `random_bytes()` output with `% strlen($chars)`, which biases the low end of the alphabet whenever the length does not divide 256
- Leave PHP's own session IDs alone unless a setting has weakened them. The default is 32 hexadecimal characters at 4 bits each, which is 128 bits and already meets the floor; `session.sid_length` and `session.sid_bits_per_character` are deprecated as of PHP 8.4 in favour of that default, so a finding is a codebase that lowered them
- Delete derived constructions rather than rehashing them. `md5(uniqid())`, `sha1(microtime())` and `hash('sha256', mt_rand())` are each exactly as guessable as their input, since hashing spreads entropy without creating any
- Check any hand-rolled `uuid()` helper for what it is built on. PHP has no built-in UUID function, so the name guarantees nothing - `ramsey/uuid`'s `Uuid::uuid4()` is sound, while `uuid1()` and `uuid7()` embed a timestamp and belong in no token
- Rotate the tokens a *weak* generator issued - `mt_rand()`, `uniqid()` and the shuffle helpers - because switching generation alone leaves guessable values valid until they expire. Bytes from `openssl_random_pseudo_bytes()` are the exception noted above and need no rotation
