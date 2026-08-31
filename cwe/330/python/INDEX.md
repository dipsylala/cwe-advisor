# CWE-330: Use of Insufficiently Random Values - Python

## LLM Guidance

The `random` module is backed by the Mersenne Twister and, in CPython's own words, is "completely unsuitable for cryptographic purposes"; `secrets` is the replacement for tokens, keys, salts and nonces. `secrets` is a thin layer over `random.SystemRandom`, which is itself a layer over `os.urandom`, so the three are one source rather than three options. Take care with the swap itself: the `random` and `secrets` functions that look like counterparts have different arities and different ranges, so a token-for-token substitution changes what the code produces.

## Key Principles

- `random.randint(a, b)` returns `a <= N <= b`; `secrets.randbelow(n)` takes one argument and returns `0 <= N < n`. Swapping one for the other drops the lower bound entirely, since `randbelow` has no parameter to receive it - `randint(1, 6)` becomes `0..5`, losing 6 and gaining 0, while `randbelow(1, 6)` is a `TypeError`. The range-preserving form is `a + secrets.randbelow(b - a + 1)`. `randbelow` also raises `ValueError` on a bound of zero or less, where `randint(0, 0)` is legal
- The argument to `secrets.token_urlsafe`, `token_hex` and `token_bytes` is a number of **bytes**, not characters. `token_hex(16)` returns 32 characters and `token_urlsafe(16)` about 22, both carrying 128 bits
- `secrets.DEFAULT_ENTROPY` is 32, so `token_urlsafe(32)` is byte-for-byte identical to `token_urlsafe()`. Passing 32 explicitly changes nothing, and PEP 506 records that the default "is expected to change in the future, possibly even in a maintenance release" - which is a reason to pass a length deliberately, not a reason to pass this one
- Size to at least 128 bits, the ASVS floor. CPython describes 32 bytes as what "is believed" sufficient "as of 2015" for the module's typical use case, which is a dated default rather than a minimum; OWASP's session-identifier floor is 64 bits of entropy and ASVS 5.0.0 requires 128
- `random.seed()` generates no values and is not itself a sink. Called with no argument it draws from the OS randomness source; the finding is a *fixed or attacker-derivable* seed argument, and even then the fix is to change the generator rather than the seed
- `uuid.uuid4()` draws `os.urandom(16)` and is documented as generated "in a cryptographically-secure method", leaving 122 random bits after the version and variant bits - an identifier, not a secret. `uuid8` is explicitly not CSPRNG-backed by default and its own docs say to "use `uuid4()` when a UUID needs to be used in a security-sensitive context"; `uuid1()` embeds the computer's network address
- `os.urandom()` blocks on Linux until the kernel pool is first initialized (PEP 524) and raises `NotImplementedError` where `/dev/urandom` is unreadable. CPython points to `secrets` as the higher-level interface rather than presenting the two as equivalent
- PyJWT checks HMAC key length against RFC 7518's floor (256 bits for HS256) but only warns by default - `InsecureKeyLengthWarning`, not an error - so a short secret still signs and verifies unless `enforce_minimum_key_length=True` is set explicitly. Generate the key with `secrets.token_bytes(32)` rather than relying on the warning to be noticed

## Taint Sinks

`random.random()`, `random.randint(`, `random.randrange(`, `random.choice(`, `random.shuffle(`, `random.getrandbits(`, `random.sample(`, `uuid.uuid1(`, `uuid.uuid8(`

## Remediation Steps

- Locate uses of the `random` module on security paths and confirm for each that unpredictability is what makes the value work - `random` remains correct for sampling, jitter, shuffling and test fixtures
- Replace token generation with `secrets.token_urlsafe()` or `secrets.token_hex()`, choosing the byte count deliberately, and bounded integers with `secrets.randbelow()`, re-adding the lower bound where the original had one
- Generate passwords with the composition loop from CPython's own recipe: build the whole candidate from `secrets.choice(alphabet)`, test it against the composition rule, and regenerate the entire string on failure. Patching individual characters to satisfy the rule biases the result
- Compare tokens and other secrets with `secrets.compare_digest`, which is constant-time, rather than `==`
- Use the framework's helper where one exists: Django's `django.utils.crypto.get_random_string` is built on `secrets.choice`, and its `length` argument has been required since Django 4.0 after being deprecated in 3.1; Flask's documented way to produce a `SECRET_KEY` is `python -c 'import secrets; print(secrets.token_hex())'`
- Rotate values the weak generator issued, since switching generation leaves the guessable ones valid until they expire
- Where a test needed reproducible values and that is why `random` is on the production path, inject a generator the test can substitute rather than keeping the weak one. `secrets` cannot be seeded at all - `random.SystemRandom` documents that its `seed()` "has no effect and is ignored" and that `getstate()` raises `NotImplementedError` - and that is the property being asked for, seen from the other side
- Verify by reading which module the security path imports, not by inspecting the output or attempting to measure its entropy. No CPython API validates the entropy of a produced token, and every standard specifies entropy as a property of the generator and the requested length rather than a property you can check afterwards. Mersenne Twister is, in the same CPython paragraph, "one of the most extensively tested random number generators in existence", so its output passes any statistical check applied to it
