# CWE-477: Use of Obsolete Function - Python

## LLM Guidance

This is about the *status* of the API: Python deprecated it or removed it outright, on a published schedule, so the population is knowable rather than a matter of judgement. PEP 594 removed nineteen standard-library modules in 3.13, `ssl.wrap_socket()` went in 3.12, and `crypt` went in 3.13. The security-relevant ones are those that *were* the security control: a TLS helper that never verified anything, a password-hashing module with no standard-library successor, and remote-access clients with no transport encryption. Establish the target Python version, then replace each withdrawn API with its named successor.

## Key Principles

- `ssl.wrap_socket()` to `ssl.create_default_context()` plus `context.wrap_socket(sock, server_hostname=host)` - the default context already sets `check_hostname=True` and `verify_mode=CERT_REQUIRED`, which the removed helper never did
- Passing `server_hostname` is what makes the hostname check possible; without it `wrap_socket` raises rather than silently skipping the check
- Set `context.minimum_version = ssl.TLSVersion.TLSv1_2` instead of the deprecated `ssl.PROTOCOL_TLSv1`-style constants
- `crypt` to a maintained hasher - `argon2-cffi` (`PasswordHasher`, with `hash()`/`verify()` and a `VerifyMismatchError` on failure) or `bcrypt`; there is no standard-library successor
- `telnetlib` to `paramiko` or an `ssh` subprocess; `pipes.quote()` to `shlex.quote()`; `cgi`/`cgitb`, `asyncore`/`asynchat`, `imp`, and the other PEP 594 modules to their documented replacements
- `hashlib.md5`/`sha1` and the `random` module are *not* deprecated and are current supported API - a scanner filing them here has the wrong CWE. The problem in those cases is the algorithm chosen for a security purpose: CWE-328/CWE-327 for the hash, CWE-338 for the PRNG
- Mark a non-security MD5 use as `hashlib.md5(data, usedforsecurity=False)` (3.9+) so the intent is recorded and the call keeps working on a FIPS-enabled build, where an unflagged call raises `ValueError`
- Run the test suite with `-W error::DeprecationWarning` so a newly deprecated API fails a build rather than surfacing at the next upgrade

## Taint Sinks

`ssl.wrap_socket()`, `crypt.crypt()`, `telnetlib.Telnet()`, `pipes.quote()`, `cgi`/`cgitb` imports, `asyncore`/`asynchat`, `imp.load_source()`, `ssl.PROTOCOL_TLSv1`/`PROTOCOL_SSLv23` constants

## Remediation Steps

- Locate - grep for the withdrawn modules and functions, and run the test suite under `-W error::DeprecationWarning` to surface the rest
- Trace data flow - for the TLS cases, determine which hostnames and trust stores are in play, since the successor requires the peer name explicitly
- Identify the unsafe pattern - an API removed or deprecated by a published Python decision, as distinct from a current API used for the wrong purpose
- Replace with the safe pattern - the documented successor, configured explicitly (context, minimum TLS version, hasher parameters)
- Bind, encode, validate, or authorize - when replacing `crypt`, rehash stored credentials on next successful login rather than migrating them in place
- Harden configuration - pin the target Python version in CI, and treat `DeprecationWarning` as an error in tests
- Test - assert a TLS connection to a host with an invalid or mismatched certificate now fails, and that password verification succeeds against both the old and the newly rehashed formats during migration
