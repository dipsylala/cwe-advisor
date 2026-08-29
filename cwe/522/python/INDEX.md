# CWE-522: Insufficiently Protected Credentials - Python

## LLM Guidance

Insufficiently protected credentials in Python appear as plaintext storage, a fast digest used as a password hash, or a secret that reaches logs and tracebacks. Separate the two cases before fixing either: a user password is hashed with an adaptive algorithm and never read back, while a credential the application must present to another system is fetched at runtime from the environment or a secrets manager. `hashlib` says it directly - "Naive algorithms such as `sha1(password)` are not resistant against brute-force attacks. A good password hashing function must be tunable, slow, and include a salt."

## Key Principles

- Prefer `argon2-cffi`'s `PasswordHasher`, whose defaults follow the RFC 9106 low-memory profile and which exposes `check_needs_rehash()` for migrating parameters on a successful verify. `bcrypt` called directly is the other reasonable choice; `pwdlib` wraps both, and its README states plainly that "Starting Python 3.13, `passlib` won't work anymore"
- **The passlib situation is version-specific and worth getting right.** passlib's last release is 1.7.4 from October 2020. `bcrypt` removed the `__about__` module in **4.1.0**, which passlib's backend probe reads, so on 4.1.0 and later it logs a `(trapped) error reading bcrypt version` traceback while still hashing correctly. `bcrypt` **5.0.0** then changed `hashpw` to raise rather than truncate - its changelog reads "Passing hashpw a password longer than 72 bytes now raises a ValueError. Previously the password was silently truncated" - and with passlib's probe already broken this surfaces as `password cannot be longer than 72 bytes, truncate manually if necessary` on passwords that are nothing of the kind
- Before rewriting call sites, consider `libpass`, a maintained fork of passlib on PyPI whose 1.9.3 release unpinned `bcrypt` and fixed the version detection. Pinning `bcrypt < 5.0` is a stopgap, not a destination
- bcrypt ignores everything past 72 bytes, and that is bytes rather than characters. On 5.0+ an over-length password raises instead, so a codebase that quietly accepted long passphrases starts failing at the hash call - a migration event, not a bug in the fix
- The standard library has adaptive options when a dependency is unwelcome: `hashlib.scrypt` and `hashlib.pbkdf2_hmac`, whose docs suggest "hundreds of thousands of iterations of SHA-256" and a salt of 16 or more bytes from `os.urandom()`. `usedforsecurity=False` (3.9+) is how a non-security digest declares itself rather than a way to keep MD5 for passwords
- Compare secrets that are not passwords with `secrets.compare_digest`, which the docs describe as a "constant-time compare" to reduce timing-attack risk. A plain `==` on an API token leaks its prefix
- `cryptography`'s Fernet is **AES-128 in CBC mode with HMAC-SHA256**, not AES-256 - describe it accurately when it is the answer. It also puts the generation time in the token in plaintext, and `MultiFernet.rotate()` is the documented way to re-encrypt under a new primary key, which is what makes the rotation advice actionable
- `python-dotenv`'s `load_dotenv()` does not override a variable already in the environment unless `override=True`, so a stale export silently wins. Floor it at 1.2.2 (CVE-2026-28684)

## Taint Sinks

`hashlib.md5()`/`hashlib.sha1()`/`hashlib.sha256()` used as a password hash, `passlib.context.CryptContext` on a current `bcrypt`, a token compared with `==`, hardcoded secrets in source, `print()`/`logging` of credentials, a committed `.env`

## Remediation Steps

- Separate the two cases - Hash what only needs recognising; fetch what must be presented elsewhere
- Locate - Run `bandit` and read the check ids: `B105`/`B106`/`B107` for hardcoded passwords, `B324` for MD4/MD5/SHA1 through `hashlib`
- Replace the digest - Move to `argon2-cffi` or `bcrypt`, and rehash inside the successful-verify branch when the configured parameters have moved on
- Check the bcrypt boundary - Confirm what the application does with a password over 72 bytes before and after the change, since 5.0 turned silent truncation into an exception
- Externalise the rest - Read credentials from the environment or a secrets manager, and let absence raise at startup
- Untrack, do not just ignore - Adding `.env` to `.gitignore` leaves an already-tracked file tracked; `git rm --cached .env` is what removes it
- Rotate - Treat anything that reached version control as compromised, and for Fernet-encrypted data use `MultiFernet.rotate()` rather than decrypt-and-re-encrypt by hand
