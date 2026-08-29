# CWE-522: Insufficiently Protected Credentials - PHP

## LLM Guidance

Insufficiently protected credentials in PHP commonly appear as database passwords or API keys in `config.php`, a committed `.env`, or passwords stored with `md5()`/`sha1()`. Separate the two cases before fixing either: a user password is hashed with `password_hash()` and never read back, while a credential the application must present to another system is loaded at runtime from the environment or a secrets manager. The reason `md5()` and `sha1()` are wrong for passwords is speed rather than reversibility - php.net's own warning on both functions points at "the fast nature of this hashing algorithm".

## Key Principles

- `password_hash($password, PASSWORD_BCRYPT)` truncates the input to 72 bytes. php.net documents this as a caution on the `password` parameter, and it is silent - a passphrase longer than that authenticates on its first 72 bytes, and no version returns `false` or throws for it. Where long passphrases matter, use `PASSWORD_ARGON2ID` or pre-hash before bcrypt
- `PASSWORD_ARGON2ID` exists from PHP 7.3 but "is only available if PHP has been compiled with Argon2 support", so it is a build-dependent constant rather than something to assume. Check availability before prescribing it
- The bcrypt cost default changed from 10 to 12 in PHP 8.4, so an explicit `['cost' => 12]` matches the current default rather than raising it. `PASSWORD_DEFAULT` is documented to change between releases, which is why the stored column should hold at least 255 bytes
- `password_verify()` is documented safe against timing attacks, and `password_needs_rehash()` after a successful verify is the supported way to migrate cost or algorithm. For any other secret comparison use `hash_equals()`, passing the user-supplied value as the *second* argument - the vendor notes that unequal lengths return immediately, which can leak the known string's length
- Where a server sets the variable, know which superglobal receives it. In CGI and FastCGI, php.net states `S` "is always equivalent to `ES`", so an Apache `SetEnv` or nginx `fastcgi_param` value arrives in `$_SERVER`. `$_ENV` is a separate question: both shipped ini files set `variables_order = "GPCS"`, which omits `E` and leaves `$_ENV` unpopulated
- `vlucas/phpdotenv` writes to `$_ENV` and `$_SERVER`, not to `getenv()`. Its `getenv()` support is opt-in through `createUnsafeImmutable`/`createUnsafeMutable` and the README calls those functions "strongly discouraged" as not thread safe - so loading with phpdotenv and then reading with `getenv()` returns nothing
- On PHP 8.2+ php-src marks the plaintext parameter of `password_hash`, `password_verify`, `crypt` and `hash_equals` with `#[\SensitiveParameter]`, so those frames are redacted in a stack trace. A project's own `login($user, $password)` wrapper is not, and needs the attribute added to stay out of traces

## Taint Sinks

`md5($password)`, `sha1($password)`, `hash('sha256', $password)` for password storage, hardcoded credentials in `config.php`, a credential compared with `==` or `===` rather than `hash_equals()`, a committed `.env`

## Remediation Steps

- Separate the two cases - Hash what only needs recognising; fetch what must be presented to another system
- Replace the digest - Move `md5()`/`sha1()` storage to `password_hash($password, PASSWORD_BCRYPT)`, verify with `password_verify()`, and rehash inside the successful-verify branch when `password_needs_rehash()` says the algorithm or options changed
- Externalise the rest - Load credentials from the environment through the mechanism that actually populates it, confirming whether the value lands in `$_SERVER`, `$_ENV` or `getenv()` in this deployment
- Deny the file with current syntax - `Deny from all` is Apache 2.2 syntax supplied by `mod_access_compat`, which Apache marks Deprecated and warns takes precedence over the modern directives when both appear. It also carries no filename scoping of its own, so writing it bare in an `.htaccess` denies the whole directory rather than one file. The 2.4 form is `Require all denied` inside a `<Files ".env">` container, which is what Apache's own shipped `httpd.conf` uses for `.ht*`
- Untrack, do not just ignore - Adding `.env` to `.gitignore` leaves an already-tracked file tracked; `git rm --cached .env` is what removes it, and neither touches history
- Search history properly - `git log -S'password'` finds commits changing the number of occurrences of a string and `git log -G'regex'` matches added or removed lines, which is what a `git log -p | grep` pipeline is approximating
- Rotate - Treat anything that reached version control as compromised and revoke it before or alongside the cleanup
