# CWE-798: Use of Hard-coded Credentials - PHP

## LLM Guidance

Hard-coded credentials in PHP are usually a literal in `config.php`, a `define()` at the top of a bootstrap file, or a real `.env` committed alongside the example one. Most findings are *outbound* - a value the application sends to a database or API - and the fix is to read it at runtime through the framework's configuration layer. Check first whether the literal is one the application *accepts*, since that is a backdoor no secret store fixes. Establish what the value authenticates before rotating: a Laravel `APP_KEY` is not merely a credential, and a leaked one was remote code execution before 5.6.30 (CVE-2018-15133).

## Key Principles

- Laravel's rule is that `env()` may be called only from files in `config/`, not that it works "in cached config". Once `config:cache` has run the `.env` file is not loaded at all, and `env()` returns `null` for anything that came from it, wherever it is called. Read values elsewhere through `config('services.key')`
- `$_ENV` may not exist. PHP's engine default for `variables_order` is `EGPCS`, but both shipped ini files - `php.ini-production` and `php.ini-development` - set `GPCS`, which omits `E` and leaves `$_ENV` unpopulated. php.net's own remedy is to use `getenv()`, so a remediation that replaces a literal with `$_ENV['DB_PASS']` can silently read nothing on a stock production configuration
- `getenv()` has its own caveat: under a SAPI such as FastCGI it returns the SAPI's value even where `putenv()` set a local one, unless the `local_only` argument is passed. `vlucas/phpdotenv` populates `$_ENV` and `$_SERVER` by default and treats `getenv()`/`putenv()` as opt-in, discouraging them as not thread safe - so know which of the three the application actually reads
- Both frameworks ship first-party encryption for this, and neither is a secrets manager substitute so much as a way to commit the file safely. Symfony's vault (`secrets:generate-keys`, `secrets:set`, since 4.4, requires the Sodium extension) keeps the prod decryption key off the server and out of git, and note that **environment variables override secrets** where both define a name. Laravel's `env:encrypt`/`env:decrypt` (9.32.0, AES-256-CBC) produce `.env.encrypted` and read the key from `LARAVEL_ENV_ENCRYPTION_KEY`
- On PHP 8.2+ a hard-coded password passed to `PDO::__construct` is redacted from stack traces, because php-src marks that parameter `#[\SensitiveParameter]`; on earlier versions the same literal appears in any trace that unwinds through it. This changes what a leaked log shows, not whether the credential is hard-coded
- Do not rely on Laravel's shipped `public/.htaccess` to deny `.env` - it contains no dotfile rule. The dotfile deny (`location ~ /\.(?!well-known).* { deny all; }`) appears only in the nginx sample in Laravel's deployment documentation, so an Apache deployment needs one written
- Keep only the front controller under the document root: Laravel documents that serving from the project root "will expose many sensitive configuration files to the public Internet", and Symfony's nginx sample returns 404 for every `.php` but `index.php`

## Taint Sinks

`new PDO($dsn, $user, $password)` or `PDO::connect()` with a literal, `define('DB_PASSWORD', ...)`, `curl_setopt($ch, CURLOPT_USERPWD, ...)` and the split `CURLOPT_USERNAME`/`CURLOPT_PASSWORD` forms, `env()` called outside `config/`, a literal compared in an auth path, real values in a committed `.env`, `config.php`, `Dockerfile` `ENV` line or Kubernetes manifest

## Remediation Steps

- Locate - Search source, `config/`, `.env`, deployment manifests and the vhost; a value moved from code into a committed config file is the same finding one file over
- Confirm the direction - A literal compared against user input needs deletion and per-installation enrolment rather than relocation
- Rotate first - The credential is in history and in every clone; for an `APP_KEY` establish what it signed before rotating, since sessions and encrypted columns break with it
- Replace the read - Route the value through `config()` backed by the environment, or through the framework's encrypted-secrets support, and confirm which of `getenv()`, `$_ENV` or `$_SERVER` the code actually reads
- Untrack, do not just ignore - Adding `.env` to `.gitignore` leaves an already-tracked file tracked; `git rm --cached .env` is what removes it, and neither touches history
- Deny the file as well as moving it - Confirm `.env` and any stray config file are not fetchable by URL, adding the dotfile rule where the shipped configuration lacks one
- Test - Confirm the application boots with the value supplied externally, that `config:cache` has not stranded an `env()` call outside `config/`, and that requesting `/.env` returns 403 or 404
