# CWE-798: Use of Hard-coded Credentials - Python

## LLM Guidance

Hard-coded credentials in Python are usually a module-level literal or a keyword argument to a connect call, and they persist in version control long after the line is deleted. Most findings are *outbound* - a value the application sends to a database or API - and the fix is to read it at runtime. Check first whether the literal is one the application *accepts*, such as a token compared in a decorator, because that is a backdoor no secret store fixes. Rotate before refactoring: removing the literal changes what the code does, not who holds the secret.

## Key Principles

- Read the value where absence is loud. `os.environ['SECRET']` raises `KeyError`, while `os.getenv('SECRET')` and `os.environ.get('SECRET')` both return `None` and let the application start in a broken state - and `os.getenv` is documented as using `os.environ`, so they differ only in that failure behaviour. Note `os.environ` is captured when `os` is first imported, so a variable exported after startup is not seen
- `pydantic-settings` is the idiomatic fail-closed shape: a required field with no value raises `ValidationError` at construction rather than at first use. Pair it with pydantic's `SecretStr`, which renders as `**********` in `repr()`, `str()` and JSON, so a settings object logged whole does not disclose the value
- SQLAlchemy's `URL.create(...)` keeps the password out of the object's own output: `render_as_string()` masks it as `***` and is what `__str__`/`__repr__` call, and `Engine.__repr__` goes through it, so a logged engine or URL is safe where a hand-formatted connection string is not. `render_as_string(hide_password=False)` is the deliberate reveal - the masking covers the URL object, not driver exceptions
- `python-dotenv`'s `load_dotenv()` does **not** override a variable already present in the environment unless `override=True`, so a stale value exported in the shell silently wins over the `.env` the developer just edited. Floor it at 1.2.2 (CVE-2026-28684)
- Floor `requests` at **2.32.4**: 2.31.0 closed a `Proxy-Authorization` header leak on redirect (CVE-2023-32681) and 2.32.4 a `.netrc` credential leak to a malicious URL (CVE-2024-47081) - both disclose exactly the credential `HTTPBasicAuth` carries
- New work should use psycopg 3, imported as `psycopg` rather than `psycopg3`, which takes the same `password=` keyword; psycopg2 remains supported but is documented as not expecting new features
- `boto3` resolves credentials in a documented order that starts with the arguments passed to `client()`, so a literal there wins over every environment and role-based source - removing the argument is what lets the instance role take over, and AWS's own guidance is not to hard-code them
- Generate replacement credentials with `secrets`, not `random`: the standard library states `secrets` "should be used in preference to" `random`, whose generator is for modelling rather than security. `secrets.token_urlsafe()` is the usual shape
- Environment variables are a fallback rather than a store, but state the exposure accurately: `/proc/<pid>/environ` is governed by a `PTRACE_MODE_READ_FSCREDS` check, so it is readable by the same user or a process holding `CAP_SYS_PTRACE`, not by any local account. The concrete exposures are `docker inspect`, which Docker documents as where `ENV` values can be viewed, and inheritance by every child process

## Taint Sinks

`psycopg2.connect(password=...)` or `psycopg.connect(password=...)` with a literal, module-level `PASSWORD = "..."`, `boto3.client(aws_secret_access_key=...)`, `requests.auth.HTTPBasicAuth()`, a literal compared in an auth decorator, real values in a committed `.env`, `Dockerfile` `ENV` line or Kubernetes manifest

## Remediation Steps

- Locate - Run `bandit` and read the specific checks rather than the summary: `B105` catches the module-level literal, `B106` a password passed as a keyword argument, `B107` one used as a function-argument default. All three map to CWE-259 and the docs note `B106` is noisy
- Confirm the direction - A literal compared against user input needs deletion and per-installation enrolment, not a secrets manager
- Rotate first - The value is in history and in every clone, so revoke before editing
- Replace the read - Take the secret from the environment or a named client (`boto3` Secrets Manager, `azure-keyvault-secrets`, `google-cloud-secret-manager`), and let absence raise
- Untrack, do not just ignore - Adding `.env` to `.gitignore` leaves an already-tracked file tracked; `git rm --cached .env` is what removes it, and neither touches history
- Test - Confirm the application starts with the value supplied externally and fails at startup with a clear error when it is absent
