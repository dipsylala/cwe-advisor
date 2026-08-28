# CWE-15: External Control of System or Configuration Setting - Python

## LLM Guidance

In Flask, Django, and FastAPI applications this occurs when request data (`request.form`, `request.args`, `request.json`, POST body) is written into `os.environ`, `app.config`, `django.conf.settings`, or a logger's level at runtime. The fix is to load configuration once at startup with Pydantic `BaseSettings` (or Flask/Django's own settings mechanism) driven entirely from environment variables and config files, and to keep that object immutable from any HTTP-reachable code path. Where a setting must change at runtime (log level, feature flag), gate it behind an admin-only decorator and an explicit allowlist.

## Key Principles

- Load configuration once at startup with Pydantic `BaseSettings` (`model_config = {"frozen": True}`) or an equivalent Flask `Config` class/Django settings module populated from environment variables, never from `request.form`/`request.json`
- Never call `os.environ[key] = value`, `app.config[key] = value`, or `setattr(settings, key, value)` with a key or value taken directly from the request
- Treat a request-reachable config write as high severity because of which keys it reaches: Flask's `DEBUG` (exposes the Werkzeug console), `SECRET_KEY` (forges sessions), `SESSION_COOKIE_SECURE`/`SESSION_COOKIE_HTTPONLY`/`SESSION_COOKIE_SAMESITE`, and Django's `ALLOWED_HOSTS`
- Use `Literal[...]` (Pydantic) or an `Enum` (FastAPI path/query parameter) for constrained settings so the framework rejects out-of-range values automatically
- Any admin endpoint that changes a setting must require an admin-only decorator (Flask `admin_required`, Django `@staff_member_required`, or a FastAPI `Depends(require_admin)`) and check both the key and value against a `dict`/`set` allowlist before applying it
- Never pass a request-controlled path to `configparser.read()`/`open()` for config loading, and use `yaml.safe_load()` (never `yaml.load()`/`yaml.Loader`) for any uploaded YAML configuration
- Log both accepted and rejected configuration changes with the acting user's identity

## Taint Sinks

`os.environ[key]=`, `app.config[key]=`, `setattr(settings, ...)`, `logging.getLogger().setLevel()`

## Remediation Steps

- Locate - find where `request.form`, `request.args`, `request.json`, or `request.POST` flows into `os.environ[...]`, `app.config[...]`, `setattr(settings, ...)`, `logging.getLogger().setLevel()`, or `configparser.read()`/`yaml.load()` with a path or file argument
- Trace data flow - follow the value from the view/route function parameter to the assignment or call that consumes it, including any dict it is merged into
- Replace the unsafe pattern - move the setting into a Pydantic `BaseSettings` class (or Flask `Config`/Django settings) populated from environment variables or `.env` at deployment, not from the request
- Bind, encode, validate, or authorize - if the value must stay runtime-configurable, require an admin-only decorator and validate the key/value pair against an allowlist `dict` of permitted settings
- Break taint after allowlist validation - assign the matched allowlist entry to a fresh local variable before calling `logging.getLogger().setLevel()` or `config_service.apply()`, never the raw request value
- Harden configuration - use Pydantic validators or `Literal[...]` types so invalid configuration raises `ValidationError` at startup instead of degrading security silently
- Test - submit values outside the allowlist and confirm 400, confirm unauthenticated calls to admin config endpoints return 401/403, and confirm assigning to a frozen `BaseSettings` field raises an error
