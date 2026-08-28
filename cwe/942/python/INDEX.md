# CWE-942: Permissive Cross-domain Policy with Untrusted Domains - Python

## LLM Guidance

In Flask, Django, and FastAPI, this weakness usually appears as a CORS extension - `flask-cors`, `django-cors-headers`, or FastAPI's `CORSMiddleware` - configured with a wildcard origin, or as an `after_request`/middleware hook that copies the incoming `Origin` header straight into the response. All three ecosystems have well-maintained CORS libraries that make an explicit allowlist as easy as a wildcard, so the fix is almost always a configuration change. The primary remediation is an explicit list of trusted origins, never a literal `*` or a reflected header, and never combined with credentialed responses.

## Key Principles

- Configure `flask-cors` (`CORS(app, resources={...})`), `django-cors-headers` (`CORS_ALLOWED_ORIGINS`), or FastAPI's `CORSMiddleware` (`allow_origins=[...]`) with an explicit list of trusted origins, not `"*"`
- Never enable `supports_credentials=True` / `allow_credentials=True` / `CORS_ALLOW_CREDENTIALS = True` alongside a wildcard origin; pair credentials only with the explicit allowlist
- Never manually copy `request.headers.get("Origin")` into `Access-Control-Allow-Origin` without checking it against an allowlist first
- With `django-cors-headers`, prefer `CORS_ALLOWED_ORIGINS` (exact list) over `CORS_ALLOWED_ORIGIN_REGEXES`; if a regex is required, anchor it and avoid a bare `.*` for the subdomain portion, which also matches path separators and other URL-special characters
- Restrict allowed methods and headers (`allow_methods`, `allow_headers`, `CORS_ALLOW_METHODS`) to what each API route needs
- Verify the CORS library version in the project manifest (`requirements.txt`/`pyproject.toml`) supports allowlist-based configuration, since older releases of these packages default to permissive behavior

## Taint Sinks

`CORS(app, origins="*")`, `CORSMiddleware(allow_origins=["*"])`, unanchored `CORS_ALLOWED_ORIGIN_REGEXES`, manual `response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin")`

## Remediation Steps

- Locate - Search for `CORS(`, `CORSMiddleware`, `CORS_ALLOWED_ORIGINS`, `Access-Control-Allow-Origin`, and manual header-setting code in `after_request`/middleware hooks
- Trace data flow - Confirm whether the configured or set origin value is a literal `"*"`, a reflected `request.headers.get("Origin")`, or a real allowlist
- Replace the unsafe pattern - Replace the wildcard or reflection with an explicit origin list in the framework's CORS configuration (`flask-cors`, `django-cors-headers`, or `CORSMiddleware`)
- Bind, encode, validate, or authorize - Let the CORS library perform the origin match against the fixed list; do not hand-roll comparison logic in view code
- Break taint after allowlist validation - If a custom `after_request` hook is required, echo back only the matched allowlist entry, never the raw `Origin` header value
- Harden configuration - Enable credentials only alongside the explicit allowlist, and scope allowed methods/headers per route or resource pattern
- Test - Send a request with an allowed `Origin` and confirm it is echoed back in `Access-Control-Allow-Origin`; send a request with an untrusted `Origin` and confirm no matching header is returned; confirm `Access-Control-Allow-Credentials: true` never appears with `*`
