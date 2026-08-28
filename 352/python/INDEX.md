# CWE-352: Cross-Site Request Forgery (CSRF) - Python

## LLM Guidance

CSRF occurs when state-changing endpoints don't validate that requests originated from the application itself, allowing attackers to forge authenticated requests from malicious sites. Enable Django's `CsrfViewMiddleware` with `{% csrf_token %}` in forms, or use Flask-WTF's `CSRFProtect` for automatic token validation. Configure `SESSION_COOKIE_SAMESITE='Strict'` as defence-in-depth.

## Key Principles

- Enable framework-native CSRF protection globally (Django middleware, Flask-WTF `CSRFProtect`)
- Validate cryptographic tokens on all state-changing operations (POST/PUT/PATCH/DELETE)
- Use SameSite=Strict cookies to prevent cross-site cookie transmission
- Include tokens in forms via template tags and AJAX via custom headers
- Never disable CSRF protection with `@csrf_exempt` or similar decorators
- Flask-WTF's `wtforms.Form` subclasses only validate CSRF when `CSRFProtect` is initialised on the app - a form used without it validates fields and nothing else
- Exempting an endpoint (`@csrf_exempt`, an excluded path) is the shape most findings take; check the exclusion list as well as the handler

## Taint Sinks

`@csrf_exempt`, views missing `CsrfViewMiddleware`/Flask-WTF `CSRFProtect`

## Remediation Steps

- Add `django.middleware.csrf.CsrfViewMiddleware` to Django `MIDDLEWARE` settings
- Include `{% csrf_token %}` in all Django forms or initialize `CSRFProtect(app)` in Flask
- Configure secure cookies - `SESSION_COOKIE_SAMESITE='Strict'`, `CSRF_COOKIE_SAMESITE='Strict'`, `CSRF_COOKIE_SECURE=True` - Django tracks the session and CSRF cookies' SameSite settings independently, so setting one does not set the other
- For AJAX - read CSRF token from cookie and send in `X-CSRFToken` header
- Remove any `@csrf_exempt` decorators from state-changing endpoints
- Verify all POST/PUT/PATCH/DELETE routes validate tokens automatically
