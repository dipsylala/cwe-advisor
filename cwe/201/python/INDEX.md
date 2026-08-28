# CWE-201: Insertion of Sensitive Information Into Sent Data - Python

## LLM Guidance

Python web applications commonly expose sensitive data through HTTP responses, error messages, logs, or API responses. Frameworks like Django, Flask, and FastAPI make it easy to serialize entire objects or return detailed error traces, which can leak passwords, tokens, internal paths, PII, and configuration details. The core fix is to explicitly control what data is returned and sanitize error messages.

## Key Principles

- Explicitly whitelist response fields rather than serializing entire objects
- Disable debug mode and detailed error traces in production
- Sanitize exceptions before exposing them to clients
- Use structured logging that excludes sensitive fields
- Implement response DTOs or serializers with only necessary fields
- Use separate serializers for separate audiences rather than one with conditional fields - a public serializer that lists only what everyone may see cannot leak a field somebody later adds to the model
- `record.getMessage()` renders the log message with its arguments interpolated, so a filter that inspects `record.msg` alone misses values passed as `record.args`
- Let framework `HTTPException`s through the boundary handler so a 404 stays a 404, and build the body for everything else from a fixed contract

## Taint Sinks

`fields = '__all__'` in DRF serializers, `jsonify(user.__dict__)`, `return str(exception)`/`traceback.format_exc()` to clients, `DEBUG = True`

## Remediation Steps

- Set `DEBUG = False` in Django/Flask production settings
- Define explicit serializer fields instead of using `fields = '__all__'`, and declare FastAPI routes with `response_model=` bound to a Pydantic model that lists only the allowed fields
- Catch exceptions and return generic error messages to clients
- Configure logging filters to redact sensitive data (passwords, tokens, keys)
- Use environment variables for secrets, never hardcode in responses
- Review API responses to ensure only required data is included
