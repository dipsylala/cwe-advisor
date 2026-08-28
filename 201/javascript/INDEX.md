# CWE-201: Insertion of Sensitive Information Into Sent Data - JavaScript

## LLM Guidance

CWE-201 occurs when JavaScript/Node.js applications expose sensitive data (passwords, tokens, API keys, stack traces, internal paths) in HTTP responses, error messages, logs, or client-side code. The core fix is to sanitize all outbound data by filtering sensitive fields, using allowlists for response properties, and implementing proper error handling that hides internal details from end users.

## Key Principles

- Sanitize error objects and responses by explicitly selecting only non-sensitive fields for transmission
- Use environment variables for secrets and never embed them in client-side JavaScript bundles
- Implement centralized error handling middleware that returns generic error messages to clients
- Apply response filtering to remove sensitive fields like passwords, tokens, and internal IDs before sending
- Log detailed errors server-side only; send sanitized messages to clients
- An environment variable prefixed `NEXT_PUBLIC_` (Next.js) or `REACT_APP_` (Create React App) is inlined into the client bundle at build time, so a secret named that way is published to every visitor - the prefix is the disclosure, not the deployment
- Return a mapped view rather than a database document: Mongoose's `.lean()` gives a plain object with every field the schema holds, and `class-transformer` only omits what is not `@Expose()`d when `excludeExtraneousValues` is set

## Taint Sinks

`res.json(err)`, `res.send(err.stack)`, `res.json(user)` on unfiltered model instances, logging full request/error objects to external services

## Remediation Steps

- Review all API response handlers and remove sensitive fields using allowlists or field exclusion
- Configure error handling middleware to catch exceptions and return generic error messages - Express only treats a handler as an error handler when it declares all four `(err, req, res, next)` parameters
- Audit client-side code (React/Vue components) to ensure no secrets are embedded in bundles
- Use `.env` files with tools like `dotenv` and never commit secrets to version control
- Implement response serializers/transformers that explicitly define allowed fields
- Add logging sanitization to strip sensitive data before writing to logs or external services
