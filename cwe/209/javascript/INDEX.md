# CWE-209: Generation of Error Message Containing Sensitive Information - JavaScript

## LLM Guidance

Error Message Information Leak occurs when JavaScript applications expose sensitive details like stack traces, database queries, file paths, or internal system information through API responses, error pages, or console output.

**Primary Defence:** sanitize error responses in production by logging detailed errors server-side while returning generic messages to clients. Node.js frameworks (Express, Fastify, Koa, Next.js) require proper error middleware configuration to prevent disclosure.

## Key Principles

- Log detailed errors server-side with monitoring tools; never expose stack traces or internals to clients
- Return generic error messages in production (e.g., "An error occurred") while preserving specific errors for development
- Configure framework error handlers to distinguish between development and production environments
- Sanitize database errors to remove query details, table names, and schema information
- Disable debug mode and verbose logging in production deployments
- `express-validator`'s `errors.array()` includes the submitted `value` for each failed field, so returning it echoes a rejected password back to the caller and into every access log on the way - build the response from field names and your own messages
- Winston and Pino serialize an `Error`'s `message` and `stack` when it is passed as the log object; decide which transport carries that, and return only a correlation id to the client

## Taint Sinks

`res.send(err.stack)`, `err.message`/`err.stack` in JSON response, default Express error handler in non-production mode

## Remediation Steps

- Fix the reported route first - replace its direct error response with a generic message, or forward to the centralized handler via `next(error)`. Centralized middleware only runs for errors that reach it, so a route answering from its own `catch` bypasses it however well it is configured
- Add environment-based error middleware that checks `NODE_ENV === 'production'` as the systemic control, then check no other route still responds from its own `catch"
- Configure logging to capture full errors server-side (Winston, Pino, Bunyan)
- Remove or disable client-side `console.error()` calls exposing sensitive data
- Set `NODE_ENV=production` in deployment environments
- Test error responses to verify no stack traces or internals leak
