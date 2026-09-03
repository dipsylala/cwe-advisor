# CWE-352: Cross-Site Request Forgery (CSRF) - JavaScript

## LLM Guidance

CSRF vulnerabilities occur when state-changing endpoints don't verify that requests originated from the legitimate application, allowing attackers to trick users into executing unwanted actions. The core fix is implementing token-based verification where each form/request includes a secret token that the server validates. Use `csrf-csrf` for Express (the maintained successor to the deprecated `csurf`) or `@fastify/csrf-protection` for Fastify.

## Key Principles

- Implement CSRF tokens for all state-changing operations (POST, PUT, DELETE, PATCH)
- Use SameSite cookie attribute (`SameSite=Lax` or `Strict`) as defence-in-depth
- Validate Origin/Referer headers for additional protection on critical endpoints
- Never rely solely on cookies for authentication without CSRF protection
- For REST APIs consumed by native apps, use token-based auth instead of cookies
- Generate with `crypto.randomBytes(32)` and compare with `crypto.timingSafeEqual()` on equal-length buffers, rather than `===`
- Send the token in a custom request header for XHR/fetch paths so a cross-site form post cannot carry it, and re-issue it whenever the session identifier is regenerated

## Taint Sinks

`app.post()`/`app.put()`/`app.delete()` routes not behind `doubleCsrfProtection` middleware; `fastify.post()`/`put()`/`delete()` routes without `fastify.csrfProtection` in their hooks

## Remediation Steps

- Install CSRF middleware - `npm install csrf-csrf cookie-parser`
- Obtain the utilities from `doubleCsrf({ getSecret, getSessionIdentifier, cookieName, cookieOptions })` and apply `doubleCsrfProtection` globally or to protected routes, mounted after `cookieParser()`. `getSessionIdentifier` is required as of v4 and is the mechanism that binds a token to one session - without it a token minted for one user would validate for another
- Generate a token per request with `generateCsrfToken(req, res)` - named `generateToken` before v4 - and inject it into forms or expose it via a GET endpoint for SPA clients
- Configure client to send token in `x-csrf-token` header (AJAX/fetch) or `_csrf` body field (forms)
- Set cookie SameSite attribute to `Strict` or `Lax` and verify implementation with security tests
- Handle CSRF errors gracefully - catch `invalidCsrfTokenError` and return 403
- For Fastify, the steps above are Express/`csrf-csrf`-specific. Register `@fastify/cookie` (or the session plugin, passed as `sessionPlugin`) and then `@fastify/csrf-protection` (8.x) - but registration alone enforces nothing. The check runs only where `fastify.csrfProtection` is attached as a hook: `fastify.addHook('onRequest', fastify.csrfProtection)` for every route, or `{ onRequest: fastify.csrfProtection }` in the options of each state-changing route. A route left without the hook is exactly as unprotected as before the plugin was added, so the write-up has to show the hook on the reported route, not just the `register` call. Use `preValidation`/`preHandler` in place of `onRequest` when the token travels in the request body, which is not parsed yet at `onRequest`. Mint the token with `reply.generateCsrf()` in a GET route the client calls first; the field/header names differ from `csrf-csrf`'s
