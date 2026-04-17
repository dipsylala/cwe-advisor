# CWE-352: Cross-Site Request Forgery (CSRF) - JavaScript/Node.js

## LLM Guidance

CSRF vulnerabilities occur when state-changing endpoints don't verify that requests originated from the legitimate application, allowing attackers to trick users into executing unwanted actions. The core fix is implementing token-based verification where each form/request includes a secret token that the server validates. Use `csrf-csrf` for Express (the maintained successor to the deprecated `csurf`) or `@fastify/csrf-protection` for Fastify.

## Key Principles

- Implement CSRF tokens for all state-changing operations (POST, PUT, DELETE, PATCH)
- Use SameSite cookie attribute (`SameSite=Lax` or `Strict`) as defence-in-depth
- Validate Origin/Referer headers for additional protection on critical endpoints
- Never rely solely on cookies for authentication without CSRF protection
- For REST APIs consumed by native apps, use token-based auth instead of cookies

## Remediation Steps

- Install CSRF middleware - `npm install csrf-csrf cookie-parser`
- Apply `doubleCsrfProtection` middleware globally or to protected routes
- Generate a token per request with `generateToken(req, res)` and inject it into forms or expose via a GET endpoint for SPA clients
- Configure client to send token in `x-csrf-token` header (AJAX/fetch) or `_csrf` body field (forms)
- Set cookie SameSite attribute to `Strict` or `Lax` and verify implementation with security tests
- Handle CSRF errors gracefully — catch `invalidCsrfTokenError` and return 403

## Safe Pattern

```javascript
const { doubleCsrfProtection, generateToken } = require('csrf-csrf').doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: '__Host-psifi.x-csrf-token',
  cookieOptions: { sameSite: 'strict', secure: true, httpOnly: true },
});
const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();

app.use(cookieParser());
app.use(doubleCsrfProtection);

// Expose token for SPA / inject into server-rendered forms
app.get('/csrf-token', (req, res) => {
  res.json({ token: generateToken(req, res) });
});

app.post('/transfer', (req, res) => {
  // Token validated automatically by middleware; 403 thrown if invalid
  processTransfer(req.body);
  res.sendStatus(200);
});
```
