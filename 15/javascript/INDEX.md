# CWE-15: External Control of System or Configuration Setting - JavaScript

## LLM Guidance

In Node.js applications this occurs when request data (`req.body`, `req.query`, headers) is written into `process.env`, a `node-config`/`convict` object, a Winston/Pino logger's level, or CORS/middleware options at runtime. The fix is to load configuration once at startup from `.env` files and environment variables, then `Object.freeze()` the resulting object so no later code path (including request handlers) can mutate it. Where a setting must change at runtime (log level, feature flag), gate it behind authentication middleware and an explicit allowlist.

## Key Principles

- Load configuration once at startup with `dotenv` or a schema-validated library like `convict`, then export an `Object.freeze()`-wrapped object; never assign to `process.env[key]` or a config object using a request-derived key
- Use `zod` (or a similar schema library) with `z.enum([...])` for the allowed setting names so unknown keys are rejected before reaching `configService.set()`
- Never let `req.body`/`req.query` values flow directly into `logger.level`, CORS `origin`, or any security-relevant middleware option
- Any admin endpoint that changes a setting must run behind authentication/authorization middleware (e.g. a `requireAdmin` guard) and check the requested key and value against an allowlist `Set` or schema before applying it
- Never pass a request-controlled path to `fs.readFileSync()`/`require()` for config loading, and never fetch a request-controlled URL for remote configuration (SSRF risk)
- Log both accepted and rejected configuration changes with the acting user's identity

## Taint Sinks

`process.env[key]=`, `config.util.extendDeep()`, `logger.level=`, CORS `origin` option

## Remediation Steps

- Locate - find where `req.body`, `req.query`, or `req.headers` flows into `process.env[...]`, `config.util.extendDeep()`, `logger.level =`, CORS options, or `fs.readFileSync()`/`require()` with a path argument
- Trace data flow - follow the value from the Express route handler to the assignment or call that consumes it, including any intermediate object it is copied into
- Replace the unsafe pattern - move the setting into a `dotenv`-loaded, `Object.freeze()`-protected config module populated from environment variables at deployment, not from the request
- Bind, encode, validate, or authorize - if the value must stay runtime-configurable, require admin middleware and validate the request body against a `zod` schema whose `key` field is a `z.enum([...])` of permitted settings
- Break taint after allowlist validation - use `result.data` (the schema-parsed, allowlist-checked value) when calling `logger.level =` or `configService.set()`, never the raw `req.body` field
- Harden configuration - use `convict`'s `format` allowlist plus `config.validate({ allowed: 'strict' })` so invalid configuration throws at startup instead of degrading security silently
- Test - submit values outside the allowlist and confirm 400, confirm unauthenticated calls to admin config endpoints return 401/403, and confirm `config.someKey = 'value'` throws or is silently ignored on the frozen object

## Safe Pattern

```javascript
// SAFE: startup-loaded, frozen configuration - no request can reach it
require('dotenv').config();
const config = Object.freeze({
  logLevel: process.env.LOG_LEVEL || 'info',
});
module.exports = config;

// SAFE: runtime log-level change gated by auth + allowlist
const ALLOWED_LOG_LEVELS = new Set(['info', 'warn', 'error']);

app.post('/admin/log-level', requireAdmin, (req, res) => {
  const level = (req.body.level || '').toLowerCase();
  if (!ALLOWED_LOG_LEVELS.has(level)) {
    return res.status(400).json({ error: 'Invalid log level' });
  }
  // Allowlist-checked value is what reaches the sink, not the raw body field
  logger.level = level;
  res.json({ status: 'updated', level });
});
```
