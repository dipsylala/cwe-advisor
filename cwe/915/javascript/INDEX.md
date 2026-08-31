# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - JavaScript

## LLM Guidance

Mass assignment in Node.js occurs when request body objects are spread or merged directly into database models or plain objects without filtering, allowing attackers to set fields like `isAdmin`, `role`, or `balance` that were never intended to be user-controlled. This is common with Mongoose (`Model.create(req.body)`), Sequelize (`Model.create(req.body)`), and plain object spread (`Object.assign(user, req.body)`). The fix is to extract only the explicitly permitted fields from the request before any persistence operation.

## Key Principles

- Never pass `req.body` directly to `Model.create()`, `model.update()`, or `Object.assign()` targeting a persisted object
- Destructure or pick only the permitted fields by name from `req.body` before use
- Define a validation schema (Joi, Zod, express-validator) that strips unknown fields - Joi requires `.stripUnknown(true)` explicitly (it rejects unknown keys by default, but doesn't remove them without this); a plain `z.object({...})` in Zod already strips unrecognized keys with no option needed - Zod's `.strict()` does something different: it throws on an unknown key rather than removing it, so don't reach for `.strict()` expecting stripping behavior
- Treat fields like `role`, `isAdmin`, `permissions`, `accountBalance`, and `ownerId` as server-only attributes
- Apply the same restriction on update (PUT/PATCH) as on create - partial updates are equally vulnerable
- `User.create(req.body)` binds whatever the request contained: pick the fields explicitly, or pass the validated schema's output, since a field added to the model later becomes assignable without any code change - and pass the validated *output* through to the model, not the original `req.body` re-spread alongside it (`Model.create({ ...req.body, isAdmin: false })` still lets every other stripped field back in, since `...req.body` is unvalidated)
- Mongoose's `select: false` on a schema field only hides it from query results by default - it does nothing to stop the same field being set on `Model.create(req.body)`; it's a read-side control, not a write-side one

## Taint Sinks

`Model.create(req.body)`, `model.update(req.body)`, `Object.assign(target, req.body)`, `{ ...req.body }` spread into a persisted object

## Remediation Steps

- Identify calls to `Model.create(req.body)`, `instance.update(req.body)`, `Object.assign(target, req.body)`, or `{ ...req.body }` spread into persisted objects
- Replace with explicit field extraction: `const { name, email } = req.body` or a schema validation that strips unknown keys
- Use a validation library (Zod, Joi) to define the allowed input shape and call `.strip()` / `stripUnknown` before passing to the model - `z.object().parse()` already drops unknown keys, and pass the parsed result to the model rather than `req.body`
- Move server-controlled fields (role, ownerId) to be set from the session/token, not from the request body
- Review both create and update routes for the same pattern
- Test by submitting `isAdmin: true` or `role: "admin"` in the request body and confirming the field is ignored
- Where the attacker controls a request *key* rather than a value (a deep-merge helper, a config walker using a path string), the same shape of bug can pollute `Object.prototype` instead of a single model - see this repo's CWE-1321 guidance for that variant
