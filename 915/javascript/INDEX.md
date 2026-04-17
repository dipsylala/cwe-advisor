# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - JavaScript/Node.js

## LLM Guidance

Mass assignment in Node.js occurs when request body objects are spread or merged directly into database models or plain objects without filtering, allowing attackers to set fields like `isAdmin`, `role`, or `balance` that were never intended to be user-controlled. This is common with Mongoose (`Model.create(req.body)`), Sequelize (`Model.create(req.body)`), and plain object spread (`Object.assign(user, req.body)`). The fix is to extract only the explicitly permitted fields from the request before any persistence operation.

## Key Principles

- Never pass `req.body` directly to `Model.create()`, `model.update()`, or `Object.assign()` targeting a persisted object
- Destructure or pick only the permitted fields by name from `req.body` before use
- Define a validation schema (Joi, Zod, express-validator) that strips unknown fields — use `.stripUnknown(true)` or `.strict()`
- Treat fields like `role`, `isAdmin`, `permissions`, `accountBalance`, and `ownerId` as server-only attributes
- Apply the same restriction on update (PUT/PATCH) as on create — partial updates are equally vulnerable

## Remediation Steps

- Identify calls to `Model.create(req.body)`, `instance.update(req.body)`, `Object.assign(target, req.body)`, or `{ ...req.body }` spread into persisted objects
- Replace with explicit field extraction: `const { name, email } = req.body` or a schema validation that strips unknown keys
- Use a validation library (Zod, Joi) to define the allowed input shape and call `.strip()` / `stripUnknown` before passing to the model
- Move server-controlled fields (role, ownerId) to be set from the session/token, not from the request body
- Review both create and update routes for the same pattern
- Test by submitting `isAdmin: true` or `role: "admin"` in the request body and confirming the field is ignored

## Safe Pattern

```javascript
// Zod — parse strips unknown fields by default
const { z } = require('zod');

const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  // 'role', 'isAdmin', 'balance' intentionally omitted
});

router.post('/users', authenticate, async (req, res) => {
  const data = createUserSchema.parse(req.body); // throws on invalid; strips extras
  const user = await User.create({
    ...data,
    role: 'user',           // set server-side, not from request
    ownerId: req.user.id,
  });
  res.status(201).json(user);
});

// Explicit destructuring (no schema library)
router.put('/profile', authenticate, async (req, res) => {
  const { name, bio, avatarUrl } = req.body;  // only permitted fields
  await User.findByIdAndUpdate(req.user.id, { name, bio, avatarUrl });
  res.sendStatus(204);
});
```
