# CWE-566: Authorization Bypass Through User-Controlled Key - JavaScript/Node.js

## LLM Guidance

IDOR vulnerabilities in Node.js REST APIs occur when route parameters or request body IDs are used in database queries without verifying the authenticated user owns or is permitted to access that resource. This is common in Express/Mongoose and Express/Sequelize patterns where `Model.findById(req.params.id)` is called without a user-scoped filter. The fix is to either query with a composite filter (resource ID + user ID) or verify ownership after retrieval.

## Key Principles

- Never pass `req.params.id` or `req.body.id` directly to `findById()` without an ownership check
- Prefer composite queries: `Model.findOne({ _id: req.params.id, userId: req.user.id })` to enforce authorization at the database layer
- Read the authenticated user identity from the verified token or session (`req.user.id`), never from the request body
- Return 404 for both non-existent and unauthorized resources to avoid confirming resource existence to attackers
- Apply consistent ownership checks across all HTTP verbs — GET, PUT, PATCH, and DELETE on the same resource all need protection

## Remediation Steps

- Locate route parameters used as resource identifiers (`req.params.id`, `req.params.orderId`, etc.)
- Trace them to database queries — find calls to `findById()`, `findByPk()`, or similar without a user filter
- Replace with a composite query or add an ownership check after retrieval
- Ensure `req.user` is set by authentication middleware that runs before the handler
- Return `res.sendStatus(404)` (not 403) when the resource doesn't exist or is not owned by the user
- Test by authenticating as one user and requesting another user's resource IDs

## Safe Pattern

```javascript
// Mongoose — composite query (preferred)
router.get('/orders/:id', authenticate, async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id,  // Enforces ownership at DB level
  });
  if (!order) return res.sendStatus(404);
  res.json(order);
});

// Sequelize — composite query
router.delete('/documents/:id', authenticate, async (req, res) => {
  const deleted = await Document.destroy({
    where: { id: req.params.id, ownerId: req.user.id },
  });
  if (!deleted) return res.sendStatus(404);
  res.sendStatus(204);
});

// Ownership check after retrieval (fallback pattern)
router.put('/invoices/:id', authenticate, async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  if (!invoice || invoice.userId.toString() !== req.user.id) {
    return res.sendStatus(404);
  }
  await invoice.set(req.body).save();
  res.json(invoice);
});
```
