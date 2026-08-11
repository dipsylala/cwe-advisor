# CWE-863: Incorrect Authorization - JavaScript

## LLM Guidance

In Express and similar Node.js frameworks, Incorrect Authorization commonly appears as middleware that trusts a role or user ID sent by the client (`req.body.role`, a decoded-but-unverified JWT claim, or a hidden form field) instead of resolving it server-side, or as a denylist check (`if (user.role !== 'admin')`) that fails open when a new role is introduced. Another frequent variant is a check applied only to one route (`GET /orders/:id`) but forgotten on a sibling route (`PATCH /orders/:id`). Fix by re-validating role and ownership from a trusted server-side source on every route, using an allowlist for role comparisons.

## Key Principles

- Never trust `req.body`, `req.query`, or unverified token claims for the acting user's role or ID - resolve identity from the verified session or a signature-checked JWT (`jsonwebtoken.verify`, not `jwt.decode`)
- Use an allowlist of permitted roles (`const allowedRoles = ['admin', 'editor']; if (!allowedRoles.includes(role))`) rather than a denylist comparison like `role !== 'admin'`
- Add ownership checks alongside role checks: load the resource and compare its `ownerId` to the authenticated user's ID from `req.user`, not from the resource ID's absence of a role check alone
- Apply the same authorization middleware to every route for a resource, including PUT/PATCH/DELETE and any bulk-action endpoints, rather than repeating inline checks that can drift
- Re-validate authorization on the server for every request; a check performed only in client-side JavaScript or hidden UI elements is not a control
- Default to `403 Forbidden` when the role is unrecognized, the ownership check fails, or an error occurs while resolving either

## Taint Sinks

`req.body.role`, `req.query.role`, `jwt.decode()` (unverified), `role !== 'admin'` denylist checks, routes missing shared authorization middleware

## Remediation Steps

- Locate - Find middleware or route handlers reading role/user data from `req.body`, `req.query`, or a decoded-without-verification token, and any denylist-style role comparisons
- Trace data flow - Identify which routes for the same resource include the check and which sibling routes (other HTTP methods, bulk endpoints) omit it
- Replace the unsafe pattern - Convert `role !== 'admin'` checks to an allowlist array lookup, and move role resolution to server-verified session/token data
- Bind, encode, validate, or authorize - Add an ownership check that loads the resource from the database and compares its owner field to `req.user.id`
- Break taint after allowlist validation - Store the verified role/user ID from the session or verified token in `req.user`, and use only that object in authorization decisions, never the raw request body
- Harden configuration - Extract the check into shared middleware applied to every route for the resource so new routes cannot be added without it
- Test - Add supertest/integration tests for a non-owner with a valid session, an unrecognized role value, and each HTTP method on the route, confirming all are rejected with 403

## Safe Pattern

```javascript
// SAFE: role allowlist + ownership check resolved from verified session data
const allowedRoles = ['admin', 'editor'];

async function authorizeOrderAccess(req, res, next) {
  // req.user is populated by session/JWT verification middleware upstream,
  // never read from req.body or req.query.
  const { id: userId, role } = req.user;

  if (!allowedRoles.includes(role)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  if (role === 'admin') {
    return next();
  }

  const order = await Order.findById(req.params.id);
  if (!order || order.ownerId !== userId) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  req.order = order;
  next();
}

app.delete('/orders/:id', requireAuth, authorizeOrderAccess, async (req, res) => {
  await req.order.deleteOne();
  res.status(204).end();
});
```
