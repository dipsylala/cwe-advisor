# CWE-285: Improper Authorization - JavaScript/Node.js

## LLM Guidance

In Express applications, improper authorization occurs when route handlers perform operations without verifying the authenticated user has permission to do so. Authorization must be enforced in middleware applied before the handler, not inside the handler after data has already been fetched. Use authorization middleware (role-check functions, `express-jwt-permissions`, or framework-level guards) attached to individual routes or route groups.

## Key Principles

- Attach authorization middleware to routes rather than checking permissions inline inside handlers
- Check both authentication (identity) and authorization (permission) separately — a valid JWT is not sufficient
- Never derive role or permission from the request body or query string; read it from the verified token or session
- Apply a default-deny approach: unauthenticated or insufficiently privileged requests must be rejected before any business logic runs
- Cover all HTTP verbs — GET endpoints that expose sensitive data need the same authorization checks as POST/DELETE

## Remediation Steps

- Identify unprotected routes — look for `router.get/post/put/delete` handlers that perform privileged operations without authorization middleware
- Create role-check middleware functions that verify `req.user.role` or `req.user.permissions` from the decoded token/session
- Apply the middleware directly on the route or router group: `router.delete('/users/:id', requireRole('admin'), deleteUser)`
- For object-level authorization (IDOR), verify the resource owner matches `req.user.id` inside the handler after retrieval
- Test with tokens representing different roles and confirm lower-privileged requests return 403
- Apply `express-rate-limit` to sensitive routes to slow enumeration of authorization gaps

## Safe Pattern

```javascript
// Authorization middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.sendStatus(401);
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
  };
}

// Route definitions — authorization applied per route
router.get('/reports', requireRole('manager', 'admin'), getReports);
router.delete('/users/:id', requireRole('admin'), deleteUser);

// Object-level authorization inside handler
router.get('/orders/:id', authenticate, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.sendStatus(404);
  if (order.userId !== req.user.id && req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  res.json(order);
});
```
