# CWE-862: Missing Authorization - JavaScript

## LLM Guidance

In Express and similar Node.js frameworks, Missing Authorization typically appears as a route that runs authentication middleware confirming a valid session or JWT but has no follow-up check on role or resource ownership, or as a new route registered directly on the router without the shared authorization middleware applied to sibling routes. Fix by adding an explicit per-route authorization middleware for role checks, and, for resource-specific actions, a check comparing the resource's owner field to `req.user.id` before performing the operation.

## Key Principles

- Treat session/JWT verification as authentication only; add a separate middleware or in-handler check for authorization (role, permission, or ownership)
- Apply authorization middleware at the router or route level (`router.post('/orders/:id/refund', requireAuth, requireRole('admin'), handler)`) so a route added without it is visibly missing the middleware in the route definition
- For resource-level checks, load the resource first and compare its owner field to `req.user.id` before mutating or returning it - a role check alone is not sufficient when the action targets a specific user's data
- Do not rely on hiding client-side UI elements or trusting a role/permission value sent from the client in the request body
- Centralize role and permission definitions in one middleware module so route files import consistent checks instead of writing inline conditionals per handler
- Return 403 for authenticated-but-unauthorized requests and 401 only when authentication itself is missing or invalid

## Taint Sinks

`router.get()`, `router.post()`, `router.put()`, `router.delete()` routes, GraphQL resolvers, `socket.on()` handlers lacking a role/ownership check

## Remediation Steps

- Locate - Identify Express routes, GraphQL resolvers, and Socket.IO event handlers that perform sensitive actions or return sensitive data
- Check for missing checks - Confirm the route only has authentication middleware with no role or ownership check before the handler executes
- Add role-based authorization - Insert a `requireRole('admin')` (or permission-based equivalent) middleware between authentication and the handler
- Add resource-based authorization - Inside the handler, load the target resource and verify `resource.ownerId === req.user.id` (or a granted-access relationship) before proceeding
- Apply consistently - Audit the router file to confirm every sensitive route uses the same middleware chain as comparable routes
- Harden configuration - Ensure authorization middleware runs after authentication middleware and before any route-specific logic that touches sensitive data
- Test - Write supertest/integration tests that call each route as an authenticated user lacking the required role or ownership and assert a 403 response

## Safe Pattern

```javascript
// SAFE: role-based middleware applied per route
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

router.post('/orders/:id/refund', requireAuth, requireRole('admin'), async (req, res) => {
  await orderService.refund(req.params.id);
  res.status(204).end();
});

// SAFE: resource-based ownership check inside the handler
router.get('/orders/:id', requireAuth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'not found' });
  }
  if (order.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json(order);
});
```
