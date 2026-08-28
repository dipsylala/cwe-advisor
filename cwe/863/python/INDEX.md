# CWE-863: Incorrect Authorization - Python

## LLM Guidance

In Django REST Framework, Incorrect Authorization commonly appears as a `permissions.BasePermission` that implements `has_permission` (checked before the view runs, role-only) but not `has_object_permission` (checked against the specific instance), so any authenticated user with the right role can act on any object regardless of ownership. It also appears as a denylist role comparison (`if request.user.role != 'admin'`) that fails open on new role values, or a check duplicated inconsistently across function-based views. Fix by implementing both permission methods and using an explicit role allowlist plus an ownership comparison in `has_object_permission`.

## Key Principles

- Implement both `has_permission` (coarse, role-level) and `has_object_permission` (per-instance, ownership) on `BasePermission` subclasses - DRF only calls `has_object_permission` for views that call `self.check_object_permissions(request, obj)` or use generic views' `get_object()`, so confirm the view path actually reaches it
- Use an explicit allowlist for role checks (`request.user.role in {'admin', 'editor'}`) instead of `!=` denylist comparisons
- Compare the object's owning user field to `request.user` inside `has_object_permission`, not just the object's type or existence
- Never resolve role or ownership from request data (`request.data.get('role')`); always read from `request.user`, populated by DRF's authentication classes from the verified session or token
- Apply the permission class via the view's `permission_classes` attribute so it runs for every method (GET/PUT/PATCH/DELETE) on that view, rather than adding inline checks per view function
- Return `False` explicitly for any unmatched role or failed ownership comparison; do not rely on falsy defaults from an incomplete conditional
- Scope `get_queryset()` on the `ModelViewSet` to the requesting user: an object-level permission does not fire on `list`, so the collection endpoint returns rows the detail endpoint would refuse

## Taint Sinks

`has_permission()` implemented without `has_object_permission()`, `request.user.role != 'admin'`, `request.data.get('role')`

## Remediation Steps

- Locate - Find `BasePermission` subclasses that implement `has_permission` only, and any inline `!=` role comparisons in views
- Trace data flow - Confirm which views call `check_object_permissions` (generic views do this automatically via `get_object()`; custom views may not) and which HTTP methods are covered
- Replace the unsafe pattern - Convert `!=` role comparisons to an explicit allowlist set/tuple membership check
- Bind, encode, validate, or authorize - Add `has_object_permission` that compares `obj.owner_id == request.user.id` alongside the role check
- Break taint after allowlist validation - Read role and identity from `request.user`, never from `request.data` or query parameters, before evaluating permissions
- Harden configuration - Set `permission_classes` on the `ViewSet`/`APIView` so the check applies uniformly across all actions, and confirm custom views call `check_object_permissions` explicitly if not using generic views
- Test - Add DRF `APITestCase` tests where a non-owner with a valid role, and a user with an unrecognized role, both attempt the action and receive HTTP 403
