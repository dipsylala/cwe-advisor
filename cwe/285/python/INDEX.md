# CWE-285: Improper Authorization - Python

## LLM Guidance

In Python web frameworks, improper authorization occurs when views or API endpoints are missing permission checks, or when checks only verify authentication rather than whether the authenticated user has the right to perform the specific action. Django provides `@permission_required`, `@login_required`, and DRF's `permission_classes`; Flask uses decorators or Flask-Login/Flask-Principal. Apply the most specific permission check possible at the view level.

## Key Principles

- Use `@permission_required` (Django) or DRF `permission_classes` rather than manual `if user.is_authenticated` checks
- Apply permissions at the view/viewset level, not scattered inside business logic
- Never read role or permission from the request data; derive it from `request.user` or the session
- Use DRF's `IsAdminUser`, `IsAuthenticated`, or custom `BasePermission` subclasses for consistent enforcement
- For object-level authorization, override `get_object()` or use `get_queryset()` filtered by the current user
- Set `DEFAULT_PERMISSION_CLASSES` in DRF so a view that declares nothing is denied by default, rather than relying on each view to opt in
- Object-level permissions do not run unless something calls them: `has_object_permission()` fires from `self.get_object()`, so a custom `@action(detail=True)` or a hand-written lookup with `Model.objects.get(pk=...)` bypasses it entirely - call `self.check_object_permissions(request, obj)` explicitly there
- Filter the queryset by the requesting user rather than returning `Model.objects.all()` and checking afterwards - a list endpoint has no object-level hook to fire
- Take the user from `request.user`, never from `request.POST` or a URL parameter

## Taint Sinks

views/`ViewSet`s missing `@permission_required`/`permission_classes`, unscoped `Model.objects.all()` querysets

## Remediation Steps

- Identify views missing authorization decorators or `permission_classes` - any CBV or FBV that performs privileged operations
- Add `@permission_required('app.change_report', raise_exception=True)` to function-based views - without `raise_exception` the decorator redirects to the login page instead of returning 403 or set `permission_classes = [IsAdminUser]` on DRF ViewSets
- For Django class-based views, use `PermissionRequiredMixin` with `permission_required` attribute
- Scope querysets to the authenticated user: `queryset = Order.objects.filter(user=request.user)` to prevent IDOR
- Return 403 (not a redirect to login) for authenticated users who lack permission
- Add test cases verifying that lower-privileged users receive 403 on each protected endpoint
