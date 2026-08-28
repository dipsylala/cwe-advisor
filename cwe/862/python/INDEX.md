# CWE-862: Missing Authorization - Python

## LLM Guidance

In Django and Django REST Framework, Missing Authorization typically appears as a view that requires `login_required`/`IsAuthenticated` but never checks permissions or object ownership, or as a new `ViewSet`/view added without the `permission_classes` used by comparable endpoints. Fix by adding `@permission_required` with `raise_exception=True` for Django views, or DRF permission classes such as `IsAdminUser` or a custom `BasePermission` with object-level `has_object_permission`, so the check runs before the sensitive action executes.

## Key Principles

- `login_required`/`IsAuthenticated` confirms authentication only; add `@permission_required`, a custom Django permission, or a DRF permission class for authorization
- In DRF, set `permission_classes` explicitly on every `ViewSet`/`APIView` rather than relying on a global `DEFAULT_PERMISSION_CLASSES` that may be broader than the endpoint needs
- Implement `has_object_permission()` on custom DRF permission classes for object-level checks such as ownership; `has_permission()` alone only gates the general endpoint, not access to a specific object
- Do not rely on filtering only the objects visible to the user in a list view while leaving the detail/update/delete view unfiltered - each action needs its own check
- Use `@permission_required('app.change_order', raise_exception=True)`, not the default redirect-to-login behavior, so an authenticated but unauthorized user gets a 403, not a login prompt
- Centralize permission classes and Django permission checks in reusable modules so new views import consistent rules rather than reimplementing checks inline
- `has_object_permission()` runs only when something calls `self.get_object()`, so a custom `retrieve()`, an `@action`, or a hand-written `get_object_or_404(Order, pk=pk)` bypasses it. Prefer routing those paths through `self.get_object()`, which applies `get_queryset()` scoping and the object permission together; `self.check_object_permissions(request, obj)` re-adds only the permission half and answers 403, recreating the existence oracle that a scoped queryset avoids
- Watch the staff branch: where `get_queryset()` widens for staff but `has_object_permission()` compares owner IDs alone, the two disagree and the wider queryset is the one that decided which rows exist
- Flask has no equivalent framework layer - `flask_login.login_required` is authentication only. Put the check in a decorator applied to every sensitive view, and scope the query by `current_user.id` rather than fetching by id and comparing
- Scope `get_queryset()` to the requesting user so a list endpoint, which has no object-level hook, cannot return other people's rows

## Taint Sinks

Django view functions, DRF `ViewSet` methods, `@api_view` functions lacking `permission_classes`/`has_object_permission()`

## Remediation Steps

- Locate - Identify Django views, DRF `ViewSet`/`APIView` methods, and Celery task entry points that perform sensitive actions or return sensitive data
- Check for missing checks - Confirm the view has only `login_required`/`IsAuthenticated` with no permission class, decorator, or object-level check
- Add permission-based authorization - Apply `@permission_required('app.change_order', raise_exception=True)` in Django, or set `permission_classes` in DRF
- Add object-level authorization - Implement a custom `BasePermission` with `has_object_permission(self, request, view, obj)` comparing `obj.owner_id` to `request.user.id`; DRF's generic views call this automatically via `get_object()`
- Reconcile with existing endpoints - Audit `urls.py` and viewset registrations to confirm the new view uses the same permission classes as comparable views
- Harden configuration - Review `DEFAULT_PERMISSION_CLASSES` in DRF settings and ensure it is not set to `AllowAny` for authenticated-only projects
- Test - Write tests using Django's test client or DRF's `APIClient` that call each endpoint as an authenticated user lacking the required permission and assert 403, and as a user who owns a different object and assert the 404 a queryset-scoped lookup returns
