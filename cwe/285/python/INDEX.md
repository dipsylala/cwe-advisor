# CWE-285: Improper Authorization - Python

## LLM Guidance

In Django and Django REST Framework, improper authorization occurs when a view is missing a permission check, or checks only authentication rather than whether the authenticated user may perform this action on this object. Django's model permissions are function-level; object-level authorization is either a queryset scoped to the user or an explicit object-permission check, and neither happens by default. Apply the most specific check the framework offers at the view level.

## Key Principles

- Use `@permission_required('app.change_report', raise_exception=True)` on function-based views; without `raise_exception` the decorator redirects to the login page rather than raising `PermissionDenied`, which reads to an already-authenticated user as a broken login. `PermissionRequiredMixin` inherits the same default through `AccessMixin.raise_exception`
- Django's permission framework "has a foundation for object permissions, though there is no implementation for it in the core", so `has_perm(perm, obj)` returns `False` until a backend such as `django-guardian` is installed. A model permission grants the verb, never the row
- On DRF, set `DEFAULT_PERMISSION_CLASSES` inside the `REST_FRAMEWORK` dict as a list of dotted paths - the shipped default is `AllowAny`, so a view that declares nothing is open. A view declaring its own `permission_classes` replaces that default rather than adding to it, and DRF composes classes with `&`, `|` and `~`
- The shipped permission classes are object-level no-ops: except `DjangoObjectPermissions`, none implements `has_object_permission`, whose base returns `True`. Calling `check_object_permissions` under `IsAuthenticated` or `IsAdminUser` checks nothing - subclass `BasePermission` and implement the method
- Object-level permissions run only from `self.get_object()`, so an `@action(detail=True)` that fetches the record itself, a hand-written `Model.objects.get(pk=...)`, or an overridden `get_object()` all bypass them unless they call `self.check_object_permissions(request, obj)` explicitly. Creation never calls `get_object()` at all - enforce that in the serializer or `perform_create()`
- Scope the data in `get_queryset()` as a method override reading `self.request.user`; a `queryset` class attribute is evaluated once at class definition and has no request in scope. That also covers the list endpoint, which DRF documents as not applying object permissions per instance
- Django 5.1's `LoginRequiredMiddleware`, listed after `AuthenticationMiddleware`, denies unauthenticated requests project-wide, with `@login_not_required` on the login view to avoid a redirect loop. DRF views are opted out of it entirely and are governed by the DRF settings instead
- Take the user from `request.user`, never from `request.POST` or a URL parameter
- Flask-Login's own documentation excludes this job - it will not "handle permissions beyond 'logged in or not'". Flask-Principal covers it but last released in 2013 and is now community-maintained under `pallets-eco`, which is worth weighing before adding it
- The framework's own APIs match correct code as readily as vulnerable code, because the defect is their absence. Grep them to list what is protected and compare that against the views that exist; the names worth auditing on sight are `AllowAny`, `@login_not_required` and `Model.objects.all()`

## Taint Sinks

`Model.objects.all()`, `Model.objects.get()`, `get_object()`, `check_object_permissions()`, `get_queryset()`, `@action(detail=True)`, `AllowAny`, `@login_not_required`, `request.data`

## Remediation Steps

- Identify views missing authorization declarations - any CBV or FBV that performs a privileged operation
- Add `@permission_required(..., raise_exception=True)` to a function-based view, or `permission_classes` naming a `BasePermission` subclass on a DRF view. The two do not interchange; `@api_view` plus `@permission_classes` is the decorator form for a DRF function view
- Implement `has_object_permission` on that permission class for object-level findings, and call `self.check_object_permissions(request, obj)` anywhere the object is fetched outside `get_object()`
- Scope querysets to the authenticated user by overriding `get_queryset()` to return `Order.objects.filter(user=self.request.user)`, which prevents IDOR on retrieve and list alike
- Return 403 (not a redirect to login) for authenticated users who lack permission
- Add test cases verifying that lower-privileged users are denied on each protected endpoint - 403 where a permission is the gate, and the 404 a user-scoped queryset already produces where the finding is object-level. Note that DRF answers 403 rather than 401 for an unauthenticated request when the first authentication class supplies no `WWW-Authenticate` header, as `SessionAuthentication` does not
