# CWE-285: Improper Authorization - Python

## LLM Guidance

In Python web frameworks, improper authorization occurs when views or API endpoints are missing permission checks, or when checks only verify authentication rather than whether the authenticated user has the right to perform the specific action. Django provides `@permission_required`, `@login_required`, and DRF's `permission_classes`; Flask uses decorators or Flask-Login/Flask-Principal. Apply the most specific permission check possible at the view level.

## Key Principles

- Use `@permission_required` (Django) or DRF `permission_classes` rather than manual `if user.is_authenticated` checks
- Apply permissions at the view/viewset level, not scattered inside business logic
- Never read role or permission from the request data; derive it from `request.user` or the session
- Use DRF's `IsAdminUser`, `IsAuthenticated`, or custom `BasePermission` subclasses for consistent enforcement
- For object-level authorization, override `get_object()` or use `get_queryset()` filtered by the current user

## Remediation Steps

- Identify views missing authorization decorators or `permission_classes` — any CBV or FBV that performs privileged operations
- Add `@permission_required('app.change_report')` to function-based views or set `permission_classes = [IsAdminUser]` on DRF ViewSets
- For Django class-based views, use `PermissionRequiredMixin` with `permission_required` attribute
- Scope querysets to the authenticated user: `queryset = Order.objects.filter(user=request.user)` to prevent IDOR
- Return 403 (not a redirect to login) for authenticated users who lack permission
- Add test cases verifying that lower-privileged users receive 403 on each protected endpoint

## Safe Pattern

```python
# Django function-based view
from django.contrib.auth.decorators import permission_required

@permission_required('reports.view_report', raise_exception=True)
def view_reports(request):
    reports = Report.objects.all()
    return render(request, 'reports.html', {'reports': reports})


# Django REST Framework ViewSet
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework import viewsets

class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Object-level: only return the current user's orders
        return Order.objects.filter(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        self.permission_classes = [IsAdminUser]
        self.check_permissions(request)
        return super().destroy(request, *args, **kwargs)
```
