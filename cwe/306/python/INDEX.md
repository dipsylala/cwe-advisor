# CWE-306: Missing Authentication for Critical Function - Python

## LLM Guidance

Django, DRF, FastAPI and Flask each default to open rather than closed, so a view added without the project's usual decorator, permission class, or dependency is public and nothing reports it. The check is normally one line away from correct, which is why the defect survives review - read the framework's default rather than the view. Fix by making authentication the project-wide default and treating each public endpoint as an explicit, reviewable opt-out.

## Key Principles

- Django 5.1+ ships `LoginRequiredMiddleware`, which makes authentication the default for every view, with `@login_not_required` as the deliberate opt-out. On earlier versions the requirement is per-view `@login_required` or `LoginRequiredMixin`, and a view that omits it is silently public
- That middleware does not reach DRF: `APIView.as_view()` sets `login_required = False` on the view and the middleware honours the attribute, so enabling it changes nothing for a DRF project. There the permission default below is the fix, not an alternative to it
- `@login_not_required` is the supported opt-out rather than a defect in itself - Django's own login, password-reset and admin login views carry it, and stripping it from a project's login view produces an infinite redirect. Confirm the view is genuinely public instead of removing the decorator
- DRF's `DEFAULT_PERMISSION_CLASSES` defaults to `AllowAny`. Set it to `IsAuthenticated` in settings so a new `ViewSet` inherits the requirement, and override per view where a genuinely public endpoint is needed
- `DEFAULT_AUTHENTICATION_CLASSES` decides how identity is established at all, and the shipped default is `SessionAuthentication` plus `BasicAuthentication`. A token API that never adds the class reading its own credential leaves `request.user` as `AnonymousUser`, with only the permission class between the caller and the view
- FastAPI has no global default: a path operation with no security dependency is public. Pass `dependencies=[Depends(verify_token)]` to `APIRouter(...)`, to the `FastAPI(...)` application, or to `app.include_router(...)` so routes added later inherit it, rather than repeating `Depends` on each operation. The `include_router` form is the one that covers a router the project did not author
- In Flask, a `@blueprint.before_request` hook covers only that blueprint - a route registered on a different blueprint, or directly on `app`, gets nothing. `Blueprint.before_app_request` is the app-wide form registered from a blueprint, equivalent to `Flask.before_request`
- Entry points outside the request cycle carry no user at all: Celery tasks and management commands bypass every HTTP check, so an operation reachable both ways needs the requirement in the shared function. Admin actions are not in that group - they run inside `AdminSite.admin_view`, which requires `is_active` and `is_staff`, and `@admin.action(permissions=[...])` narrows them further
- Verify the token rather than decoding it - in PyJWT, `jwt.decode(token, options={"verify_signature": False})` returns claims without proving anything, and every claim check defaults to `verify_signature`, so disabling it switches off expiry and audience too. Any identity read from that call is attacker-supplied. The floor is 2.13.0, which closed a set including a public-key-as-HMAC-secret forgery of `HS256` tokens

## Taint Sinks

DRF views relying on the default `AllowAny`, FastAPI path operations with no security dependency, Django views without `@login_required`/`LoginRequiredMixin` before 5.1, `@login_not_required`, Flask routes outside a `before_request` blueprint, Celery task entry points, `jwt.decode` with `verify_signature` disabled

## Remediation Steps

- Locate - Enumerate Django views and URL patterns, DRF `ViewSet`/`APIView` classes, FastAPI path operations, Flask routes, and Celery task entry points
- Diff against coverage - Establish the project-wide default first (`LoginRequiredMiddleware`, `DEFAULT_PERMISSION_CLASSES`, router-level `dependencies`), then list which entry points fall outside it
- Confirm identity is never established - A view that authenticates but skips a permission or ownership check is CWE-862 rather than this entry
- Apply the fix - Close the default the framework actually uses: `LoginRequiredMiddleware` on Django 5.1+ for its own views, `DEFAULT_PERMISSION_CLASSES` set to `IsAuthenticated` for DRF regardless of that middleware, or `dependencies=[Depends(...)]` at the FastAPI router or `include_router` call
- Audit the exceptions - Review each `@login_not_required`, `permission_classes = [AllowAny]`, and route left outside the dependency, and confirm it is intentionally public. The login view is expected to carry one
- Cover the non-HTTP paths - Move the identity requirement into the shared function where a Celery task or management command reaches the same operation
- Test directly against the endpoint - Issue unauthenticated requests to each route, including the Django admin and any debug endpoint, and confirm a 401 or 302 to login rather than a 200
