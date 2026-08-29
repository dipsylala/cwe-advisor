# CWE-862: Missing Authorization - PHP

## LLM Guidance

In Laravel, Missing Authorization typically appears as a controller method reachable through `auth` middleware, which confirms login only, that never calls `Gate::authorize()`, a Policy method, or the `can` middleware before performing a sensitive action, or as a new route added to `routes/web.php`/`routes/api.php` without the authorization check present on comparable routes. Fix by defining a Policy or Gate for the resource and calling it explicitly at the start of the controller action, or via the `can` middleware on the route.

## Key Principles

- `auth` middleware confirms authentication only; add an explicit `Gate::authorize()` call, `can` route middleware, or a Policy check for authorization
- Use `Gate::authorize()` rather than `$this->authorize()`. From Laravel 11 the skeleton's base controller no longer applies `AuthorizesRequests`, so `$this->authorize()` is undefined on a default controller unless the trait is added back explicitly. `Gate::allows()` is not a substitute for either: it returns a boolean and aborts nothing, so its result has to be acted on (`if (! Gate::allows(...)) { abort(403); }`)
- Define a Policy class (`php artisan make:policy OrderPolicy --model=Order`) per model so ownership and role rules live in one place and are reused across controllers
- Register policies with `Gate::policy(Order::class, OrderPolicy::class)` in `AppServiceProvider::boot()`, or rely on auto-discovery, so the authorization call resolves to the correct Policy method. Laravel 11 removed `AuthServiceProvider` from the skeleton; an application still on the Laravel 10 structure keeps it and continues to work
- For resource-specific actions, the Policy method should compare the authenticated user to the model instance, such as `$user->id === $order->user_id`, not just check a role
- Use the `can` middleware (`->middleware('can:update,order')`) on routes so authorization is visible in the route definition and cannot be silently omitted from a handler
- Let unauthorized `authorize()` calls throw `AuthorizationException`, which Laravel converts to a 403 response by default - do not catch and suppress it
- Use the framework's authorization layer rather than an inline check - Symfony's `denyAccessUnlessGranted()`/`#[IsGranted(...)]` and Laravel's policies keep the rule in one place and apply it to every route that declares it
- Prefer the "deny as not found" form so "not yours" and "does not exist" answer alike and the id space cannot be walked. In Laravel that is `Illuminate\Auth\Access\Response::denyAsNotFound()` returned from a Policy method (9.20+), or `findOrFail` after a query already scoped to the user. Route model binding already answers 404 for an id with no row, so a policy returning plain `false` answers 403 for one that exists - that pairing is the oracle. Matching the status is not the end of it: the two 404s are thrown as different exception classes and render different default bodies, so assert the body too; in Symfony it is `#[IsGranted(..., statusCode: 404)]` (6.2+) or throwing `$this->createNotFoundException()` from a controller extending `AbstractController`

## Taint Sinks

`Route::get()`, `Route::post()`, `Route::put()`, `Route::delete()`, `Gate::authorize()`, `Gate::allows()`, `Gate::policy()`, `middleware('can:...')`, `denyAccessUnlessGranted()`

## Remediation Steps

- Locate - Identify controller methods, form request classes, and API actions that perform sensitive operations or return sensitive data
- Check for missing checks - Confirm the method relies only on `auth` middleware with no `Gate::authorize()`, `can` middleware, or acted-on `Gate::allows()` result
- Define or extend a Policy - Add the relevant method (`update`, `delete`, `view`) to the model's Policy class, comparing the authenticated user against the resource
- Add the check - Call `Gate::authorize('update', $order)` at the top of the controller action, or attach `->middleware('can:update,order')` to the route, which requires `order` to be resolved by route model binding
- Cover role-only actions - For actions not tied to a specific model instance, use `Gate::define()` and `Gate::authorize('manage-orders')`
- Reconcile route files - Audit `routes/web.php` and, where present, `routes/api.php` (opt-in via `php artisan install:api` from Laravel 11) to confirm every sensitive route applies the same `can` middleware or authorize call as comparable routes
- Test - Write feature tests that call each route as an authenticated user without the required role and assert 403, and as a user who owns a different record and assert the 404 that the deny-as-not-found form produces
