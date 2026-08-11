# CWE-862: Missing Authorization - PHP

## LLM Guidance

In Laravel, Missing Authorization typically appears as a controller method reachable through `auth` middleware, which confirms login only, that never calls `$this->authorize()`, `Gate::allows()`, or a Policy method before performing a sensitive action, or as a new route added to `routes/web.php`/`routes/api.php` without the authorization check present on comparable routes. Fix by defining a Policy or Gate for the resource and calling it explicitly at the start of the controller action, or via the `can` middleware on the route.

## Key Principles

- `auth` middleware confirms authentication only; add an explicit `$this->authorize()` call, `can` route middleware, or `Gate::allows()` check for authorization
- Define a Policy class (`php artisan make:policy OrderPolicy --model=Order`) per model so ownership and role rules live in one place and are reused across controllers
- Register policies in `AuthServiceProvider`, or rely on Laravel's naming-convention auto-discovery, so `$this->authorize()` resolves to the correct Policy method
- For resource-specific actions, the Policy method should compare the authenticated user to the model instance, such as `$user->id === $order->user_id`, not just check a role
- Use the `can` middleware (`->middleware('can:update,order')`) on routes so authorization is visible in the route definition and cannot be silently omitted from a handler
- Let unauthorized `authorize()` calls throw `AuthorizationException`, which Laravel converts to a 403 response by default - do not catch and suppress it

## Remediation Steps

- Locate - Identify controller methods, form request classes, and API actions that perform sensitive operations or return sensitive data
- Check for missing checks - Confirm the method relies only on `auth` middleware with no `$this->authorize()`, `can` middleware, or `Gate::allows()` call
- Define or extend a Policy - Add the relevant method (`update`, `delete`, `view`) to the model's Policy class, comparing the authenticated user against the resource
- Add the check - Call `$this->authorize('update', $order)` at the top of the controller action, or attach `->middleware('can:update,order')` to the route
- Cover role-only actions - For actions not tied to a specific model instance, use `Gate::define()` and `Gate::allows('manage-orders')` or `$this->authorize('manage-orders')`
- Reconcile route files - Audit `routes/web.php` and `routes/api.php` to confirm every sensitive route applies the same `can` middleware or authorize call as comparable routes
- Test - Write feature tests that call each route as an authenticated user without the required role or ownership and assert a 403 response

## Safe Pattern

```php
// SAFE: OrderPolicy defines the authorization rule
class OrderPolicy
{
    public function update(User $user, Order $order): bool
    {
        return $user->id === $order->user_id;
    }
}

// SAFE: controller calls authorize() before performing the action
class OrderController extends Controller
{
    public function update(Request $request, Order $order)
    {
        $this->authorize('update', $order);

        $order->update($request->validated());

        return response()->json($order);
    }
}

// SAFE: route-level authorization via the "can" middleware
Route::put('/orders/{order}', [OrderController::class, 'update'])
    ->middleware(['auth', 'can:update,order']);
```
