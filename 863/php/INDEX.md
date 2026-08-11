# CWE-863: Incorrect Authorization - PHP

## LLM Guidance

In Laravel and similar PHP frameworks, Incorrect Authorization commonly appears as a Policy or controller check that compares role with `!=` (`if ($user->role != 'admin')`, failing open on new role values), or a Policy method that checks the resource's class/type but never compares its owning user ID to the authenticated user. It also appears as a check present in one controller action but missing from a sibling action for the same model. Fix by writing Policy methods that combine an explicit role allowlist with an ownership comparison, and by calling `$this->authorize()` (or `Gate::authorize()`) on every action that touches the resource.

## Key Principles

- Use Laravel Policies (`php artisan make:policy`) with explicit allowlist role checks (`in_array($user->role, ['admin', 'editor'], true)`) instead of `!=` denylist comparisons
- Compare the resource's owning user ID against `$user->id` inside the Policy method - a Policy that only checks the model class (`$user->can('update', Order::class)`) without also loading the instance (`$user->can('update', $order)`) skips ownership entirely
- Call `$this->authorize('update', $order)` or `Gate::authorize('update', $order)` in every controller method that reads or mutates the resource, including `update`, `destroy`, and any bulk-action methods
- Never resolve the acting role or ownership from request input (`$request->input('role')`, a hidden form field); always read from the authenticated `$user` model loaded server-side via `Auth::user()`
- Register Policies via `Gate::policy()` (or auto-discovery) so authorization logic is centralized, not duplicated inline across controllers
- Ensure Policy methods return `false` (denied) for any unmatched or unexpected role rather than omitting a `return`, which in PHP defaults to `null` and can be misinterpreted by custom authorization middleware

## Taint Sinks

`!=`/`!==` role comparisons, `$user->can('update', Order::class)` class-level checks, `$request->input('role')`

## Remediation Steps

- Locate - Find Policy methods or inline controller checks using `!=`/`!==` role comparisons, and Policy calls that check only the model class rather than a loaded instance
- Trace data flow - Identify every controller action for the resource (index, show, update, destroy, bulk operations) and confirm which ones call `authorize()` with the loaded instance
- Replace the unsafe pattern - Convert `!=` role comparisons to `in_array($user->role, $allowedRoles, true)`, and change class-level `can()` checks to instance-level checks
- Bind, encode, validate, or authorize - Add `$order->user_id === $user->id` (or equivalent) inside the Policy method alongside the role check
- Break taint after allowlist validation - Read the role from `$user->role` on the authenticated model, never from request input, before evaluating the Policy
- Harden configuration - Register the Policy for the model in `AuthServiceProvider` (or via auto-discovery) so every `authorize()`/`can()` call resolves to the same logic
- Test - Add feature tests where a non-owner with a valid role, and a user with an unrecognized role, both attempt the action and receive a 403

## Safe Pattern

```php
// SAFE: Policy combines an explicit role allowlist with an ownership check
class OrderPolicy
{
    private const ALLOWED_ROLES = ['admin', 'editor'];

    public function update(User $user, Order $order): bool
    {
        if (!in_array($user->role, self::ALLOWED_ROLES, true)) {
            return false;
        }

        if ($user->role === 'admin') {
            return true;
        }

        // Ownership is checked against the loaded model, not the request.
        return $order->user_id === $user->id;
    }
}

// Controller
class OrderController extends Controller
{
    public function update(Request $request, Order $order)
    {
        $this->authorize('update', $order);

        $order->update($request->validate(['status' => 'required|string']));

        return response()->json($order);
    }
}
```
