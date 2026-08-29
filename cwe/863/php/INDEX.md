# CWE-863: Incorrect Authorization - PHP

## LLM Guidance

In Laravel and similar PHP frameworks, Incorrect Authorization commonly appears as a Policy or controller check that compares role with a loose `!=` (`if ($user->role != 'admin')`, which before PHP 8 could match a non-string role through type juggling), or a Policy method that checks the resource's class/type but never compares its owning user ID to the authenticated user. It also appears as a check present in one controller action but missing from a sibling action for the same model. Fix by writing Policy methods that combine an explicit role allowlist with an ownership comparison, and by calling `Gate::authorize()` on every action that touches the resource.

## Key Principles

- Use Laravel Policies (`php artisan make:policy OrderPolicy --model=Order`; without `--model` the generated class is empty) with explicit allowlist role checks. Pass `true` as `in_array`'s third argument (`in_array($user->role, ['admin', 'editor'], true)`) - the default is loose comparison, which before PHP 8.0 matched a string needle against an array value of `0`
- Compare the resource's owning user ID against `$user->id` inside the Policy method, and pass the loaded instance (`Gate::authorize('update', $order)`). A class name is the documented argument only for abilities that take just a user, such as `create`; handing one to a method that expects a model does not silently pass the check, so treat a class-level call on `update` or `delete` as a mistake to correct rather than as a bypass to exploit
- Call `Gate::authorize('update', $order)` in every controller method that reads or mutates the resource, including `update`, `destroy`, and any bulk-action methods. Prefer it to `$this->authorize()`, which the Laravel 11+ skeleton's base controller no longer provides
- Never resolve the acting role or ownership from request input (`$request->input('role')`, a hidden form field); always read from the authenticated `$user` model loaded server-side via `Auth::user()`
- Register Policies with `Gate::policy(Order::class, OrderPolicy::class)` in `AppServiceProvider::boot()`, or rely on auto-discovery, so authorization logic is centralized rather than duplicated inline across controllers
- Return `false` explicitly from a Policy method for any unmatched role rather than falling off the end. An implicit `null` is falsy and the Gate denies on it, so the risk is not a bypass but a silent denial that reads as a bug; the one place `null` carries its own meaning is a `before` method, where it means fall through to the policy method rather than deny
- Apply the check to every operation, including bulk ones: a `bulkUpdate()` that authorizes the *action* and not each row in the set is the path that survives a fix to `update()`. `authorizeResource()` maps only the seven RESTful controller methods and there is no framework helper for authorizing a collection, so the Policy must decide the whole batch. Two traps go with that: `Collection::every()` returns true over an empty collection, so an empty batch authorizes and then updates nothing, and `whereIn` silently drops ids that do not exist, so compare the loaded count against the requested count before deciding. Keep every denial on one path - splitting it between an `abort_if` in the controller and the Policy gives the two failure modes different responses
- Return the "not found" form for an unauthorized record (`Illuminate\Auth\Access\Response::denyAsNotFound()`, Laravel 9.20+) so the two denials answer alike - comparing the body as well as the status, since it attaches its own message

## Taint Sinks

`Gate::authorize()`, `Gate::allows()`, `Gate::policy()`, `$user->can()`, `middleware('can:...')`, `$request->input()`

## Remediation Steps

- Locate - Find Policy methods or inline controller checks using loose `!=`/`!==` role comparisons, and Policy calls that pass a class name where the ability expects a loaded instance
- Trace data flow - Identify every controller action for the resource (index, show, update, destroy, bulk operations) and confirm which ones call `authorize()` with the loaded instance
- Replace the unsafe pattern - Convert loose `!=` role comparisons to `in_array($user->role, $allowedRoles, true)`, and change class-level `can()` checks to instance-level checks
- Bind, encode, validate, or authorize - Add `$order->user_id === $user->id` (or equivalent) inside the Policy method alongside the role check
- Break taint after allowlist validation - Read the role from `$user->role` on the authenticated model, never from request input, before evaluating the Policy
- Harden configuration - Register the Policy for the model with `Gate::policy()` in `AppServiceProvider` (or via auto-discovery) so every authorization call resolves to the same logic
- Test - Add feature tests where a non-owner with a valid role, and a user with an unrecognized role, both attempt the action. Expect 403 for the unrecognised role, and the 404 that `denyAsNotFound()` produces for the non-owner - asserting the body too, since that 404 carries its own message
