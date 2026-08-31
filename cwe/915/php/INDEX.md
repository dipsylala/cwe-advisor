# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - PHP

## LLM Guidance

Mass assignment in Laravel Eloquent occurs when `Model::create($request->all())` or `$model->update($request->all())` is called, allowing request parameters to overwrite any model attribute including protected ones like `is_admin`, `role`, or `email_verified_at`. Laravel's guard against this is the `$fillable` (allowlist) or `$guarded` (denylist) property on the model - a model defining neither is fully guarded by default (Eloquent's base `$guarded` is `['*']`), so the actual exposure comes from a model that explicitly sets `$guarded = []` or lists a sensitive field in `$fillable`, not from omitting both properties. Always define `$fillable` with an explicit allowlist.

## Key Principles

- Define `$fillable` on every Eloquent model to explicitly allowlist mass-assignable attributes
- Never set `$guarded = []`; `protected $guarded = ['*']` guards all fields, but explicit `$fillable` is clearer for intended mass assignment
- Never pass `$request->all()` or `$request->input()` directly to `create()` or `update()` without filtering
- Use `$request->only(['field1', 'field2'])` to select permitted fields from the request - `$request->except('is_admin')` is a denylist, not an allowlist, and `array_merge($validated, $request->except('is_admin'))` reopens every other field the validator was supposed to constrain
- `forceFill()` deliberately bypasses `$fillable`/`$guarded` entirely - treat it as an explicit-disable, the same way as `unguard()`, and confirm any request-derived data never reaches it
- Set security-critical attributes (role, is_admin, verified_at) only through dedicated code paths, not from request input
- `Model::unguard()` disables mass-assignment protection process-wide, so a seeder or test helper that calls it and does not call `Model::reguard()` afterward leaves every model open
- Call `Model::preventSilentlyDiscardingAttributes()` (typically in a service provider's `boot()`) so an attribute outside `$fillable` throws a `MassAssignmentException` instead of being dropped without any signal - without it, a missing `$fillable` entry looks identical to a bug that silently loses data
- A `$fillable` entry for a cast attribute (an array or JSON column) lets the caller supply the whole structure, including keys the application treats as internal

## Taint Sinks

`Model::create($request->all())`, `$model->update($request->all())`, `$model->fill($request->all())`, `$model->forceFill(...)`, `$guarded = []`

## Remediation Steps

- Find `Model::create($request->all())` and `$model->update($request->all())` calls in controllers
- Replace with `$request->only([...permitted fields...])` or `$request->validated()` after a Form Request
- Add or tighten `$fillable` on the affected Eloquent model to list only user-settable fields
- Remove or replace `protected $guarded = []` with a proper `$fillable` definition
- Use Laravel Form Requests (`php artisan make:request`) to centralize validation and field filtering
- Test by posting `is_admin=1` or `role=admin` and verifying the attribute is not persisted
