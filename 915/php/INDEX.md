# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - PHP / Laravel

## LLM Guidance

Mass assignment in Laravel Eloquent occurs when `Model::create($request->all())` or `$model->update($request->all())` is called, allowing request parameters to overwrite any model attribute including protected ones like `is_admin`, `role`, or `email_verified_at`. Laravel's guard against this is the `$fillable` (allowlist) or `$guarded` (denylist) property on the model — but models with `$guarded = []` or missing both properties are fully exposed. Always define `$fillable` with an explicit allowlist.

## Key Principles

- Define `$fillable` on every Eloquent model to explicitly allowlist mass-assignable attributes
- Never set `$guarded = []` or `protected $guarded = ['*']` (the latter disables protection entirely in some versions)
- Never pass `$request->all()` or `$request->input()` directly to `create()` or `update()` without filtering
- Use `$request->only(['field1', 'field2'])` to select permitted fields from the request
- Set security-critical attributes (role, is_admin, verified_at) only through dedicated code paths, not from request input

## Remediation Steps

- Find `Model::create($request->all())` and `$model->update($request->all())` calls in controllers
- Replace with `$request->only([...permitted fields...])` or `$request->validated()` after a Form Request
- Add or tighten `$fillable` on the affected Eloquent model to list only user-settable fields
- Remove or replace `protected $guarded = []` with a proper `$fillable` definition
- Use Laravel Form Requests (`php artisan make:request`) to centralize validation and field filtering
- Test by posting `is_admin=1` or `role=admin` and verifying the attribute is not persisted

## Safe Pattern

```php
<?php
// app/Models/User.php
class User extends Model
{
    // Explicit allowlist — only these fields can be mass-assigned
    protected $fillable = ['name', 'email', 'password'];
    // 'is_admin', 'role', 'email_verified_at' are NOT listed — they cannot be mass-assigned
}

// app/Http/Requests/UpdateProfileRequest.php
class UpdateProfileRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'name'  => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'unique:users,email,' . $this->user()->id],
        ];
    }
}

// app/Http/Controllers/UserController.php
class UserController extends Controller
{
    public function update(UpdateProfileRequest $request): RedirectResponse
    {
        // $request->validated() returns only the fields defined in rules()
        $request->user()->update($request->validated());
        return redirect()->route('profile');
    }
}
```
