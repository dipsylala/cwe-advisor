# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - Ruby

## LLM Guidance

Mass assignment vulnerabilities in Ruby on Rails occur when Rails automatically assigns request parameters to model attributes, allowing attackers to modify security-critical fields like `is_admin`, `role`, or `balance`. Always use Strong Parameters to allowlist permitted attributes, never use `update` with unfiltered params, and validate all input.

## Key Principles

- Allowlist only safe attributes - Never permit all parameters; explicitly define permitted fields
- Separate create/update permissions - Different actions may require different permitted attributes
- Protect administrative fields - Never permit `role`, `is_admin`, `user_id`, or similar security fields
- Validate business logic - Strong Parameters prevents mass assignment but doesn't validate values
- Avoid legacy patterns - `attr_accessible` isn't a Rails 4+ feature at all; it's inert unless the unmaintained `protected_attributes` gem is explicitly added, so finding it is a sign that gem is present, not that Strong Parameters was skipped. Never permit all with `params.permit!`
- As of Rails 8.0, `params.expect(model: [:field1, :field2])` is the guide's preferred form over `params.require(:model).permit(:field1, :field2)` - it raises on a missing or wrong-shaped top-level key instead of silently proceeding
- A permitted nested attributes hash (`accepts_nested_attributes_for`) is still a mass-assignment vector: permitting a nested `:id` alongside the nested fields lets the caller redirect the update to an arbitrary existing record of that association rather than creating a new one - permit nested `:id` only where reassigning to another user's record is an accepted outcome. Strong Parameters also has to be applied recursively - permitting a top-level key doesn't automatically permit its own nested hash
- `params.to_unsafe_h` and a dynamic `send("#{key}=", value)` loop both bypass Strong Parameters as completely as `permit!` does - grep for both alongside the more obvious sinks
- `update_column`/`update_columns` write directly to the database, skipping validations and callbacks - routing a "fix" through them to avoid a validation that's "in the way" reopens whatever that validation was enforcing

## Taint Sinks

`Model.new(params[:model])`, `@model.update(params[:model])`, `params.permit!`, `params.to_unsafe_h`, `update_column`/`update_columns` with request-derived data

## Remediation Steps

- Define private `*_params` methods in controllers using `params.require().permit()`, or `params.expect()` on Rails 8.0+
- Replace all `Model.new(params[:model])` with `Model.new(model_params)`
- Replace `@model.update(params[:model])` with `@model.update(model_params)`
- Review permitted attributes - remove any administrative or security-critical fields
- If `attr_accessible` appears in the codebase, check for the `protected_attributes` gem in the Gemfile and remove both in favor of Strong Parameters
- Add server-side validation for business rules and constraints
- Grep for every controller, admin panel, and Rake task that touches the model directly, not just the actions already using Strong Parameters - a scoped `*_params` method on one controller doesn't protect a second one calling `Model.new`/`.update` on the same class
- Test by attempting to inject unauthorized parameters in requests
