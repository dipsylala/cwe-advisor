# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - C#

## LLM Guidance

Mass assignment vulnerabilities in C# occur when ASP.NET model binding automatically maps user input to object properties, allowing attackers to modify security-critical fields like `IsAdmin`, `Role`, or `Balance`. This guidance focuses on ASP.NET Core and newer. Always use ViewModels/DTOs with only permitted properties, apply `[Bind]` attributes to restrict binding, and validate all model state.

## Key Principles

- Use dedicated ViewModels/DTOs containing only properties safe for user modification
- Never bind directly to domain models or entities with sensitive properties
- Apply `[BindNever]` to exclude sensitive properties from model binding explicitly
- Validate `ModelState.IsValid` before processing any bound data
- Use explicit property assignment instead of automatic model binding for sensitive operations
- `TryUpdateModelAsync()`'s property-list overload takes lambda expressions, which the compiler checks; `[Bind("Prop1,Prop2")]`'s string list does not - `[Bind]` is a closed allowlist, so a misspelled or renamed name in the string simply matches nothing and that property is silently excluded from binding (a functional bug: an intended update silently fails), not a security exposure. The compiler-checked form still catches the mistake at build time instead of only at runtime
- `[Bind("Username,Email")]` is an allowlist on one action and is easy to omit on the next - a dedicated view model with only the bindable properties makes the restriction structural
- `[Bind]`/`[BindNever]` only affect form-encoded MVC model binding - Microsoft's own docs state they "do not affect input formatters," so a `[FromBody]` JSON action parameter (the common case for a JSON API) ignores them entirely; a DTO or `[JsonIgnore]` on the bound type is the only thing that restricts a JSON-bound property
- Minimal APIs (.NET 6+) bind a JSON request body straight through `System.Text.Json` with no MVC model-binding pipeline at all - `[Bind]`, `[BindNever]`, and `ModelState` don't apply there either; a dedicated request-record type is the only defense

## Taint Sinks

`TryUpdateModelAsync()`, action parameters bound directly to domain/entity types, `[Bind]` applied to an entity instead of a DTO

## Remediation Steps

- Create a ViewModel/DTO class with only the properties users should modify
- Apply `[BindNever]` attribute to sensitive properties if direct entity binding is unavoidable
- Replace controller action parameters from domain entities to ViewModels
- Prefer DTOs; if using ASP.NET Core `[Bind]` for a form-encoded action, use `[Bind("Prop1,Prop2")]` to whitelist bindable properties - for a `[FromBody]` JSON action or a Minimal API endpoint, `[Bind]` has no effect, so a DTO is not optional there
- Map ViewModel properties explicitly to domain entities using manual assignment or AutoMapper
- Always check `ModelState.IsValid` before processing bound data
- Test by adding `IsAdmin`, `Role`, `Balance`, or an ownership field (`UserId`, `TenantId`) to the request payload and confirming the persisted entity does not reflect it - `ModelState.IsValid` alone doesn't prove this, since a bound-but-unwanted property still validates successfully
