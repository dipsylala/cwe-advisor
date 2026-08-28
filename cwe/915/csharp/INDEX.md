# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - C#

## LLM Guidance

Mass assignment vulnerabilities in C# occur when ASP.NET model binding automatically maps user input to object properties, allowing attackers to modify security-critical fields like `IsAdmin`, `Role`, or `Balance`. This guidance focuses on ASP.NET Core and newer. Always use ViewModels/DTOs with only permitted properties, apply `[Bind]` attributes to restrict binding, and validate all model state.

## Key Principles

- Use dedicated ViewModels/DTOs containing only properties safe for user modification
- Never bind directly to domain models or entities with sensitive properties
- Apply `[BindNever]` to exclude sensitive properties from model binding explicitly
- Validate `ModelState.IsValid` before processing any bound data
- Use explicit property assignment instead of automatic model binding for sensitive operations
- `[Bind("Username,Email")]` is an allowlist on one action and is easy to omit on the next - a dedicated view model with only the bindable properties makes the restriction structural

## Taint Sinks

`TryUpdateModelAsync()`, action parameters bound directly to domain/entity types, `[Bind]` applied to an entity instead of a DTO

## Remediation Steps

- Create a ViewModel/DTO class with only the properties users should modify
- Apply `[BindNever]` attribute to sensitive properties if direct entity binding is unavoidable
- Replace controller action parameters from domain entities to ViewModels
- Prefer DTOs; if using ASP.NET Core `[Bind]`, use `[Bind("Prop1,Prop2")]` on action parameters to whitelist bindable properties
- Map ViewModel properties explicitly to domain entities using manual assignment or AutoMapper
- Always check `ModelState.IsValid` before processing bound data
