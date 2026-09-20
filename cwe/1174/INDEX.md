# CWE-1174: ASP.NET Misconfiguration: Improper Model Validation

## LLM Guidance

Which *properties* may be bound and whether their *values* are valid are decided by the same model-binding step and fail together: a ViewModel that excludes `IsAdmin` addresses CWE-915, and the annotations on the properties it does expose address this one - fixing either alone leaves a real hole. Non-ASP.NET input-validation findings belong on CWE-20.

## Key Principles

- Enforce server-side model validation consistently; never rely solely on client-side validation
- Check `ModelState.IsValid` before processing any model data in MVC applications
- Return appropriate validation error responses when validation fails
- Protect against mass assignment/over-posting vulnerabilities using binding controls
- Implement both attribute-based and custom validation logic where needed
- `ModelState.IsValid` reports on the annotations of the type that was bound, so binding a request straight to a database entity passes the check while validating nothing the entity does not declare

## Remediation Steps

- Always check `ModelState.IsValid` before processing model data and return errors on failure
- Apply validation attributes (`[Required]`, `[StringLength]`, `[Range]`) to all model properties
- Use `[Bind]` attribute with explicit allowlists to prevent mass assignment attacks
- Implement `IValidatableObject` for complex cross-property validation logic
- Ensure validation is enabled globally in ASP.NET configuration
- Never trust client-side validation as the sole security control
