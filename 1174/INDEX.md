# CWE-1174: ASP.NET Misconfiguration: Improper Model Validation

## LLM Guidance

ASP.NET Misconfiguration: Improper Model Validation occurs when applications fail to properly validate model data, allowing attackers to bypass security controls or inject malicious data. This vulnerability arises from improper configuration or use of ASP.NET's built-in model validation features. The core fix is to enforce server-side model validation consistently and reject invalid models before processing.

## Key Principles

- Enforce server-side model validation consistently; never rely solely on client-side validation
- Check `ModelState.IsValid` before processing any model data in MVC applications
- Return appropriate validation error responses when validation fails
- Protect against mass assignment/over-posting vulnerabilities using binding controls
- Implement both attribute-based and custom validation logic where needed
- Which *properties* may be bound and whether their *values* are valid are decided by the same model-binding step and fail together: a ViewModel that excludes `IsAdmin` addresses CWE-915, and the annotations on the properties it does expose address this one - fixing either alone leaves a real hole
- `ModelState.IsValid` reports on the annotations of the type that was bound, so binding a request straight to a database entity passes the check while validating nothing the entity does not declare
- Non-ASP.NET input-validation findings belong on CWE-20

## Remediation Steps

- Always check `ModelState.IsValid` before processing model data and return errors on failure
- Apply validation attributes (`[Required]`, `[StringLength]`, `[Range]`) to all model properties
- Use `[Bind]` attribute with explicit allowlists to prevent mass assignment attacks
- Implement `IValidatableObject` for complex cross-property validation logic
- Ensure validation is enabled globally in ASP.NET configuration
- Never trust client-side validation as the sole security control
