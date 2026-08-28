# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - Java

## LLM Guidance

Mass assignment vulnerabilities in Java occur when Spring MVC/Boot automatically binds HTTP request parameters to object fields, allowing attackers to modify security-critical fields like `isAdmin`, `role`, or `balance`. Use DTOs with only permitted fields for user input, apply `@JsonIgnoreProperties` or allowlist binding with `@InitBinder`, and validate with Bean Validation annotations. Never bind request data directly to JPA entities or domain objects.

## Key Principles

- Use separate DTOs for user input that expose only modifiable fields
- Exclude sensitive fields from JSON binding with `@JsonIgnore`
- Restrict form parameter binding using `@InitBinder` with `setAllowedFields()` or `setDisallowedFields()`
- Validate all input with Bean Validation constraints (`@Valid`, `@NotNull`, `@Size`, etc.)
- Map DTO fields explicitly to entities rather than using reflection-based copiers

## Taint Sinks

`BeanUtils.copyProperties()`, `@RequestBody` bound directly to a JPA entity, `@ModelAttribute` bound to an entity

## Remediation Steps

- Create a DTO class containing only fields users should modify (e.g., `UpdateUserDTO` with `name`, `email`)
- Annotate sensitive entity fields with `@JsonIgnore` to prevent JSON binding
- Add `@InitBinder` method to controllers restricting allowed form fields
- Apply `@Valid` to controller method parameters and handle `BindingResult` errors
- Use explicit field mapping when transferring DTO data to entities (avoid `BeanUtils.copyProperties`)
- Never expose JPA entities directly as `@RequestBody` or form-backing objects
