# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - Java

## LLM Guidance

Mass assignment vulnerabilities in Java occur when Spring MVC/Boot automatically binds HTTP request parameters to object fields, allowing attackers to modify security-critical fields like `isAdmin`, `role`, or `balance`. Use DTOs with only permitted fields for user input, apply `@JsonIgnoreProperties` or allowlist binding with `@InitBinder`, and validate with Bean Validation annotations. Never bind request data directly to JPA entities or domain objects.

## Key Principles

- Use separate DTOs for user input that expose only modifiable fields
- Exclude sensitive fields from JSON binding with `@JsonIgnore` - this is the mechanism that actually governs a `@RequestBody` sink, since `@RequestBody` is deserialized by Jackson's `HttpMessageConverter` before any `WebDataBinder` runs. `@JsonIgnore` is bidirectional - it also removes the field from serialization, so anything reading that same field back out (an admin view, an internal API) silently breaks; use `@JsonProperty(access = JsonProperty.Access.READ_ONLY)` instead where the field must still be readable from JSON output - `READ_ONLY` means readable-only (serialized, never accepted on deserialization), and it's easy to reach for the wrong-sounding `WRITE_ONLY` by mistake, which does the opposite: it still accepts the field from incoming JSON and only suppresses it from the response, so the value stays attacker-controlled and simply becomes invisible afterward
- Reflection-based mappers carry the same silent-copy risk as `BeanUtils.copyProperties()` - MapStruct requires an explicit `@Mapping(target = "isAdmin", ignore = true)` per sensitive field with no compiler enforcement if one is missed, so a mapper interface is not automatically safer just for being generated
- Restrict form parameter binding using `@InitBinder` with `setAllowedFields()` or `setDisallowedFields()` - this only applies to `@ModelAttribute`/form-parameter binding through `WebDataBinder`; it has no effect on a `@RequestBody` JSON payload, so pairing it with a JPA entity bound via `@RequestBody` leaves that path unprotected
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
- Test by adding `isAdmin`, `role`, `balance`, or an ownership field to the request payload and confirming it is not persisted - a passing `@Valid` check doesn't prove this, since an unwanted-but-well-typed field validates successfully
