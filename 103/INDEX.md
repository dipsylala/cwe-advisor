# CWE-103: Struts: Incomplete validate() Method Definition

## LLM Guidance

Struts ActionForm's `validate()` method that returns null or is improperly implemented bypasses validation, allowing unvalidated user input to reach application logic. This enables injection attacks, data integrity issues, and business logic bypasses. Three things must agree for validation to run - the method, the action mapping's `validate` attribute, and the form name in `validation.xml` - and all three fail silently, so confirm which one is actually broken before editing.

## Key Principles

- All ActionForm classes must implement complete `validate()` methods that return ActionErrors (never null); Struts treats a `null` return and an empty `ActionErrors` alike, as "no errors"
- When overriding `validate()` in a `ValidatorForm`/`DynaValidatorForm` subclass, call `super.validate(mapping, request)` and merge its result - without that call the declarative rules in `validation.xml` never run, however complete the hand-written checks look
- Confirm the action mapping carries `validate="true"` and that the `validation.xml` form name matches the `form-bean` name; a correct method wired to neither validates nothing
- Every form field accepting user input requires explicit validation rules
- Security requirements and validations must be fully documented and enforced
- Use Struts validator framework (`ValidatorForm`, `DynaValidatorForm`) for comprehensive validation
- Trace data flows to ensure no unvalidated input reaches business logic

## Remediation Steps

- Review security findings to identify ActionForm classes with incomplete or null-returning `validate()` methods
- Check for empty implementations, stub code, or missing field validations
- Extend proper validation classes (`ValidatorForm` or `DynaValidatorForm`) instead of basic `ActionForm`
- Implement complete `validate()` method that validates all form fields and returns ActionErrors object
- Configure validation rules in validation.xml or use annotations for declarative validation
- Test all input paths to verify validation is enforced before data reaches business logic - submit a value only `validation.xml` rejects (a too-short field, a malformed email) and assert the `input` page is returned with the field error, then a value only the custom check rejects, then a valid submission to confirm it still reaches the action
- Treat the reported form as a sample: overriding `validate()` without `super` is a habit, so check every `ValidatorForm` subclass and every mapping with `validate="false"`
- Record the fix as a compensating control - Struts 1 has had no security patches since 2008, so the codebase is running an unmaintained framework, and migration is the larger finding. Restored validation is also not a replacement for parameterized queries (CWE-89) or output encoding (CWE-79) downstream
