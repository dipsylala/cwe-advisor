# CWE-104: Struts: Form Bean Does Not Extend Validation Class

## LLM Guidance

This vulnerability occurs when Struts form beans do not extend the proper validation base class for the validation mechanism in use. Declarative Struts validation requires `ValidatorForm` or `DynaValidatorForm`; a plain `ActionForm` must implement a complete `validate()` method. Missing validation allows untrusted input to reach application logic. This is the sibling of CWE-103 and looks identical from the outside: CWE-104 is a form bean never wired into the validator at all, while CWE-103 is a bean that extends the right class but whose `validate()` is broken or never calls `super`. Confirm which mechanism applies before remediating.

## Key Principles

- Enforce validation at the framework level - extend ValidatorForm or DynaValidatorForm to automatically integrate with Struts validation
- Use declarative validation - define constraints in validation.xml rather than manual input checking
- Fail securely - validation should reject invalid input by default, not warn
- Nothing reports this failure: `ActionForm` is a perfectly valid form bean, so Struts accepts the configuration and the rules declared in `validation.xml` simply never run
- Check the whole path after changing the base class - the mapping needs `validate="true"` and the `validation.xml` form name must match the `form-bean` name
- Enforce through APIs and tooling - make improper usage difficult or impossible, not just documented

## Remediation Steps

- Identify non-validating beans - locate form classes that are plain POJOs or don't extend ActionForm/ValidatorForm
- Choose the right base class - extend ValidatorForm for declarative validation or DynaValidatorForm for dynamic forms
- Configure validation rules - define constraints in validation.xml mapped to your form bean
- Trace data paths - verify user input flows from HTTP parameters through validation before reaching business logic
- Test validation enforcement - confirm invalid input is rejected and doesn't reach application code
- Centralize framework validation while preserving necessary server-side business-rule checks
- Record the fix as a compensating control - Struts 1 has had no security patches since 2008, so migration off it is the larger finding, and restored validation does not replace parameterized queries (CWE-89) or output encoding (CWE-79) downstream
