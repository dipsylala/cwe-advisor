# CWE-104: Struts Form Bean Does Not Extend Validation Class

## LLM Guidance

This vulnerability occurs when Struts form beans do not extend the proper validation base class for the validation mechanism in use. Declarative Struts validation requires `ValidatorForm` or `DynaValidatorForm`; a plain `ActionForm` must implement a complete `validate()` method. Missing validation allows untrusted input to reach application logic.

## Key Principles

- Enforce validation at the framework level - extend ValidatorForm or DynaValidatorForm to automatically integrate with Struts validation
- Use declarative validation - leverage validation.xml rather than manual input checking
- Fail securely - validation should reject invalid input by default, not warn
- Enforce through APIs and tooling - make improper usage difficult or impossible, not just documented

## Remediation Steps

- Identify non-validating beans - locate form classes that are plain POJOs or don't extend ActionForm/ValidatorForm
- Choose the right base class - extend ValidatorForm for declarative validation or DynaValidatorForm for dynamic forms
- Configure validation rules - define constraints in validation.xml mapped to your form bean
- Trace data paths - verify user input flows from HTTP parameters through validation before reaching business logic
- Test validation enforcement - confirm invalid input is rejected and doesn't reach application code
- Centralize framework validation while preserving necessary server-side business-rule checks
