# CWE-234: Failure to Handle Missing Parameter

## LLM Guidance

Applications fail to validate that required input parameters are present before use, causing null pointer exceptions, logic errors, security bypasses (missing authentication tokens), or crashes. The fix requires explicit validation that required parameters exist before accessing them, with proper error handling for missing values. Read the citation before acting on it: MITRE marks CWE-234 Discouraged and notes it conflates two ideas - a request arriving without a parameter the handler requires (this page) and a *call site* passing fewer arguments than a function declares, which is CWE-685 under CWE-628. For new findings prefer CWE-20.

## Key Principles

- Validate parameter existence: Check all required parameters are present before accessing their values
- Fail securely: Reject requests with missing required parameters rather than using unsafe defaults
- Validate authentication/authorization params: Never proceed with security operations when tokens or credentials are missing
- Use framework validation: Apply built-in parameter validation in frameworks (schema validators, required field annotations)
- Handle optionals explicitly: Distinguish between required and optional parameters with clear default behaviors
- Check presence, not truthiness: `if (param)` rejects the legitimate values `0`, `false` and `""` as missing while letting other absent-value representations through - use `in`, `hasOwnProperty`, or `is None`
- Never default a security-relevant flag to the permissive value: `includePrivate` or `isAdmin` defaulting to true turns a forgotten field into an authorization bypass. Safe defaults belong on pagination and formatting, nothing a security decision reads
- A `required` marker in a front-end form or an OpenAPI schema is not enforcement - validate the actual request server-side, and on every verb and endpoint that shares the handler, not only the one the finding named

## Remediation Steps

- Identify unguarded parameter access - Find code that accesses request/function parameters without null/existence checks
- Add validation gates - Insert checks that verify required parameters exist before use (throw errors if missing)
- Review authentication flows - Ensure security-critical parameters (tokens, user IDs, permissions) are validated as present
- Replace unsafe defaults - Remove code that assigns default values to missing required parameters
- Use schema validation - Implement request schema validators that enforce required parameters at API boundaries
- Test missing parameter cases - Add test cases that send requests with missing parameters to verify proper rejection
