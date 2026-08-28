# CWE-1426: Improper Validation of Generative AI Output

## LLM Guidance

This vulnerability occurs when an application trusts the output of a generative AI model - its text response, tool-call arguments, or generated code/queries - without validating it the way it would validate any other untrusted input reaching the same sink. Most real-world instances are actually the existing sink-specific weakness (code injection, command injection, SQL injection, XSS) where the untrusted source happens to be the model instead of a user form field; route the actual fix to that CWE's guidance. What is specific to CWE-1426 is the mental-model gap - treating "the model produced this" as equivalent to "this is safe" or "a developer authored this" - and the LLM-specific mitigations: constraining output shape with structured generation, and validating tool-call arguments the same way you would validate a client-supplied API request.

## Key Principles

- Never pass model-generated output directly to `eval`/`exec`, a shell, a SQL driver, or an HTML renderer without the same validation or escaping applied to user input reaching that sink - use the sink-specific CWE guidance (code injection, command injection, SQL injection, XSS) for the concrete fix, with the model as the untrusted source
- Constrain the shape of generated output with structured/schema-constrained generation rather than free-text output parsed with regex or string matching - this narrows, but does not eliminate, the injection surface for whatever parses the output downstream
- Validate tool-call arguments the model produced against the same rules a client-supplied API request would need to satisfy: type-check, range-check, and re-verify authorization; the model choosing a value does not make it valid or permitted
- Treat filenames and paths that appear in generated output or tool results as attacker-controlled and apply path-traversal containment before any file operation
- Do not equate "the model reported that it verified this" with "this was verified" - a model can be instructed or manipulated into falsely claiming it checked something; perform independent verification for anything security-relevant
- MITRE marks this Discouraged for mapping: the finding is usually an existing sink-specific weakness where the untrusted source happens to be a model - a shell is CWE-78, a page CWE-79, a query CWE-89, an interpreter CWE-94, a path CWE-22 - and that entry's remediation applies unchanged
- What is specific here is the assumption that "the model produced this" means "a developer authored this", plus two mitigations: constrain the output's shape with schema-constrained generation, and treat tool-call arguments as untrusted API input rather than pre-authorized instructions
- The most common concrete case is a tool call whose `filename` argument is a traversal payload
- This is the output-side counterpart of CWE-1427, and one incident can involve both

## Remediation Steps

- Locate every point where model output - a text response, tool-call input, or generated code/query - reaches a sink: code execution, a shell, a database, the filesystem, HTML/DOM, or another API call
- Identify whether that sink already has CWE-specific guidance for its type (code injection, command injection, SQL injection, path traversal, XSS) and apply that entry's remediation, treating the model as the untrusted source in place of user input
- For tool-call arguments specifically, confirm there is a server-side validation and authorization step between "the model requested this" and "the action executes" - if that check is missing entirely, this is CWE-1427, not CWE-1426
- For filenames or paths appearing in generated output or tool results, apply path-traversal containment: resolve to canonical form and verify it stays within the intended directory before any file operation
- Constrain free-form generation with structured output or schema validation wherever the consuming code expects a specific, parseable shape
- Test with adversarial or mocked model output that attempts to reach each sink with a malicious payload, and confirm the validation layer rejects it independent of what the model intended
