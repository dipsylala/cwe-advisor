# CWE-{ID}: {Vulnerability Name}

## LLM Guidance

{Write 2-4 concise sentences explaining how the weakness appears, why the current pattern is unsafe, and the primary remediation strategy. Keep this vendor-neutral and focused on what the LLM should do when fixing code.}

## Key Principles

- {Primary defence mechanism}
- {Pattern or shortcut to avoid}
- {How to handle untrusted data}
- {Where validation, encoding, canonicalization, or authorization belongs}
- {Defence-in-depth control, if applicable}

## Remediation Steps

- Locate - {Identify the untrusted source and vulnerable sink}
- Trace data flow - {Follow the value through assignments, transformations, calls, and framework boundaries}
- Identify the unsafe pattern - {Name the operation, configuration, or API usage that creates the weakness}
- Replace with the safe pattern - {Describe the secure mechanism to use instead}
- Add secondary controls - {Add validation, least privilege, logging, headers, or configuration where relevant}
- Test - {Describe focused verification using representative malicious and normal inputs}
