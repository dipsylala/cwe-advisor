# CWE-{ID}: {Vulnerability Name} - {Language}

## LLM Guidance

{Write 2-4 concise sentences explaining how this CWE commonly appears in this language or framework, naming the vulnerable APIs and the preferred safe APIs or framework protections.}

## Key Principles

- {Language-specific primary defence with API or framework names}
- {Unsafe functions, methods, annotations, configuration, or idioms to avoid}
- {Preferred validation, encoding, binding, canonicalization, or authorization approach}
- {Framework-native protection to enable or preserve}
- {Defence-in-depth control, if applicable}

## Remediation Steps

- Locate - {Identify language-specific sources and sinks, such as request APIs and dangerous operations}
- Trace data flow - {Follow the value through common language constructs, callbacks, templates, or framework layers}
- Replace the unsafe pattern - {Convert the vulnerable API usage to the safe API or framework feature}
- Bind, encode, validate, or authorize - {Apply the concrete language-specific operation required by this CWE}
- Harden configuration - {Enable relevant framework protections or runtime settings}
- Test - {Verify with language-appropriate unit, integration, or scanner tests}

## Safe Pattern

```{language}
// SAFE: {Short description of the secure pattern}
{Minimal safe code example}
```
