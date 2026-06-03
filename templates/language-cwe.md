# CWE-{ID}: {Vulnerability Name} - {Language}

## LLM Guidance

{Write 2-4 concise sentences explaining how this CWE commonly appears in this language or framework, naming the vulnerable APIs and the preferred safe APIs or framework protections.}

## Key Principles

- {Language-specific primary defence with API or framework names}
- {Unsafe functions, methods, annotations, configuration, or idioms to avoid}
- {Preferred validation, encoding, binding, canonicalization, or authorization approach}
- {If allowlists are used, use language-appropriate lookup/map patterns that return a trusted value instead of continuing with the original input}
- {Framework-native protection to enable or preserve}
- {Defence-in-depth control, if applicable}

## Remediation Steps

- Locate - {Identify language-specific sources and sinks, such as request APIs and dangerous operations}
- Trace data flow - {Follow the value through common language constructs, callbacks, templates, or framework layers}
- Replace the unsafe pattern - {Convert the vulnerable API usage to the safe API or framework feature}
- Bind, encode, validate, or authorize - {Apply the concrete language-specific operation required by this CWE}
- Break taint after allowlist validation - {Assign the allowlist-selected canonical value to a fresh variable and use it for the sink}
- Harden configuration - {Enable relevant framework protections or runtime settings}
- Test - {Verify with language-appropriate unit, integration, or scanner tests}

## Safe Pattern

```{language}
// SAFE: {Short description of the secure pattern}
// If this pattern uses an allowlist, pass the allowlist-selected value to the sink.
{Minimal safe code example}
```
