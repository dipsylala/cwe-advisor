# CWE-134: Use of Externally-Controlled Format String

## LLM Guidance

Untrusted input reaches the *format* argument rather than the substituted arguments, so the attacker controls how the function parses its own argument list.

## Key Principles

- The format/template argument must always be an application-written literal, never derived from input
- Untrusted data belongs only in the substitution argument list, never in the template position
- Concatenating a literal prefix onto untrusted input and using the result as the format does not neutralize embedded format specifiers
- Denylisting `%n` while still passing attacker-controlled text as the format leaves `%x`, `%s` and the managed-language equivalents available for disclosure or a crash
- A memory-safe language does not make the finding low risk - the write primitive is C/C++-specific, but the same root cause gives a reliable denial of service, and in languages whose format syntax supports attribute or item access, information disclosure
- For logging, use the logging framework's parameterized placeholder syntax rather than building or passing the message as a format template
- If a format must be selected dynamically, choose it from a fixed, application-defined set of templates by key, never construct one from input
- Ensure a formatting error cannot surface an unhandled exception or stack trace to the caller, as defence in depth

## Remediation Steps

- Locate - Find every call to a printf-family function, String.format/equivalent, or %/.format() interpolation where the format/template argument is not a literal
- Trace data flow - Follow the value passed as the format argument back to its source; confirm whether it originates from user input, a file, or an external system
- Identify the unsafe pattern - The format argument is a variable, concatenation, or externally influenced string rather than a fixed literal
- Replace with the safe pattern - Rewrite the call so the format is a literal template and the untrusted value moves into the substitution argument list
- Audit sibling call sites - Check the same file and related callers for other calls to the same formatting function built the same way
- Add secondary controls - Suppress detailed error output on formatting failures and enable any available compiler/linter warning for non-literal format arguments
- Test - Verify with format specifiers embedded in input that the specifiers are treated as literal text, not resolved, and that normal output still renders correctly
