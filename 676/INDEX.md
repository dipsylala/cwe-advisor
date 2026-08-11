# CWE-676: Use of Potentially Dangerous Function

## LLM Guidance

Dangerous functions - unbounded string/memory operations, unvalidated shell or process execution, weak randomness, and dynamic code evaluation - lack bounds checking, enable code execution, or carry other inherent security flaws in a language's standard library. Using them creates buffer overflows, command injection, code injection, and other vulnerabilities that modern, safer alternatives prevent.

## Key Principles

- Replace unbounded string/memory-copy functions with length-aware or bounds-checked alternatives
- Replace shell/process execution with parameterized alternatives that pass arguments as arrays rather than a shell-interpreted string
- Use the platform's cryptographically secure random source instead of general-purpose or legacy random functions
- Ban dangerous functions in security-sensitive code through linting rules, static analysis, and code review policies
- Add validation layers if dangerous functions cannot be replaced: strict input validation, bounds checking, allowlisting

## Remediation Steps

- Identify dangerous calls - search the codebase for the language's known-unsafe string, memory, process-execution, and eval-style functions (see the language-specific guidance's Taint Sinks for concrete names)
- Analyze data flow - Trace if user input or untrusted data reaches the dangerous function
- Replace systematically - swap in the language's bounds-checked, parameterized, or sandboxed equivalents
- Validate inputs - Where replacement impossible, add strict length checks, character allowlisting, bounds verification before calling function
- Test with exploits - Try oversized inputs, command injection payloads (`;rm -rf /`), format strings to verify fixes block attacks
- Enforce prevention - Add static analysis/linting rules appropriate to the language to catch dangerous functions in the CI/CD pipeline
