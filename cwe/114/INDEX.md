# CWE-114: Process Control

## LLM Guidance

MITRE discourages mapping findings here directly, since it is a Class combining several weaknesses. A loader searching an attacker-influenced path is CWE-426, one whose fixed path contains an attacker-writable element is CWE-427, an attacker-specified library or executable path is CWE-73, and a built command line is CWE-78. Use this entry for the process-lifecycle case those do not cover - start, stop, kill, priority, resource limits.

## Key Principles

Only load components from trusted, integrity-checked locations and never allow user input to directly control process operations or library search paths.

- Hardcode all library paths and process execution commands; never construct them from user input
- Validate process identifiers against an allowlist before performing control operations
- Use absolute paths for all library loading and disable dynamic search path manipulation
- Implement strict input validation and sanitization before any process control operation
- Run processes with least privilege and enforce OS-level security policies

## Remediation Steps

- Identify the vulnerability. Locate where untrusted data controls process operations - library loading, process termination, or process spawning (see the language-specific guidance's Taint Sinks for concrete function names)
- Replace user-controlled process parameters with hardcoded values or validated allowlists
- Use absolute paths for libraries and enforce the platform loader's secure library search path settings
- If process control is required, validate PIDs/names against authorized processes owned by the application
- Apply least privilege. Ensure processes run with minimal permissions and cannot manipulate critical system processes
