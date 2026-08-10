# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')

## LLM Guidance

CWE-77 is the general weakness: untrusted input reaches a command interpreter of any kind, not only the OS shell, without proper neutralization of that interpreter's special or delimiter characters. The vulnerable sink can be a database or cache protocol command builder, a mail/network control-channel client, an embedded query or scripting language, or a custom application-level command parser (a REPL, chatbot, or macro syntax). For OS/shell command execution specifically, see CWE-78. For argument/flag injection into an already-safe no-shell call, see CWE-88. For injecting into a code-execution or compilation context that runs arbitrary code, see CWE-94. Remediate by using the target interpreter's own parameterized or structured command-construction API instead of building command strings by concatenation.

## Key Principles

- Identify the specific command interpreter involved (protocol client, embedded query/scripting language, application command parser) before choosing a fix; the safe API differs per interpreter
- Prefer the interpreter's structured or parameterized command-construction method over raw string building wherever the client library or parser exposes one
- Treat the interpreter's own syntax (delimiters, terminators, escape sequences) as untrusted-input-hostile; never assume input is free of them
- Where no parameterized method exists, allowlist the command verb and validate each parameter's structure and type before it reaches the interpreter
- Apply defence-in-depth: least privilege for the interpreter's execution context, and logging of unexpected or malformed command verbs
- Do not conflate this with OS process execution (CWE-78), argument/flag injection (CWE-88), or code-execution/compilation contexts (CWE-94); route to those entries when the sink matches

## Remediation Steps

- Locate - identify untrusted input and the specific non-OS-shell command interpreter it reaches (protocol client, embedded language, custom parser)
- Trace data flow - follow the value from source to the point where it is assembled into a command or command argument
- Identify the unsafe pattern - string concatenation or interpolation building a raw command instead of using the library's structured command API
- Replace with the safe pattern - use the interpreter's parameterized or structured command method, or a well-maintained client library that frames commands itself
- Add allowlisting - restrict command verbs and parameter shapes to known-safe values as defence-in-depth
- Apply least privilege - constrain what the interpreter's execution context can do even if injection occurs
- Test - verify with inputs containing the interpreter's delimiter or terminator sequences (for example CRLF or command separators) to confirm they cannot inject additional commands
