# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')

## LLM Guidance

CWE-77 is the general weakness: untrusted input reaches a command interpreter of any kind, not only the OS shell, without proper neutralization of that interpreter's special or delimiter characters. The vulnerable sink can be a database or cache protocol command builder, a mail/network control-channel client, an embedded query or scripting language, or a custom application-level command parser (a REPL, chatbot, or macro syntax). Most findings reported as CWE-77 are in fact OS shell injection, and MITRE notes the ID is often used where CWE-78 was meant - if the sink is a shell, apply CWE-78 (the remediation is the same: array-form execution with the shell disabled, or a native API instead of a command). For argument/flag injection into an already-safe no-shell call, see CWE-88. For injecting into a code-execution or compilation context that runs arbitrary code, see CWE-94. Where the interpreter is an expression language (SpEL, OGNL, MVEL, JEXL), see CWE-917; where it is an LLM and the untrusted text becomes part of the instructions it follows, see CWE-1427. Remediate by using the target interpreter's own parameterized or structured command-construction API instead of building command strings by concatenation.

## Key Principles

- Identify the specific command interpreter involved (protocol client, embedded query/scripting language, application command parser) before choosing a fix; the safe API differs per interpreter
- Prefer the interpreter's structured or parameterized command-construction method over raw string building wherever the client library or parser exposes one
- Treat the interpreter's own syntax (delimiters, terminators, escape sequences) as untrusted-input-hostile; never assume input is free of them
- Where no parameterized method exists, allowlist the command verb and validate each parameter's structure and type before it reaches the interpreter
- Reject a leading hyphen in any value that becomes a command argument: array-form execution delivers `-oProxyCommand=...` or `--checkpoint-action=exec=sh` faithfully to the invoked program, which reads it as an option (CWE-88)
- Anchor validation regexes to the whole string: `$` matches before a trailing newline in Python's `re`, .NET's `Regex` and PCRE, so `^[a-zA-Z0-9.-]+$` accepts `evil.com\n` in Python, C# and PHP. Use `re.fullmatch()`, `Matcher.matches()`, or `\A...\z` instead
- Allowlist the expected format rather than denylisting metacharacters, and never hand-roll escaping for a command string - quoting rules differ between POSIX shells and `cmd.exe`, and one missed case reopens the finding
- Apply defence-in-depth: least privilege for the interpreter's execution context, and logging of unexpected or malformed command verbs
- Do not conflate this with OS process execution (CWE-78), argument/flag injection (CWE-88), code-execution or compilation contexts (CWE-94), expression-language evaluation (CWE-917), or prompt injection into an LLM (CWE-1427); route to those entries when the sink matches

## Remediation Steps

- Locate - identify untrusted input and the specific non-OS-shell command interpreter it reaches (protocol client, embedded language, custom parser)
- Trace data flow - follow the value from source to the point where it is assembled into a command or command argument
- Identify the unsafe pattern - string concatenation or interpolation building a raw command instead of using the library's structured command API
- Replace with the safe pattern - use the interpreter's parameterized or structured command method, or a well-maintained client library that frames commands itself
- Add allowlisting - restrict command verbs and parameter shapes to known-safe values as defence-in-depth
- Apply least privilege - constrain what the interpreter's execution context can do even if injection occurs
- Test - verify with inputs containing the interpreter's delimiter or terminator sequences (command separators, CRLF, substitution syntax such as `$(...)`, and a value beginning with `-`) and confirm they are treated as literal data; test the bytes that reach the sink rather than the bytes on the wire, since the framework has usually already percent-decoded them. Assert legitimate input still works - a control that rejects everything passes every attack test
