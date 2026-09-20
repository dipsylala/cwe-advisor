# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')

## LLM Guidance

Most findings filed as CWE-77 are OS shell injection, and MITRE records the ID being used where CWE-78 was meant - if the sink is a shell, use CWE-78. Use this entry for a non-shell interpreter: a protocol command builder, a mail or network control channel, an embedded query or macro language, or an application's own command parser. Narrower siblings take precedence where they match - argument and flag injection into an already-safe call is CWE-88, a context that runs arbitrary code is CWE-94, an expression language (SpEL, OGNL, MVEL, JEXL) is CWE-917, and an LLM that follows injected text as instructions is CWE-1427.

## Key Principles

- Identify the specific command interpreter involved (protocol client, embedded query/scripting language, application command parser) before choosing a fix; the safe API differs per interpreter
- Prefer the interpreter's structured or parameterized command-construction method over raw string building wherever the client library or parser exposes one
- Treat the interpreter's own syntax (delimiters, terminators, escape sequences) as untrusted-input-hostile; never assume input is free of them
- Where no parameterized method exists, allowlist the command verb and validate each parameter's structure and type before it reaches the interpreter
- Reject a leading hyphen in any value that becomes a command argument: array-form execution delivers `-oProxyCommand=...` or `--checkpoint-action=exec=sh` faithfully to the invoked program, which reads it as an option (CWE-88)
- Anchor validation regexes to the whole string: `$` matches before a trailing newline in Python's `re`, .NET's `Regex` and PCRE, so `^[a-zA-Z0-9.-]+$` accepts `evil.com\n` in Python, C# and PHP. Use `re.fullmatch()`, `Matcher.matches()`, or `\A...\z` instead
- Where a value must be validated, allowlist the expected format rather than denylisting metacharacters, and never hand-roll escaping for a command string - quoting rules differ between POSIX shells and `cmd.exe`, and one missed case reopens the finding
- Apply defence-in-depth: least privilege for the interpreter's execution context, and logging of unexpected or malformed command verbs

## Remediation Steps

- Locate - identify untrusted input and the specific non-OS-shell command interpreter it reaches (protocol client, embedded language, custom parser)
- Trace data flow - follow the value from source to the point where it is assembled into a command or command argument
- Identify the unsafe pattern - string concatenation or interpolation building a raw command instead of using the library's structured command API
- Replace with the safe pattern - use the interpreter's parameterized or structured command method, or a well-maintained client library that frames commands itself
- Validate where a format exists - command verbs come from a fixed set, so look them up in a map; constrain a parameter's shape only where the protocol or the application defines it, and say in the write-up what it rejects
- Apply least privilege - constrain what the interpreter's execution context can do even if injection occurs
- Test - verify with inputs containing the interpreter's delimiter or terminator sequences (command separators, CRLF, substitution syntax such as `$(...)`, and a value beginning with `-`) and confirm they are treated as literal data; test the bytes that reach the sink rather than the bytes on the wire, since the framework has usually already percent-decoded them. Assert legitimate input still works - a control that rejects everything passes every attack test
