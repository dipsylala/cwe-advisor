# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - Java

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In Java, eliminate Runtime.exec() and ProcessBuilder calls where the command is incidental, by using native Java libraries (java.nio.file.Files, java.net.http.HttpClient, java.util.zip, etc.) for file operations, HTTP requests, and archive handling. Decide first which case this is: where the command is incidental - a wrapper around something the language does natively - replacing it removes the sink entirely and is the better fix; where running a command is the feature the endpoint exists for, removing it is not a fix but a regression, and the work is to execute safely. In either case the remediated code must return what the original returned: a replacement that emits data the original discarded introduces an information leak while closing the injection.

## Key Principles

- Replace all Runtime.exec() and ProcessBuilder calls with Java standard library alternatives
- Use java.nio.file.Files for file operations (copy, move, delete) instead of system commands
- Use java.net.http.HttpClient or HttpURLConnection for HTTP requests instead of curl/wget
- Use java.util.zip for archive operations instead of tar/zip commands
- Never concatenate user input into command strings
- Only use ProcessBuilder as a last resort with validated argument lists (no shell invocation)
- `Runtime.exec(String)` tokenizes its argument with `StringTokenizer`, so one concatenated string becomes several arguments; use `Runtime.exec(String[])` or `ProcessBuilder` with a list - the single-string overloads are deprecated as of Java 18
- On Windows, a `.bat`/`.cmd` target re-enters `cmd.exe`, which parses the command line itself, so an argument list is not sufficient - launch the executable the batch file wraps. Set `jdk.lang.Process.allowAmbiguousCommands=false` explicitly: leaving it unset behaves the same as `true` and selects the lenient legacy encoding, so this is an opt-in to harden, not a default to preserve
- A separate argument list prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; reject values starting with `-` or use `--` to end option parsing where the target program supports it

- Use `Matcher.matches()` over a `find()` with `^...$`, and prefer `\A`/`\z` where the pattern is
  reused - a `$` also matches before a trailing line terminator, so an anchored pattern can accept a
  value with a newline appended

## Taint Sinks

`Runtime.exec()`, `ProcessBuilder()`, `ProcessBuilder.start()`

## Remediation Steps

- Locate command execution - Identify all Runtime.exec() and ProcessBuilder instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the Java library alternative - Use Files API for file ops, HttpClient for HTTP, InetAddress for network checks
- Replace process execution - Delete Runtime.exec()/ProcessBuilder code and use the appropriate Java library
- For unavoidable commands - Use ProcessBuilder with separate arguments (never shell), validate all inputs
- Test thoroughly - Verify the Java library replacement provides the same functionality
