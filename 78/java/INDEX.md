# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - Java

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In Java, eliminate Runtime.exec() and ProcessBuilder calls entirely by using native Java libraries (java.nio.file.Files, java.net.http.HttpClient, java.util.zip, etc.) for file operations, HTTP requests, and archive handling.

## Key Principles

- Replace all Runtime.exec() and ProcessBuilder calls with Java standard library alternatives
- Use java.nio.file.Files for file operations (copy, move, delete) instead of system commands
- Use java.net.http.HttpClient or HttpURLConnection for HTTP requests instead of curl/wget
- Use java.util.zip for archive operations instead of tar/zip commands
- Never concatenate user input into command strings
- Only use ProcessBuilder as a last resort with validated argument lists (no shell invocation)
- `Runtime.exec(String)` tokenizes its argument with `StringTokenizer`, so one concatenated string becomes several arguments; use `Runtime.exec(String[])` or `ProcessBuilder` with a list
- On Windows, a `.bat`/`.cmd` target re-enters `cmd.exe`, which parses the command line itself, so an argument list is not sufficient - launch the executable the batch file wraps. Keep `jdk.lang.Process.allowAmbiguousCommands` at `false` so the JVM does not fall back to the legacy, less-quoted Windows command-line handling
- A separate argument list prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; reject values starting with `-` or use `--` to end option parsing where the target program supports it

## Taint Sinks

`Runtime.exec()`, `ProcessBuilder()`, `ProcessBuilder.start()`

## Remediation Steps

- Locate command execution - Identify all Runtime.exec() and ProcessBuilder instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the Java library alternative - Use Files API for file ops, HttpClient for HTTP, InetAddress for network checks
- Replace process execution - Delete Runtime.exec()/ProcessBuilder code and use the appropriate Java library
- For unavoidable commands - Use ProcessBuilder with separate arguments (never shell), validate all inputs
- Test thoroughly - Verify the Java library replacement provides the same functionality
