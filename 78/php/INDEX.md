# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - PHP

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In PHP, eliminate exec(), system(), shell_exec(), passthru(), and backtick calls entirely by using native PHP functions (copy(), rename(), file_get_contents(), cURL functions) for file operations and HTTP requests.

## Key Principles

- Replace all exec(), system(), shell_exec(), passthru(), and backtick calls with PHP built-in function alternatives
- Use copy(), rename(), unlink(), mkdir() for file operations instead of system commands
- Use cURL functions or file_get_contents() for HTTP requests instead of curl/wget commands
- Use fsockopen() for network checks instead of ping command
- Neither `escapeshellarg()` nor `escapeshellcmd()` is a primary defence, and they are not interchangeable: `escapeshellcmd()` escapes metacharacters but does not quote, so the value can still split into extra arguments - treat a finding closed with it as still open. `escapeshellarg()` does quote, but its quoting is platform-dependent and correct only for the shell it targets
- Never concatenate user input into command strings
- Only use proc_open() as a last resort with an argument array; the `bypass_shell` option in `$other_options` avoids the `cmd.exe` wrapper but is Windows-specific and has no effect on Linux/macOS
- Prefer `Symfony\Component\Process\Process` constructed with an array of arguments over a hand-rolled `proc_open()` - it builds the argument vector itself and reaches a shell only via `Process::fromShellCommandline()`
- On Windows a `.bat`/`.cmd` target re-enters `cmd.exe` even with `bypass_shell` set, because `CreateProcess` starts the shell for a batch file. PHP fixed `proc_open()` with an argument array in 8.1.28, 8.2.18 and 8.3.6 (CVE-2024-1874), then fixed a trailing-space bypass of that fix in 8.1.29, 8.2.20 and 8.3.8 (CVE-2024-5585). Set the floor at 8.1.29 / 8.2.20 / 8.3.8, since the first fix alone is bypassable. The patch does not reach `exec()`, `system()`, `shell_exec()` or backticks, which invoke a shell by design and are unaffected either way, and it cannot help when the batch file itself interpolates `%1` into a further command - invoke the executable the batch file wraps
- An argument array prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; reject values starting with `-` or use `--` to end option parsing where the target program supports it

## Taint Sinks

`exec()`, `system()`, `shell_exec()`, `passthru()`, `` `backticks` ``, `proc_open()`, `popen()`

## Remediation Steps

- Locate command execution - Identify all exec(), system(), shell_exec(), passthru(), backtick, and proc_open() instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the PHP function alternative - Use copy/rename for file ops, cURL for HTTP, fsockopen for network
- Replace process execution - Delete exec()/system()/shell_exec() code and use the appropriate PHP function
- For unavoidable commands - Use proc_open() with argument array and bypass_shell option, validate all inputs
- Test thoroughly - Verify the PHP function replacement provides the same functionality
