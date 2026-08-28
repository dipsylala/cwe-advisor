# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - PHP

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In PHP, eliminate exec(), system(), shell_exec(), passthru(), and backtick calls entirely by using native PHP functions (copy(), rename(), file_get_contents(), cURL functions) for file operations and HTTP requests.

## Key Principles

- Replace all exec(), system(), shell_exec(), passthru(), and backtick calls with PHP built-in function alternatives
- Use copy(), rename(), unlink(), mkdir() for file operations instead of system commands
- Use cURL functions or file_get_contents() for HTTP requests instead of curl/wget commands
- Use fsockopen() for network checks instead of ping command
- Never use escapeshellarg() or escapeshellcmd() as a primary defence - they are insufficient
- Never concatenate user input into command strings
- Only use proc_open() as a last resort with an argument array; the `bypass_shell` option in `$other_options` avoids the `cmd.exe` wrapper but is Windows-specific and has no effect on Linux/macOS
- A `.bat`/`.cmd` target re-enters `cmd.exe` regardless, because Windows parses the command line for batch files; PHP addressed the resulting injection in 2024 (CVE-2024-1874), so keep the runtime patched and prefer invoking the executable the batch file wraps
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
