# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - PHP

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In PHP, eliminate exec(), system(), shell_exec(), passthru(), and backtick calls where the command is incidental, by using native PHP functions (copy(), rename(), file_get_contents(), cURL functions) for file operations and HTTP requests. Decide first which case this is: where the command is incidental - a wrapper around something the language does natively - replacing it removes the sink entirely and is the better fix; where running a command is the feature the endpoint exists for, removing it is not a fix but a regression, and the work is to execute safely. In either case the remediated code must return what the original returned: a replacement that emits data the original discarded introduces an information leak while closing the injection.

## Key Principles

- Replace all exec(), system(), shell_exec(), passthru(), and backtick calls with PHP built-in function alternatives
- Use copy(), rename(), unlink(), mkdir() for file operations instead of system commands
- Use cURL functions or file_get_contents() for HTTP requests instead of curl/wget commands
- `ping` has no PHP equivalent: ICMP means `socket_create(AF_INET, SOCK_RAW, ...)` with root or `CAP_NET_RAW`, or on Linux `SOCK_DGRAM` with the ICMP protocol where `net.ipv4.ping_group_range` admits the process's group, and then the echo, timing and output the tool produced - a rewrite, not a function call - while `fsockopen()` is a TCP connect that answers a different question (a host that replies to ping with the probed port closed now reads unreachable). Keep the `ping` binary, run it through `proc_open()` in array form with the host as its own element and the count flag fixed, and return the output the caller had
- Neither `escapeshellarg()` nor `escapeshellcmd()` is a primary defence, and they are not interchangeable: `escapeshellcmd()` escapes metacharacters but does not quote, so the value can still split into extra arguments - treat a finding closed with it as still open. `escapeshellarg()` does quote, but its quoting is platform-dependent and correct only for the shell it targets
- Never concatenate user input into command strings
- Only use proc_open() as a last resort with an argument array; the array form requires PHP 7.4 or later, below which only a string is accepted. On Windows the `bypass_shell` option in `options` avoids the `cmd.exe` wrapper and has no effect on Linux or macOS; note the manual treats the array form as itself opening the process without a shell, so the two are one mechanism rather than two independent guards
- Prefer `Symfony\Component\Process\Process` constructed with an array of arguments over a hand-rolled `proc_open()` - it builds the argument vector itself and reaches a shell only via `Process::fromShellCommandline()`
- On Windows a `.bat`/`.cmd` target re-enters `cmd.exe` even with `bypass_shell` set, because `CreateProcess` starts the shell for a batch file. PHP fixed `proc_open()` with an argument array in 8.1.28, 8.2.18 and 8.3.6 (CVE-2024-1874), then fixed a trailing-space bypass of that fix in 8.1.29, 8.2.20 and 8.3.8 (CVE-2024-5585). Set the floor at 8.1.29 / 8.2.20 / 8.3.8, since the first fix alone is bypassable. The patch does not reach `exec()`, `system()`, `shell_exec()` or backticks, which invoke a shell by design and are unaffected either way, and it cannot help when the batch file itself interpolates `%1` into a further command - invoke the executable the batch file wraps
- An argument array prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; insert a literal `--` before user-controlled operands where the target program honours it, which rejects nothing; reject a leading `-` only where it does not, and say so in the write-up

- Where an allowlist is used, anchor it with `\A` and `\z`, not `^` and `$`. In PCRE `$` also matches immediately
  before a trailing newline, so `/^[\w.-]+$/` accepts `report.csv\n`

## Taint Sinks

`exec()`, `system()`, `shell_exec()`, `passthru()`, `` `backticks` ``, `proc_open()`, `popen()`

## Remediation Steps

- Locate command execution - Identify all exec(), system(), shell_exec(), passthru(), backtick, and proc_open() instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the PHP function alternative - Use copy/rename for file ops, cURL for HTTP; there is none for `ping`
- Replace process execution - Delete exec()/system()/shell_exec() code and use the appropriate PHP function
- For unavoidable commands - use `proc_open()` with an argument array on PHP 7.4 or later, which is
  itself what avoids the shell; `bypass_shell` matters only for the Windows string-command form.
  Validate all inputs
- Test thoroughly - Verify the PHP function replacement provides the same functionality
