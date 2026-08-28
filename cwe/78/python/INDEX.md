# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - Python

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In Python, eliminate subprocess, os.system(), and os.popen() calls where the command is incidental, by using native Python libraries (pathlib, shutil, requests, socket) for file operations, HTTP requests, and network operations. Decide first which case this is: where the command is incidental - a wrapper around something the language does natively - replacing it removes the sink entirely and is the better fix; where running a command is the feature the endpoint exists for, removing it is not a fix but a regression, and the work is to execute safely. In either case the remediated code must return what the original returned: a replacement that emits data the original discarded introduces an information leak while closing the injection.

## Key Principles

- Replace all subprocess, os.system(), and os.popen() calls with Python standard library alternatives
- Use pathlib and shutil for file operations (copy, move, delete) instead of system commands
- Use requests or urllib for HTTP requests instead of curl/wget
- Use socket for network checks instead of ping commands
- Never concatenate user input into command strings
- Default to `shell=False` with an argument list; where a shell is used it becomes the caller's job to
  quote every metacharacter, which is the actual source of the injection. Treat this as a strong
  default rather than an absolute, because CPython's own security-considerations section recommends
  the opposite in one case: for a Windows batch file with untrusted arguments it advises passing
  `shell=True` so Python can escape the special characters
- Only use subprocess as a last resort with argument lists and shell=False
- On Windows, a `.bat`/`.cmd` target re-enters `cmd.exe`, which parses the command line itself; Python leaves that to the caller, so `shell=False` plus an argument list gives no protection there. Invoke the executable the batch file wraps instead
- `shlex.quote()` is a shell-quoting helper, not a substitute for `shell=False`; reach for it only when
  a shell is genuinely unavoidable, and only on POSIX. The `shlex` documentation states the module is
  designed only for Unix shells and that `quote()` is not guaranteed correct elsewhere, so on Windows
  it is not a mitigation at all
- An argument list prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; reject values starting with `-` or use `--` to end option parsing where the target program supports it

- Anchor the allowlist with `re.fullmatch()`, not `re.match()` against `^...$`. In Python `$` also
  matches immediately before a trailing newline, so the anchored pattern accepts `report.csv\n` and
  the value reaches the command with a newline attached

- Make the argument-injection check concrete: `['tar', 'czf', archive, filename]` with a filename of
  `--to-command=...` hands `tar` an option and no shell was involved. Note also that
  `['ping', '-c', '4', ip]` and `['python3', script]` have the same shape and very different
  exposure - the second hands its argument to an interpreter, so any value is code

## Taint Sinks

`subprocess.run()`, `subprocess.call()`, `subprocess.Popen()`, `os.system()`, `os.popen()`

## Remediation Steps

- Locate command execution - Identify all subprocess, os.system(), os.popen() instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the Python library alternative - Use pathlib/shutil for file ops, requests for HTTP, socket for network
- Replace process execution - Delete subprocess/os.system code and use the appropriate Python library
- For unavoidable commands - Use subprocess.run() with argument list and shell=False, validate all inputs
- Test thoroughly - Verify the Python library replacement provides the same functionality
