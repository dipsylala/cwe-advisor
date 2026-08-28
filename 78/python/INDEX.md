# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - Python

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In Python, eliminate subprocess, os.system(), and os.popen() calls entirely by using native Python libraries (pathlib, shutil, requests, socket) for file operations, HTTP requests, and network operations.

## Key Principles

- Replace all subprocess, os.system(), and os.popen() calls with Python standard library alternatives
- Use pathlib and shutil for file operations (copy, move, delete) instead of system commands
- Use requests or urllib for HTTP requests instead of curl/wget
- Use socket for network checks instead of ping commands
- Never concatenate user input into command strings
- Never use shell=True - it enables shell injection
- Only use subprocess as a last resort with argument lists and shell=False
- On Windows, a `.bat`/`.cmd` target re-enters `cmd.exe`, which parses the command line itself; Python leaves that to the caller, so `shell=False` plus an argument list gives no protection there. Invoke the executable the batch file wraps instead
- `shlex.quote()` is a shell-quoting helper, not a substitute for `shell=False`; reach for it only when a shell is genuinely unavoidable
- An argument list prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; reject values starting with `-` or use `--` to end option parsing where the target program supports it

## Taint Sinks

`subprocess.run()`, `subprocess.call()`, `subprocess.Popen()`, `os.system()`, `os.popen()`

## Remediation Steps

- Locate command execution - Identify all subprocess, os.system(), os.popen() instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the Python library alternative - Use pathlib/shutil for file ops, requests for HTTP, socket for network
- Replace process execution - Delete subprocess/os.system code and use the appropriate Python library
- For unavoidable commands - Use subprocess.run() with argument list and shell=False, validate all inputs
- Test thoroughly - Verify the Python library replacement provides the same functionality
