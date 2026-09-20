# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - Python

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In Python, eliminate subprocess, os.system(), and os.popen() calls where the command is incidental, by using native Python libraries (pathlib, shutil, requests, socket) for file operations, HTTP requests, and network operations. Decide first which case this is: where the command is incidental - a wrapper around something the language does natively - replacing it removes the sink entirely and is the better fix; where running a command is the feature the endpoint exists for, removing it is not a fix but a regression, and the work is to execute safely. In either case the remediated code must return what the original returned: a replacement that emits data the original discarded introduces an information leak while closing the injection.

## Key Principles

- Decide first whether the command is incidental or the feature: incidental means replacing `subprocess`/`os.system()`/`os.popen()` with the Python library that does the work natively; the feature case means it stays and the work is executing it safely
- Use pathlib and shutil for file operations (copy, move, delete) instead of system commands
- Use requests or urllib for HTTP requests instead of curl/wget
- `socket` has no ping: ICMP means `SOCK_RAW` (root or `CAP_NET_RAW`) or, on Linux, `SOCK_DGRAM` with `IPPROTO_ICMP` where `net.ipv4.ping_group_range` admits the process's group, and then the echo, sequence and timing the tool did - a rewrite, not a library call; a `socket.create_connection()` probe is a TCP check with a different answer for a host that replies to ping with the probed port closed. Keep `ping` as the command: `subprocess.run(['ping', '-c', '4', host], ...)` with the host as its own list element, returning the output the caller had
- Never concatenate user input into command strings
- Default to `shell=False` with an argument list; where a shell is used it becomes the caller's job to
  quote every metacharacter, which is the actual source of the injection. CPython's own
  security-considerations section makes one exception - for a Windows batch file with untrusted
  arguments it says to "consider passing `shell=True` to allow Python to escape special characters" -
  and the implementation does not do that. `list2cmdline()` runs on an argument list either way and
  `shell=True` only wraps the result in `cmd.exe /c`, so the two are byte-identical, injection
  included (reproduced on 3.13.12). Do not take that advice; the bullet below is the answer for a
  batch target
- Only use subprocess as a last resort with argument lists and shell=False
- On Windows, a `.bat`/`.cmd` target re-enters `cmd.exe`, which parses the command line itself; Python leaves that to the caller, so `shell=False` plus an argument list gives no protection there. Invoke the executable the batch file wraps instead
- `shlex.quote()` is a shell-quoting helper, not a substitute for `shell=False`; reach for it only when
  a shell is genuinely unavoidable, and only on POSIX. The `shlex` documentation states the module is
  designed only for Unix shells and that `quote()` is not guaranteed correct elsewhere, so on Windows
  it is not a mitigation at all
- An argument list prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; insert a literal `--` before user-controlled operands where the target program honours it, which rejects nothing; reject a leading `-` only where it does not, and say so in the write-up

- Where an allowlist is used, anchor it with `re.fullmatch()`, not `re.match()` against `^...$`. In Python `$` also
  matches immediately before a trailing newline, so the anchored pattern accepts `report.csv\n` and
  the value reaches the command with a newline attached

- Make the argument-injection check concrete: `['tar', 'czf', archive, filename]` with a filename of
  `--to-command=...` hands `tar` an option and no shell was involved. Note also that
  `['ping', '-c', '4', ip]` and `['python3', script]` have the same shape and very different
  exposure - the second hands its argument to an interpreter, so any value is code

## Taint Sinks

`subprocess.run()`, `subprocess.call()`, `subprocess.check_call()`, `subprocess.check_output()`, `subprocess.Popen()`, `os.system()`, `os.popen()`

## Remediation Steps

- Locate command execution - Identify all subprocess, os.system(), os.popen() instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the Python library alternative - Use pathlib/shutil for file ops, requests for HTTP; there is none for `ping`
- Replace process execution - where that decision was to replace, delete the call and use the Python library that does the same work; confirm it returns what the original did
- For unavoidable commands - Use subprocess.run() with argument list and shell=False, validate only where the application owns the value's format, and say what that rejects
- Test - send `;`, `&&`, a newline, `$(id)` and a leading `-` as argument values, asserting on the arguments the child received rather than on the absence of an error, and confirm one legitimate awkward value (a path with a space, an IPv6 address) still works
