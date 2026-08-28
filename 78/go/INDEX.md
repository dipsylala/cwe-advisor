# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - Go

## LLM Guidance

`os/exec` does not invoke a shell when given a command and separate arguments, so most Go command injection comes from explicitly invoking `sh -c`, `bash -c`, or `cmd /C` with a concatenated or `fmt.Sprintf`-built string. The primary remediation is eliminating command execution entirely by replacing it with Go standard library equivalents (`os`, `net`, `net/http`, `archive/zip`, `archive/tar`). If a command is truly unavoidable, use `exec.Command`/`exec.CommandContext` with a separate argument list, never a shell, plus allowlist validation.

## Key Principles

- Eliminate command execution first: replace with `os`, `net`, `net/http`, `archive/tar`/`archive/zip` for the equivalent operation
- Never call `exec.Command("sh", "-c", ...)`, `"bash", "-c", ...`, or `"cmd", "/C", ...` with any untrusted string
- Pass each argument as a separate `exec.Command` parameter; never build a single command string with `+` or `fmt.Sprintf`
- Use `exec.CommandContext` with a timeout to bound any unavoidable process execution
- Validate any value that must reach `exec.Command` against a strict allowlist (regexp or map) before use
- A separate argv prevents shell injection but not argument injection (CWE-88) - a value passed as its own argument can still be read as a flag by the target program; reject values starting with `-` or insert a literal `--` before user-controlled positional arguments where the target program supports it
- Watch for the injection point moving downstream - a wrapper script invoked with safe argv that itself runs `sh -c` on one of the arguments reopens the same risk
- On Windows, launching a `.bat`/`.cmd` target re-enters `cmd.exe`, which parses the command line itself; Go leaves that to the caller, so a separate argv gives no protection there. Invoke the executable the batch file wraps instead

## Taint Sinks

`exec.Command()`, `exec.CommandContext()`, `cmd.Run()`, `cmd.Output()`, `cmd.CombinedOutput()`

## Remediation Steps

- Locate - find `os/exec` usage: `exec.Command`, `exec.CommandContext`, `cmd.Run`/`Output`/`CombinedOutput`
- Trace data flow - identify request or config data reaching the command name or its arguments
- Replace the unsafe pattern - substitute the Go standard library API that performs the same operation (file, network, archive) instead of shelling out
- Bind, encode, validate, or authorize - if exec is unavoidable, pass each user-controlled value as its own `exec.Command` argument and validate it against an allowlist
- Break taint after allowlist validation - use only the allowlist-approved value (for example, a resolved map value) as the argument, never the raw input
- Harden configuration - run with a least-privilege OS account, apply `exec.CommandContext` timeouts, and pass absolute binary paths to avoid `PATH` ambiguity
- Test - verify with shell metacharacters (`;`, `|`, `&&`, `$()`) and confirm they are treated as literal argument data, not command syntax
