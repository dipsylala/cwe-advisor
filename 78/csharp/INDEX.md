# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - C#

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In C#, eliminate Process.Start() and ProcessStartInfo calls entirely by using .NET Framework classes (System.IO, System.Net, System.IO.Compression) for file operations, HTTP requests, and archive handling.

## Key Principles

- Replace all Process.Start() and ProcessStartInfo calls with .NET Framework class alternatives
- Use System.IO.File and System.IO.Directory for file operations instead of system commands
- Use System.Net.Http.HttpClient for HTTP requests instead of curl/wget
- Use System.Net.NetworkInformation.Ping for network checks instead of ping command
- Use System.IO.Compression for archive operations instead of zip commands
- Never concatenate user input into command strings
- Only use ProcessStartInfo as a last resort with ArgumentList and UseShellExecute = false
- `ArgumentList` does not protect a `.bat`/`.cmd` target: Windows has no argv array at the system-call level, so `cmd.exe` re-parses the command line for a batch file and .NET leaves that to the caller. Launch the executable the batch file wraps instead. The same applies to `powershell.exe -Command`, which re-parses its argument as script - use `-File` with a fixed script path and `-NoProfile` where PowerShell is genuinely required, passing user data as declared script parameters - `-File` is what stops the value being re-parsed as script; signing governs which scripts may run at all, not how their arguments are parsed
- ArgumentList prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; reject values starting with `-` or use `--` to end option parsing where the target program supports it

## Taint Sinks

`Process.Start()`, `ProcessStartInfo`

## Remediation Steps

- Locate command execution - Identify all Process.Start() and ProcessStartInfo instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the .NET class alternative - Use System.IO for file ops, HttpClient for HTTP, Ping for network
- Replace process execution - Delete Process.Start() code and use the appropriate .NET class
- For unavoidable commands - Use ProcessStartInfo with ArgumentList and UseShellExecute = false, validate all inputs
- Test thoroughly - Verify the .NET class replacement provides the same functionality
