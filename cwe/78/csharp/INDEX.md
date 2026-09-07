# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - C#

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In C#, eliminate Process.Start() and ProcessStartInfo calls where the command is incidental, by using .NET Framework classes (System.IO, System.Net, System.IO.Compression) for file operations, HTTP requests, and archive handling. Decide first which case this is: where the command is incidental - a wrapper around something the language does natively - replacing it removes the sink entirely and is the better fix; where running a command is the feature the endpoint exists for, removing it is not a fix but a regression, and the work is to execute safely. In either case the remediated code must return what the original returned: a replacement that emits data the original discarded introduces an information leak while closing the injection.

## Key Principles

- Replace all Process.Start() and ProcessStartInfo calls with .NET Framework class alternatives
- Use System.IO.File and System.IO.Directory for file operations instead of system commands
- Use System.Net.Http.HttpClient for HTTP requests instead of curl/wget
- `System.Net.NetworkInformation.Ping` is ICMP, so it can replace the `ping` command - but `ping -n 4` sends four echoes and prints a per-reply table, while `Ping.Send()` sends one and returns a `PingReply`. Loop the count and keep the response shape the caller parsed; where the tool's output is itself the feature, keep the `ping` binary under `ArgumentList` instead
- Inside a controller, a bare `File` resolves to the inherited `ControllerBase.File()` method (CS0119), so write `System.IO.File` in full when replacing a command with file I/O there
- Use System.IO.Compression for archive operations instead of zip commands
- Never concatenate user input into command strings
- Only use `ProcessStartInfo` as a last resort, with `ArgumentList` and `UseShellExecute = false`. Two
  things about that pair are commonly misread. `ArgumentList` exists only on .NET Core 2.1, .NET
  Standard 2.1 and later and is absent from every .NET Framework version, so on Framework the escaping
  falls back to hand-quoting `Arguments`. And `UseShellExecute` defaults to `false` on .NET Core and
  .NET 5+ but `true` on .NET Framework, so setting it explicitly is load-bearing only there
- `UseShellExecute = false` is not what keeps a command shell out of the picture: Microsoft documents
  the "shell" in that property as the *graphical* shell, not `cmd.exe` or `sh`. What avoids a command
  shell is not naming one as the executable - so a fix that flips this flag while still launching
  `cmd.exe /c` has changed nothing
- `ArgumentList` does not protect a `.bat`/`.cmd` target: Windows has no argv array at the system-call level, so `cmd.exe` re-parses the command line for a batch file and .NET leaves that to the caller. Launch the executable the batch file wraps instead. The same applies to `powershell.exe -Command`, which re-parses its argument as script - use `-File` with a fixed script path and `-NoProfile` where PowerShell is genuinely required, passing user data as declared script parameters - `-File` is what stops the value being re-parsed as script; signing governs which scripts may run at all, not how their arguments are parsed
- ArgumentList prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; insert a literal `--` before user-controlled operands where the target program honours it, which rejects nothing; reject a leading `-` only where it does not, and say so in the write-up

- Where an allowlist is used, anchor it with `\A` and `\z`, not `^` and `$`. In .NET both `$` and `\Z` also match
  immediately before a trailing newline, so the anchored pattern accepts `report.csv\n`

- `IPAddress.TryParse` is not a validator by itself: it accepts `010.1.1.1` and returns `8.1.1.1`,
  and accepts the three-part form `8.8.8` as `8.8.0.8`. Compare `parsed.ToString()` back against the
  input and reject any mismatch, or the value that reaches the command is not the one you checked

## Taint Sinks

`Process.Start()`, `ProcessStartInfo`

## Remediation Steps

- Locate command execution - Identify all Process.Start() and ProcessStartInfo instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the .NET class alternative - Use System.IO for file ops, HttpClient for HTTP, Ping for network
- Replace process execution - Delete Process.Start() code and use the appropriate .NET class
- For unavoidable commands - Use ProcessStartInfo with ArgumentList and UseShellExecute = false, validate all inputs
- Test thoroughly - Verify the .NET class replacement provides the same functionality
