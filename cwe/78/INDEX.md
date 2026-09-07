# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. The primary remediation, where the command is incidental to what the code needs to do, is to eliminate system command execution entirely by using language-native library alternatives (file I/O APIs, HTTP clients, compression libraries). Only if no library exists should parameterized execution APIs be considered.

Where executing a command is the purpose of the code rather than a means to an end, removing the call is a regression, not a remediation - keep the execution and make it safe. A library that does something similar is not an equivalent: a TCP connect is not an ICMP ping, and a host that answers `ping` with port 80 closed changes from reachable to unreachable under the swap. `ping` is the standing example: no standard library here ships a ping, and building one means an ICMP socket - a raw socket, or on Linux a datagram ICMP socket that the `net.ipv4.ping_group_range` sysctl must admit the process's group to - plus the echo, timing and output the tool produced. That is a rewrite, not a replacement, so it is a keep-and-execute-safely case in every language file here except where the runtime ships an ICMP class. Either way, preserve what the code returned: a replacement that emits output the original discarded trades an injection for an information leak, and one that returns a different shape (a boolean where the caller parsed a table) breaks the caller.

## Key Principles

- Eliminate OS command execution completely - Replace with built-in library functions as the primary defence
- Never concatenate user input into command strings
- Avoid shell interpreters (sh, bash, cmd.exe) completely - and note that changing to a modern API while keeping `shell=True`, `sh -c`, or `cmd /c` changes only the function name, not the injection point
- On Windows, a `.bat`/`.cmd` target is a shell: there is no argv array at the system-call level, so `cmd.exe` re-parses the command line even when the caller passed an argument array. Node.js and PHP shipped fixes for this in 2024 (CVE-2024-27980, CVE-2024-1874); Java, .NET, Go and Python leave it to the caller. Invoke the executable the batch file wraps instead
- Use parameterized APIs only as a last resort when no native library exists (ProcessBuilder, subprocess with list arguments)
- Array-form/no-shell execution stops shell metacharacter injection but not argument injection (CWE-88) - a value that becomes a full argument can still be interpreted as a flag by the target program; insert a literal `--` before user-controlled operands where the program honours it, which rejects nothing, and reject a leading `-` only where it does not, saying so in the write-up
- Input validation is insufficient - It's only effective as a secondary defence layer, and it must be applied to the value that actually reaches the sink; validating at the entry point does not hold if a later layer re-assembles the command as a single string
- Invoke the program by absolute path so a writable `PATH` entry cannot substitute a different binary
- Apply least privilege to any remaining process execution

## Remediation Steps

- Identify all command execution points - anywhere the process spawns a shell or external program (see the language-specific guidance's Taint Sinks for concrete function names)
- Determine the native library alternative for each command's purpose (file operations → File I/O APIs, HTTP requests → HTTP clients, etc.) and confirm it performs the same operation with the same result, not a similar one; where none does, the command stays
- Replace system commands with appropriate language-native APIs
- For truly unavoidable commands, use parameterized execution APIs with separate argument arrays (never shell invocation)
- Remove all shell patterns and string concatenation in command construction
- Add validation only where the value has a format the application owns (a hostname, an interface name, a report id); enforce that format and say what it rejects. A pattern chosen for security alone rejects legitimate values (an IPv6 address, a filename with a space) and is a regression, not a defence
- Apply least privilege principles to any remaining process execution
