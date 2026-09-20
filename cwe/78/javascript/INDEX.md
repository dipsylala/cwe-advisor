# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - JavaScript

## LLM Guidance

In Node.js, eliminate child_process module usage where the command is incidental, by using native Node.js modules (fs, net, http/https) for file operations, HTTP requests, and network operations.

## Key Principles

- Decide first whether the command is incidental or the feature: incidental means replacing the `child_process` call with the Node module that does the work natively; the feature case means it stays and the work is executing it safely
- Use fs or fs.promises for file operations instead of system commands
- Use fetch, http, or https modules for HTTP requests instead of curl/wget
- `net` is a TCP client, not a ping: Node has no ICMP without a native addon, so a `net.connect()` probe changes what "reachable" means for a host that answers ping with the probed port closed. Keep `ping` as the command and run it with `execFile('ping', [...])`, the host as its own array element and the count flag fixed, returning the output the caller had
- Never concatenate user input into command strings
- Never use shell: true - it enables shell injection
- Only use child_process as a last resort with argument arrays and shell: false
- A `.bat`/`.cmd` target re-enters `cmd.exe` on Windows even without `shell: true`. Node's first attempt at this (CVE-2024-27980, in 18.20.2, 20.12.2 and 21.7.3) was later identified as an incomplete fix, bypassed by batch files with other extensions; the operative floor is the second round - **18.20.4, 20.15.1 and 22.4.1** (CVE-2024-36138). The 21.x line reached end of life without ever receiving the complete fix. Both rounds work by *refusing* to spawn a batch file directly, so `spawn`/`spawnSync` fail with `EINVAL`. Read that error as the fix working: adding `shell: true` to make the call succeed again re-opens the exact surface the patch closed. Invoke the executable the batch file wraps instead
- An argument array prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; insert a literal `--` before user-controlled operands where the target program honours it, which rejects nothing; reject a leading `-` only where it does not, and say so in the write-up

## Taint Sinks

`child_process.exec()`, `child_process.execSync()`, `child_process.spawn()`, `child_process.spawnSync()`, `child_process.execFile()`, `child_process.execFileSync()`

## Remediation Steps

- Locate command execution - Identify all child_process.exec(), spawn(), execFile() instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the Node.js module alternative - Use fs for file ops, fetch/https for HTTP; there is none for `ping`
- Replace process execution - where that decision was to replace, delete the `child_process` call and use the Node module that does the same work; confirm it returns what the original did
- For unavoidable commands - Use execFile() with argument array and no shell option, validate only where the application owns the value's format, and say what that rejects
- Test - send `;`, `&&`, a newline, `$(id)` and a leading `-` as argument values, asserting on the arguments the child received rather than on the absence of an error, and confirm one legitimate awkward value (a path with a space, an IPv6 address) still works
