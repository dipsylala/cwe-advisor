# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - JavaScript

## LLM Guidance

OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation, allowing attackers to execute arbitrary commands on the host. In Node.js, eliminate child_process module usage entirely by using native Node.js modules (fs, net, http/https) for file operations, HTTP requests, and network operations.

## Key Principles

- Replace all child_process.exec(), child_process.spawn(), and child_process.execFile() calls with Node.js module alternatives
- Use fs or fs.promises for file operations instead of system commands
- Use fetch, http, or https modules for HTTP requests instead of curl/wget
- Use net module for network checks instead of ping commands
- Never concatenate user input into command strings
- Never use shell: true - it enables shell injection
- Only use child_process as a last resort with argument arrays and shell: false
- A `.bat`/`.cmd` target re-enters `cmd.exe` on Windows even without `shell: true`. Node closed this in 18.20.2, 20.12.2 and 21.7.3 (CVE-2024-27980) by *refusing* to spawn a batch file directly - `spawn`/`spawnSync` now fail with `EINVAL`. Read that error as the fix working: adding `shell: true` to make the call succeed again re-opens the exact surface the patch closed. Invoke the executable the batch file wraps instead
- An argument array prevents shell injection but not argument injection (CWE-88) - a value that becomes a full argument can still be read as a flag by the target program; reject values starting with `-` or use `--` to end option parsing where the target program supports it

## Taint Sinks

`child_process.exec()`, `child_process.execSync()`, `child_process.spawn()` (with `shell: true`), `child_process.execFile()`

## Remediation Steps

- Locate command execution - Identify all child_process.exec(), spawn(), execFile() instances
- Determine the operation's purpose - Understand what the command is trying to accomplish
- Find the Node.js module alternative - Use fs for file ops, fetch/https for HTTP, net for network
- Replace process execution - Delete child_process code and use the appropriate Node.js module
- For unavoidable commands - Use execFile() with argument array and no shell option, validate all inputs
- Test thoroughly - Verify the Node.js module replacement provides the same functionality
