# CWE-114: Process Control - JavaScript

## LLM Guidance

Process control vulnerabilities in JavaScript/Node.js applications occur when untrusted user input controls process execution, lifecycle, or module/library loading. Node.js's `child_process` module makes command-injection-style process control dangerous, while its CommonJS module resolution and native addon loading make dynamic `require()` calls and `NODE_OPTIONS`/native `.node` addons a library-loading equivalent of DLL hijacking. Always validate and sanitize input before using it in process-related or module-loading operations, and use allowlists to restrict what can be spawned or loaded.

Key Security Issues:

- User input directly controls `child_process.spawn()`, `exec()`, or `fork()` parameters
- Unsanitized input used in process arguments, environment variables, or working directories
- Allowing process termination via user-controlled PID values
- Command injection through shell metacharacters in process execution
- `require()` called with a path built from untrusted input, loading an attacker-planted module
- `NODE_OPTIONS`/`--require` environment injection forcing arbitrary code to load at startup
- Untrusted native addons (`.node` files) loaded via `process.dlopen()` or `require()`

## Key Principles

- Use strict allowlists for executable paths and process arguments
- Disable shell interpretation by using `spawn()` with array arguments instead of `exec()`
- Validate all user input against expected formats before process operations
- Never build a `require()` path from user input; map input to a fixed allowlist of known module specifiers instead
- Treat `NODE_OPTIONS`, `--require`, and any environment variable that injects startup code as a trust boundary; strip or reject them in contexts that accept untrusted env vars
- Implement least privilege principles for process execution permissions
- Use safe APIs like `execFile()` that bypass shell interpretation

## Taint Sinks

`child_process.exec()`, `execSync()`, `spawn()` with `shell: true`, `fork()` with untrusted args, `process.kill()`, `require()` with a dynamic/untrusted path, `process.dlopen()`, `NODE_OPTIONS` environment variable, `--require`/`-r` CLI flag with untrusted paths

## Remediation Steps

- Replace `exec()` and `execSync()` with `spawn()` or `execFile()` to avoid shell interpretation
- Create allowlists of permitted executables and validate against them before execution
- Sanitize and validate all user inputs used in process arguments or environment variables
- Use argument arrays instead of concatenating strings for command execution
- For dynamic module loading, resolve user input against a fixed allowlist/map of module specifiers rather than passing input straight to `require()`
- Reject or scrub `NODE_OPTIONS` and other code-injecting environment variables before they reach a spawned Node process, and only load native `.node` addons from trusted, integrity-checked locations
- Implement timeout and resource limits for spawned processes
- Log all process execution and dynamic-loading attempts with security monitoring

## Safe Pattern

```javascript
const { execFile } = require('child_process');
const path = require('path');

// Allowlist of permitted tools
const ALLOWED_TOOLS = { 'imagemagick': '/usr/bin/convert', 'ffmpeg': '/usr/bin/ffmpeg' };

function processFile(toolName, userFile) {
  const executablePath = ALLOWED_TOOLS[toolName];
  if (!executablePath) throw new Error('Invalid tool');
  
  // Example allowlist policy: matches jpg/png filenames that do not start with
  // "-", allowing only letters, digits, "_", and "-" before the extension.
  if (!/^(?!-)[a-zA-Z0-9_-]+\.(jpg|png)$/.test(userFile)) throw new Error('Invalid file');
  
  // Use execFile with argument array - no shell interpretation
  execFile(executablePath, ['-resize', '800x600', '--', userFile], { timeout: 5000 }, (err, stdout) => {
    if (err) console.error('Process failed:', err);
  });
}
```
