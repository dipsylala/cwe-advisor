# CWE-77: Command Injection - PHP

## LLM Guidance

Command injection in PHP occurs when applications construct system commands using untrusted input through functions like `system()`, `exec()`, `shell_exec()`, or backticks.

**Primary Defence:** Use PHP native functions (file_get_contents, unlink, copy, etc.) instead of executing system commands to eliminate the vulnerability entirely. If process execution is absolutely unavoidable, use argument arrays with strict allowlists and avoid the shell.

## Key Principles

- **BEST:** Use PHP native functions (file_get_contents, unlink, copy, curl_exec) instead of system commands to eliminate command injection risk
- **If commands unavoidable:** Use argument arrays through `proc_open()` or a process library, validate operands, and pass `--` before user-controlled operands where the executable supports it
- Implement strict allowlist validation for any parameters that determine command behavior as defence-in-depth
- Never use dynamic command construction through string concatenation or interpolation
- Enforce least privilege by running PHP processes with minimal system permissions
- Avoid shell execution functions (`system()`, `exec()`, `shell_exec()`, backticks, `passthru()`) entirely

## Remediation Steps

- Audit code for all instances of `system()`, `exec()`, `shell_exec()`, backticks, `passthru()`, `proc_open()`, and `popen()`
- **Replace shell commands with PHP native functions** (file_get_contents, unlink, copy) to eliminate vulnerability
- If process execution is unavoidable, use argument arrays, avoid shell parsing, validate operands, and add `--` before user-controlled operands where supported
- Implement allowlist validation for any parameters that determine command behavior as additional defence
- Remove or restrict user control over command structure, file paths, and executable names
- Configure PHP with `disable_functions` in php.ini to block dangerous functions in production

## Safe Pattern

```php
// UNSAFE: Direct user input in command
$file = $_GET['file'];
$output = shell_exec("cat $file");

// SAFE: Use PHP built-in instead
$file = $_GET['file'];
$allowedFiles = ['report.txt', 'data.csv'];
if (in_array($file, $allowedFiles, true)) {
    $output = file_get_contents($file);
}

// SAFE: If process execution is unavoidable, validate and avoid shell parsing
$file = $_GET['file'];
if (!in_array($file, $allowedFiles, true)) {
    throw new InvalidArgumentException('Invalid file');
}
$process = proc_open(
    ['grep', 'search_term', '--', $file],
    [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']],
    $pipes
);
```
