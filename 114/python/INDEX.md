# CWE-114: Process Control - Python

## LLM Guidance

Process control vulnerabilities occur when untrusted input influences process creation, termination, or management operations, or when it influences which library or module gets loaded. Attackers can spawn malicious processes, kill critical services, exhaust system resources, or trick the interpreter into loading an attacker-supplied `.so`/`.dll`/module instead of the intended one. Always validate process identifiers and library/module names, use allowlists, and avoid passing user input directly to process control or dynamic-loading functions.

## Key Principles

- Validate all process identifiers (PIDs) against an allowlist of expected/authorized processes
- Never pass unsanitized user input to subprocess calls, signal operations, or process management functions
- Never pass user-controlled names to `ctypes.CDLL()`/`LoadLibrary()` or `importlib.import_module()`; resolve against an allowlist of fully-qualified, known-safe names first
- Use least-privilege principles: restrict process control operations to specific authorized users/roles
- Implement resource limits and monitoring to detect abnormal process spawning or termination patterns
- Prefer built-in APIs over shell execution; avoid shell=True in subprocess calls

## Taint Sinks

`subprocess.run()`/`Popen()` with `shell=True`, `os.system()`, `os.kill()`, `os.exec*()` family, `ctypes.CDLL()`, `ctypes.cdll.LoadLibrary()`, `ctypes.WinDLL()`, `importlib.import_module()`, `__import__()`, `sys.path.insert()`/`sys.path.append()` with untrusted paths, `LD_PRELOAD`/`LD_LIBRARY_PATH` environment variables

## Remediation Steps

- Identify all code paths where user input affects process control (subprocess, os.kill, signal operations) or dynamic library/module loading (ctypes, importlib, sys.path)
- Implement strict allowlists mapping user inputs to predefined safe process operations
- Replace dynamic process calls with parameterized safe alternatives using validated inputs
- For library/module loading, map user input to a fixed allowlist of absolute library paths or fully-qualified module names rather than building the path/name from input
- Never let request data, environment variables, or config files reachable by untrusted users set `sys.path` entries or `LD_PRELOAD`/`LD_LIBRARY_PATH`
- Add authorization checks before any process control operation
- Set resource limits using setrlimit() to prevent process exhaustion attacks
- Log and monitor all process control and dynamic-loading operations for security auditing

## Safe Pattern

```python
import subprocess

ALLOWED_COMMANDS = {
    'backup': ['/usr/bin/backup.sh', '--safe'],
    'report': ['/usr/bin/generate_report.py']
}

def execute_task(task_name):
    if task_name not in ALLOWED_COMMANDS:
        raise ValueError("Unauthorized task")
    
    result = subprocess.run(
        ALLOWED_COMMANDS[task_name],
        capture_output=True,
        timeout=30,
        shell=False
    )
    return result.stdout
```
