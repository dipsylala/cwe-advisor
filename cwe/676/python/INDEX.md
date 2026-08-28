# CWE-676: Use of Potentially Dangerous Function - Python

## LLM Guidance

Python's dangerous functions are dangerous because of what they are designed to do: `eval()`/`exec()` run arbitrary source, `pickle.load()`/`pickle.loads()` deserialize into arbitrary object construction and method calls, and `os.system()` or `subprocess` with `shell=True` hand a string to a shell. None are deprecated; each has a narrow, safe replacement for nearly every legitimate use. The primary remediation is swapping the dangerous call for a parser, a safe deserializer, or an argument-list `subprocess` call.

## Key Principles

- Replace `eval()`/`exec()` on untrusted input with `ast.literal_eval()` for literal values or `json.loads()` for structured data
- Never call `pickle.load()`, `pickle.loads()`, `yaml.load()` (without `SafeLoader`), or `marshal.loads()` on untrusted or externally-sourced data; use `json` for untrusted data interchange
- Replace `os.system()` and `subprocess` calls using `shell=True` with `subprocess.run()`/`subprocess.Popen()` passing a list of arguments and `shell=False`
- Never build a shell command string via f-string or concatenation from request data, filenames, or CLI input
- If a dangerous function is unavoidable (e.g. a plugin system genuinely needs `exec`), isolate it and restrict its `globals`/`locals` to a minimal allowlist, and treat this as a design smell, not a fix
- Enforce the ban with `bandit` (rules B102, B307, B301/B403, B605/B607) in CI

## Taint Sinks

`eval()`, `exec()`, `pickle.load()`/`pickle.loads()`, `os.system()`, `subprocess`/`os.popen` with `shell=True`

## Remediation Steps

- Locate - Search for `eval(`, `exec(`, `os.system(`, `pickle.load(`, `pickle.loads(`, `yaml.load(`, and `subprocess`/`os.popen` calls with `shell=True`
- Trace data flow - Determine whether request data, file content, or CLI arguments reach the dangerous call, directly or via a variable
- Replace the unsafe pattern - Convert code evaluation to `ast.literal_eval()`/`json.loads()`, convert untrusted deserialization to `json`, convert shell execution to `subprocess.run([...], shell=False)`
- Bind, encode, validate, or authorize - Pass command arguments as separate list elements, never interpolated into one string
- Break taint after allowlist validation - Where a value like a filename must be constrained, validate it against an allowlist or pattern first and use only the validated value in the `subprocess` call
- Harden configuration - Avoid `shell=True` even for trusted-looking input; keep the ban enforced by linting rather than relying on manual review
- Test - Run payloads such as `__import__('os').system('id')` against replaced `eval`/`exec` calls and shell metacharacters (`; | & $() \``) against replaced subprocess calls, confirming both are rejected or treated as literal data
