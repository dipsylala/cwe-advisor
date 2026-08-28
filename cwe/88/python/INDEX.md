# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - Python

## LLM Guidance

Passing a list to `subprocess` instead of `shell=True` closes command injection but not argument injection: the arguments never reach a shell, yet they still reach the *program*, and a value beginning with `-` is read as an option rather than as data. Findings here look correct at the call site - a list, no shell, no string formatting - and are still exploitable. The fix is to do the work with a native library where one exists, and otherwise to require the value's first character to be alphanumeric before it becomes an argument.

## Key Principles

- Prefer the standard library over a subprocess: `tarfile`, `zipfile`, `shutil`, `pathlib.Path.glob`, `httpx`/`requests` take a typed argument, so there is no option parser left to reinterpret a leading `-`
- Anchor the first character rather than denylisting a prefix: `re.compile(r'\A[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z')` and `match()`, since a denylist of `-`/`--` misses unicode dashes and whitespace-prefixed values
- Use `re.fullmatch()` or an `\A...\Z` pattern - `$` in Python's `re` also matches before a trailing newline, so `^...$` accepts `evil\n`
- Add `--` where the invoked program honours it, as a second layer only: `find` has no end-of-options marker at all, and `--` does nothing for a value in an option's *value* position
- Check where the value lands in the list before calling a finding real: a bare positional (`['find', directory, '-name', '*.log']`) is exploitable, while an option's value slot (`['grep', '-e', pattern]`) or a concatenated prefix (`f'--include={pattern}'`) is one argument that already starts with something safe
- Severity is a property of the invoked program: `tar`, `find`, `curl`, `git`, `ssh`, `rsync` all have options that execute a command or write an arbitrary path; a tool with no such option is a much weaker finding
- Only an option carrying its own value (`--opt=value`, or an attached short option) can be delivered by a single injected element, so check whether the dangerous option needs a companion argument the attacker cannot add
- `shlex.quote()` is for building shell strings and has no role here - applied to a list element it adds literal quote characters and fixes nothing
- Where a path is involved, resolve it under a fixed base and check `is_relative_to()` as well; the pattern check alone does not settle traversal

## Taint Sinks

`subprocess.run()`, `subprocess.Popen()`, `subprocess.check_output()`, `os.execv()`, `os.spawnv()`

## Remediation Steps

- Locate - find `subprocess` calls whose argument list contains a value derived from `request.args`, `request.form`, a path parameter, or an uploaded filename
- Trace data flow - identify the exact list position the value occupies, and whether the invoked program treats that position as a path/pattern (exploitable) or as an option's value (usually not)
- Replace the unsafe pattern - substitute a standard-library equivalent (`tarfile` for `tar`, `Path.glob` for `find`, an HTTP client for `curl`) wherever the library covers the job
- Bind, encode, validate, or authorize - where the tool is genuinely required, validate with an anchored pattern whose first character class excludes `-`, then resolve any path under a fixed base directory
- Break taint after allowlist validation - pass the validated variable (or the resolved `Path`) to `subprocess`, never the raw request value
- Harden configuration - add `timeout=` and `check=True`, run under a least-privilege account, and insert `--` before user-controlled positional arguments where the program supports it
- Test - send the tool's own dangerous option (`--use-compress-program=touch /tmp/pwned`, `-delete`) and assert both that the request is rejected and that the side effect did not happen; verify the payload actually fires against the unfixed code first, or the test proves nothing
