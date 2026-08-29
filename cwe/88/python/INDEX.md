# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - Python

## LLM Guidance

Passing a list to `subprocess` instead of `shell=True` closes command injection but not argument injection: the arguments still reach the *program*, and a value beginning with `-` is read as an option rather than as data. Findings here look correct at the call site - a list, no shell, no string formatting - and are still exploitable. The fix is to do the work with a native library where one exists, and otherwise to require the value's first character to be alphanumeric before it becomes an argument.

## Key Principles

- Prefer the standard library over a subprocess: `tarfile`, `zipfile`, `shutil`, `pathlib.Path.glob`, `httpx`/`requests` take a typed argument, so there is no option parser left to reinterpret a leading `-`
- Two of those replacements carry their own trap. `tarfile.extractall()` defaulted to `fully_trusted` through **3.13** and only defaults to `filter='data'` from **3.14**, so pass `filter='data'` explicitly on anything older - and note the filter itself needed 3.14-era fixes (CVE-2024-12718, CVE-2025-4138, CVE-2025-4330, CVE-2025-4435). `Path.glob` takes a *pattern*, and a user-controlled one escapes the base: `base.glob('../secret.txt')` returns the file outside it
- Anchor the first character rather than denylisting a prefix: `re.compile(r'\A[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z')` and `match()`. The reason is that the allowlist is closed and a denylist is not - you would have to enumerate every option form of every program you might invoke, and the invoked program's parser, not yours, decides what counts
- Use `re.fullmatch()` or an `\A...\Z` pattern - `$` in Python's `re` also matches before a trailing newline, so `^...$` accepts `evil\n`. Python's `\Z` is strict end-of-string (Perl's `\z`); `\z` itself is a `PatternError` before 3.14
- **On Windows a list argument is not a guarantee of no shell.** CPython's own security note: "batch files (`*.bat` or `*.cmd`) may be launched by the operating system in a system shell regardless of the arguments passed to this library... but without any escaping added by Python". CPython declined to treat this as a vulnerability (gh-114539) and fixed only the documentation, so there is no version to upgrade to - if the target may be a batch file, the vendor's advice is to pass `shell=True` so Python escapes, or not to invoke it with untrusted arguments
- Add `--` where the invoked program honours it, as a second layer only. GNU `find` documents that `--` *does not work* for it, and names its own remedies instead: prefix the value with `./`, use an absolute path, or use `-files0-from`. Note `./` starts with `.`, which the first-character allowlist above rejects - so prepend it after validating, not before
- Check where the value lands in the list before calling a finding real: a bare positional (`['find', directory, '-name', '*.log']`) is exploitable, while an option's value slot (`['grep', '-e', pattern]`) or a concatenated prefix (`f'--include={pattern}'`) is one argument that already starts with something safe
- A single injected element is enough when the option carries its own value (`--opt=value`, or an attached short option) *or* when it takes no value at all - `find -delete` is the second kind. Where the dangerous option needs a companion argument the attacker cannot add, the finding is weaker
- `shlex.quote()` is for building shell strings and has no role here. Note what it actually does with these payloads: it returns `-delete` and `-oProxyCommand=x` **unchanged**, because a leading `-` is in its safe-character set - so it neither blocks nor visibly alters the attack
- Where a path is involved, resolve it under a fixed base and check `is_relative_to()` (3.9+) as well; that method is string-based and does not treat `..` specially, so it has to follow `resolve()`, not replace it

## Taint Sinks

`subprocess.run()`, `subprocess.Popen()`, `subprocess.check_output()`, `os.execv()`, `os.spawnv()`

## Remediation Steps

- Locate - find `subprocess` calls whose argument list contains a value derived from `request.args`, `request.form`, a path parameter, or an uploaded filename
- Trace data flow - identify the exact list position the value occupies, and whether the invoked program treats that position as a path/pattern (exploitable) or as an option's value (usually not)
- Replace the unsafe pattern - substitute a standard-library equivalent (`tarfile` for `tar`, `Path.glob` for `find`, an HTTP client for `curl`) wherever the library covers the job, applying the two caveats above
- Bind, encode, validate, or authorize - where the tool is genuinely required, validate with an anchored pattern whose first character class excludes `-`, then resolve any path under a fixed base directory
- Break taint after allowlist validation - pass the validated variable (or the resolved `Path`) to `subprocess`, never the raw request value
- Harden configuration - use `subprocess.run()` with `timeout=` and `check=True` (neither is a `Popen` parameter, and `check_output` raises `ValueError` if given `check`), run under a least-privilege account, and insert `--` before user-controlled positional arguments where the program supports it
- Test - send the tool's own dangerous option (`--use-compress-program=touch /tmp/pwned`, `-delete`) and assert both that the request is rejected and that the side effect did not happen; verify the payload actually fires against the unfixed code first, or the test proves nothing
