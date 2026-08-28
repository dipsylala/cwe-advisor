# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - PHP

## LLM Guidance

PHP's two escaping helpers address the shell, not the program: `escapeshellcmd()` neutralises shell metacharacters in a command string, and `escapeshellarg()` wraps a value so the shell treats it as one token. Neither stops the invoked program reading a quoted, metacharacter-free `-o/var/www/html/shell.php` as an option - and `escapeshellarg()` in particular delivers exactly what the attack needs: one argument, beginning with `-`, intact. The baseline fix is `proc_open()` with an argument array (PHP 7.4+), which removes the shell, plus a first-character allowlist on any value that becomes an argument.

## Key Principles

- Prefer a PHP extension over a subprocess: `ZipArchive` instead of `tar`/`zip`, the cURL extension or an HTTP client instead of the `curl` binary, GD or Imagick instead of a converter - a typed path argument has no option parser behind it
- Use `proc_open()` with an array so `argv` goes to the process directly; with no shell involved, no escaping function is needed or useful
- Anchor the first character: `preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\z/', $name)`, since "must not start with a dash" misses `--`, unicode dashes, and a space-prefixed value
- Use `\A...\z` rather than `^...$` - PCRE's `$` also matches before a trailing newline, so `^[A-Za-z0-9.-]+$` accepts `evil.com` followed by a newline
- Swapping `escapeshellcmd()` for `escapeshellarg()` does not close a finding here; and `escapeshellarg()` is locale- and platform-dependent besides (it strips bytes invalid in the current locale and quotes with `"` on Windows), so it is not a validator even where a shell string is unavoidable
- Add `--` before user-controlled positional arguments where the program honours it, as a second layer
- Confine any path with `realpath()` plus a separator-terminated prefix check - the name pattern alone does not settle traversal
- Severity follows the invoked binary's option set (`tar --use-compress-program=`, `curl -K`, `git --upload-pack=`); a tool whose reachable options are inert is a defensible false positive worth recording with its reason

## Taint Sinks

`exec()`, `system()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()` with a command string, backtick operator

## Remediation Steps

- Locate - find command execution whose arguments include `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES` filenames, or database values
- Trace data flow - identify whether the value becomes a bare positional argument (exploitable) or an option's value, and whether the command is a string (word-split by the shell) or an array
- Replace the unsafe pattern - use a PHP extension where one covers the job; otherwise convert the command string to a `proc_open()` argument array
- Bind, encode, validate, or authorize - validate with an anchored pattern whose first character class excludes `-`, and resolve any path with `realpath()` under a fixed base directory
- Break taint after allowlist validation - pass the validated variable or the `realpath()` result into the array, never the raw superglobal
- Harden configuration - give stdout and stderr `tmpfile()` handles rather than pipes (an undrained pipe fills, the child blocks in `write()`, and the read never returns), close the stdin pipe so the child sees EOF, and poll `proc_get_status()` against a deadline with `proc_terminate()` since `proc_open()` has no timeout and `proc_close()` blocks
- Test - send the tool's dangerous option (`--use-compress-program=/tmp/evil.sh`) and assert both rejection and absence of the side effect; note the payload shape differs by call form - without quoting the shell word-splits a spaced payload into two inert arguments, while `escapeshellarg()` makes the spaced form the one that works
