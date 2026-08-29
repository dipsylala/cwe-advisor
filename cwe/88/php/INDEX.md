# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - PHP

## LLM Guidance

PHP's two escaping helpers address the shell, not the program: `escapeshellcmd()` neutralises shell metacharacters in a command string, and `escapeshellarg()` wraps a value so the shell treats it as one token. Neither stops the invoked program reading a quoted, metacharacter-free `-o/var/www/html/shell.php` as an option - and `escapeshellarg()` in particular delivers exactly what the attack needs: one argument, beginning with `-`, intact. The baseline fix is `proc_open()` with an argument array (PHP 7.4+), which removes the shell, plus a first-character allowlist on any value that becomes an argument.

## Key Principles

- Prefer a PHP extension over a subprocess: the cURL extension or an HTTP client instead of the `curl` binary, GD or Imagick instead of a converter, `ZipArchive` instead of `zip` - and `PharData` rather than `ZipArchive` where the archive is a **tar**, since `ZipArchive` does not read tar at all
- Use `proc_open()` with an array so `argv` goes to the process directly; the manual states it "will be opened directly (without going through a shell)". **On Windows that guarantee has a version floor**: CVE-2024-1874 was command injection through the array form despite it, and CVE-2024-5585 bypassed the first fix by appending a trailing space, so the operative floor is **8.1.29 / 8.2.20 / 8.3.8**. The manual also assumes the target parses its command line the way the VC runtime does, which `.bat`/`.cmd` targets do not
- Anchor the first character: `preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\z/', $name)`. The reason is that the allowlist is closed and a denylist is not - it would have to enumerate every option form of every program you might invoke, and the invoked program's parser decides what counts, not yours
- Use `\A...\z` rather than `^...$` - PCRE's `$` also matches before a trailing newline, so `^[A-Za-z0-9.-]+$` accepts `evil.com` followed by a newline. The `D` modifier does the same job if the pattern must keep `$`
- Swapping `escapeshellcmd()` for `escapeshellarg()` does not close a finding here. The manual does recommend that swap, but for a different weakness - its stated reason is that `escapeshellcmd()` "still allows the attacker to pass arbitrary number of arguments", which is argument *count*, not an argument being read as an option
- `escapeshellarg()` is not a validator anywhere. On Windows it quotes with `"` rather than `'`, and it replaces percent signs and exclamation marks **with spaces**, so it silently corrupts legitimate values as well as failing to stop this attack. It also discards characters unrecognised in the current `LC_CTYPE` locale
- Add `--` before user-controlled positional arguments where the program honours it, as a second layer. GNU `find` documents that `--` *does not work* for it, and names its own remedies instead: prefix the value with `./`, use an absolute path, or use `-files0-from`
- Severity follows the invoked binary's option set, and the mechanisms differ: `tar --use-compress-program=` splits the value itself and execs the first word; `git --upload-pack=` is documented as the command run on the remote end; `curl -K` executes nothing itself, it reads a further argument set from the named file. A tool whose reachable options are inert is a defensible false positive worth recording with its reason - `ffmpeg` is the worked example, since it has no `--opt=value` form at all, so a single injected element cannot carry its own value

## Taint Sinks

`exec()`, `system()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()` with a command string, backtick operator

## Remediation Steps

- Locate - find command execution whose arguments include `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES` filenames, or database values
- Trace data flow - identify whether the value becomes a bare positional argument (exploitable) or an option's value, and whether the command is a string (word-split by the shell) or an array
- Replace the unsafe pattern - use a PHP extension where one covers the job; otherwise convert the command string to a `proc_open()` argument array
- Bind, encode, validate, or authorize - validate with an anchored pattern whose first character class excludes `-`, and resolve any path with `realpath()` under a fixed base directory
- Break taint after allowlist validation - pass the validated variable or the `realpath()` result into the array, never the raw superglobal
- Harden configuration - give stdout and stderr `tmpfile()` handles rather than pipes (an undrained pipe fills, the child blocks in `write()`, and the read never returns), close the stdin pipe so the child sees EOF, and poll `proc_get_status()` against a deadline with `proc_terminate()` since `proc_open()` has no timeout and `proc_close()` waits for the process. Before PHP 8.3 only the first `proc_get_status()` call returned the real exit code, so a poll loop written against an older version must not read it twice
- Test - send the tool's dangerous option (`--use-compress-program=/tmp/evil.sh`) and assert both rejection and absence of the side effect. Pick a payload that fires: `--checkpoint-action=exec=...`, the one usually reached for, is inert without a companion `--checkpoint=N` and so passes whether the fix works or not. Note also that the payload shape differs by call form - without quoting the shell word-splits a spaced payload into two inert arguments, while `escapeshellarg()` keeps it as one argument and makes the spaced form the one that works
