# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - JavaScript

## LLM Guidance

`child_process.spawn` and `execFile` take arguments as an array and, with the default `shell: false`, never involve a shell - which closes command injection and leaves argument injection untouched. The array elements are the program's `argv`, so an element beginning with `-` is an option. The usual Node advice ("use `spawn`, not `exec`") is about the shell, so a `spawn` call with an array reads as already safe and is not.

## Key Principles

- `shell: false` answers a different question - it is the CWE-78 fix and is already the default for `spawn`/`execFile`; a finding here is not resolved by pointing at it
- Prefer the platform API where one exists: Node has had a global `fetch` since 18, so shelling out to `curl` removes the argument vector entirely and with it the weakness
- Validate a URL by parsing it - construct a `URL`, then check `url.protocol` and `url.hostname` against a `Set`; a substring check accepts `https://github.com.attacker.example/a/b` and a parsed check does not
- Anchor the first character of any free-form value (`/^[A-Za-z0-9][\w.-]*$/`) rather than denylisting `-`, which misses `--`, unicode dashes, and leading whitespace
- Pass user-controlled positional arguments after `--` where the program honours it, as a second layer - `find` has no end-of-options marker at all
- `shell-quote` and similar escaping libraries are the wrong tool here: they build shell strings, and the safe code has no shell, so escaping an array element only inserts literal characters into the value
- Trace where the value lands before judging the finding: a bare positional slot is the exploitable case, an option's value slot (`['--name', value]`) is much weaker, and only an option carrying its own value (`--opt=value`, or an attached short option such as `-K/path`) can be delivered by a single element
- Severity follows the target binary: `git --upload-pack=`, `tar --use-compress-program=`, and `curl -K` all execute or write; a tool whose reachable options are inert is a defensible false positive worth recording with its reason

## Taint Sinks

`child_process.spawn()`, `child_process.execFile()`, `child_process.spawnSync()`, `child_process.execFileSync()`

## Remediation Steps

- Locate - find `spawn`/`execFile` calls whose argument array contains a value from `req.body`, `req.query`, `req.params`, or an uploaded filename
- Trace data flow - identify which array element the value becomes and whether the program treats that position as a path, repository, or pattern
- Replace the unsafe pattern - use `fetch` (with `redirect: 'error'`), `fs`/`fs.promises`, or a library instead of invoking a CLI where one covers the job
- Bind, encode, validate, or authorize - parse and allowlist structured values (`URL` + host `Set`), and anchor free-form values with a first-character class that excludes `-`
- Break taint after allowlist validation - pass `url.href` or the validated variable into the array, never the raw request field
- Harden configuration - set `timeout`, keep `shell: false`, and pass a minimal `env` (for example `GIT_TERMINAL_PROMPT: '0'` so a private repository does not block the handler on a credential prompt)
- Test - send the tool's dangerous option as one array element (`--upload-pack=touch /tmp/pwned`, `--use-compress-program=touch /tmp/pwned`) and assert both rejection and absence of the side effect; verify it fires against the unfixed handler first, and check that legitimate hyphenated names and `.git` suffixes still work
