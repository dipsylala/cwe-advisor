# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - JavaScript

## LLM Guidance

`child_process.spawn` and `execFile` take arguments as an array and, with the default `shell: false`, normally involve no shell - which closes command injection and leaves argument injection untouched. The array elements are the program's `argv`, so an element beginning with `-` is an option. The usual Node advice ("use `spawn`, not `exec`") is about the shell, so a `spawn` call with an array reads as already safe and is not.

## Key Principles

- `shell: false` answers a different question - it is the CWE-78 fix and is already the default for `spawn`/`execFile`; a finding here is not resolved by pointing at it
- **On Windows that default has been defeated twice, so check the Node version.** CVE-2024-27980 was command injection through the `args` array of `spawn`/`spawnSync` against a `.bat`/`.cmd` target "even if the shell option is not enabled"; CVE-2024-36138 is the documented bypass of that fix. The operative floor is **18.20.4 / 20.15.1 / 22.4.1**, and at or above it Node raises `EINVAL` for a batch target without `shell`. Do not reach for `--security-revert`. Relatedly, passing an args array *with* `shell: true` is runtime-deprecated from v24 (DEP0190) because the values are only space-separated, not escaped
- Prefer the platform API where one exists: a global `fetch` has been available without a flag since Node 18, so shelling out to `curl` removes the argument vector entirely. Its stability index stayed Experimental in the 18 and 20 docs and became Stable in 21, and that was not backported - so on an LTS line it works but is documented as experimental
- Validate a URL by parsing it - construct a `URL`, then check `url.protocol` and `url.hostname` against a `Set`; a substring check accepts `https://github.com.attacker.example/a/b` and a parsed check does not. Note `protocol` includes the trailing colon, so the set membership value is `'https:'`, not `'https'`
- Anchor the first character of any free-form value (`/^[A-Za-z0-9][\w.-]*$/`) rather than denylisting `-`. The reason is that the allowlist is closed and a denylist is not: it would have to enumerate every option form of every program you might invoke, and the invoked program's parser decides what counts, not yours
- Pass user-controlled positional arguments after `--` where the program honours it, as a second layer. GNU `find` documents that `--` *does not work* for it, and gives its own remedies instead: prefix the value with `./`, use an absolute path, or use `-files0-from`
- Trace where the value lands before judging the finding: a bare positional slot is the exploitable case, an option's value slot (`['--name', value]`) is much weaker, and only an option carrying its own value (`--opt=value`, or an attached short option such as `-K/path`) or one taking no value at all can be delivered by a single element
- Severity follows the target binary, and the mechanisms differ: `git --upload-pack=` and `tar --use-compress-program=` cause execution, while `curl -K` executes nothing itself - it reads further arguments from the named file, and the damage is whatever those options then do. A tool whose reachable options are inert is a defensible false positive worth recording with its reason - `ffmpeg` is the worked example, since it has no `--opt=value` form at all, so a single injected element arrives as one unrecognised option and every dangerous option there needs a second element the attacker does not control

## Taint Sinks

`child_process.spawn()`, `child_process.execFile()`, `child_process.spawnSync()`, `child_process.execFileSync()`, `child_process.fork()`

## Remediation Steps

- Locate - find `spawn`/`execFile` calls whose argument array contains a value from `req.body`, `req.query`, `req.params`, or an uploaded filename
- Trace data flow - identify which array element the value becomes and whether the program treats that position as a path, repository, or pattern
- Replace the unsafe pattern - use `fetch` (with `redirect: 'error'`), `fs`/`fs.promises`, or a library instead of invoking a CLI where one covers the job
- Bind, encode, validate, or authorize - parse and allowlist structured values (`URL` + host `Set`), and anchor free-form values with a first-character class that excludes `-`
- Break taint after allowlist validation - pass `url.href` or the validated variable into the array, never the raw request field
- Harden configuration - set `timeout`, keep `shell: false`, check the Node version against the floor above where the target may be a batch file on Windows, and pass a minimal `env` (for example `GIT_TERMINAL_PROMPT: '0'` so a private repository does not block the handler on a credential prompt)
- Test - send the tool's dangerous option as one array element (`--upload-pack=touch /tmp/pwned`, `--use-compress-program=touch /tmp/pwned`) and assert both rejection and absence of the side effect; verify it fires against the unfixed handler first - `git` ignores `--upload-pack` over an `https://` remote and bypasses the transport entirely for a plain local path, so the test needs `--no-local` or an `ssh://` remote - and check that legitimate hyphenated names and `.git` suffixes still work
