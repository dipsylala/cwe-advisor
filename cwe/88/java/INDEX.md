# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - Java

## LLM Guidance

`ProcessBuilder` and `Runtime.exec(String[])` hand arguments to the program as an argument vector rather than a command line, which stops command injection and leaves argument injection untouched: the program still parses its own `argv`, so a user-supplied value beginning with `-` is read as an option. The common shape is a service shelling out to `curl`, `git`, `ffmpeg` or `pdftk` for something the JDK or a library already does - and for most of those the fix is to delete the subprocess rather than sanitise its arguments.

## Key Principles

- Prefer a JDK or library equivalent: `java.net.http.HttpClient` (Java 11+) instead of `curl`, `java.util.zip` or the `jdk.zipfs` provider instead of `unzip` - a `URI` or `Path` object is a typed argument, not a token an option parser can reinterpret. Note the JDK reads no tar at all, so replacing a `tar` call means a library such as Apache Commons Compress, not `java.util.zip`
- Anchor the first character rather than denylisting a prefix: `Pattern.compile("\\A[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\\z")` with `matches()`. The reason is that the allowlist is closed and a denylist is not - it would have to enumerate every option form of every program you might invoke, and the invoked program's parser decides what counts, not yours. (`matches()` already requires the whole region, so the anchors matter mainly if the code is later changed to `find()`, where `$` would also match before a trailing line terminator)
- Add `--` where the invoked program honours it, as a second layer only - support is thinner than it looks. `curl` documents it; for `git` it depends on position - `--` closes a value used as a path, while one in revision position needs `--end-of-options` (2.24+); `tar`'s manual documents no terminator; and GNU `find` documents that `--` *does not work* for it, naming instead a `./` prefix, an absolute path, or `-files0-from`
- Validate a URL by parsing it: check `getScheme()` and `getHost()` on the resulting `URI`, not on the raw string. Use `new URI(String)` rather than `URI.create()` here - the javadoc reserves `create()` for strings known to be legal and says the constructors "should be used in situations where a URI is being constructed from user input" - and call `parseServerAuthority()`, which is what makes a malformed authority fail rather than be accepted as registry-based. `new URL(String)` is `@Deprecated(since="20")`, a soft deprecation without `forRemoval`, so it will not stop compiling; the reason to move is that `URL.equals`/`hashCode` perform name resolution, making comparison a blocking operation that can equate different hostnames
- Distinguish the two weaknesses when triaging: `Runtime.exec(String)` tokenizes with a `StringTokenizer` on whitespace and is CWE-78 (also `@Deprecated(since="18")`); `ProcessBuilder` with a list is not, and is still this weakness. "Is a shell involved" is the wrong question here
- **On Windows the no-shell property has an exception.** Invoking `.bat`/`.cmd`, or any command not ending in `.exe`, can reach the interpreter's own parsing; the JDK's opt-in restriction on that is the system property `jdk.lang.Process.allowAmbiguousCommands` set to `false`, which tightens quoting for arguments containing `"`, `&`, `|`, `<`, `>` or `^`. It is documented in the release notes rather than the javadoc, and it is off by default
- Severity follows the invoked program's option set, and the mechanisms differ - `git --upload-pack=` and `tar --use-compress-program=` cause execution, while `curl -K` executes nothing itself and instead reads an entire further argument set from the named file; a tool with no such option is a much weaker finding
- Where the argument is a path, confine it with `toRealPath()` and `startsWith(base)`: `normalize()` is lexical, so a symlink inside the base directory passes it while `Files.isRegularFile` follows the link to the real target

## Taint Sinks

`new ProcessBuilder(...)`, `Runtime.exec(String[])`, `ProcessBuilder.command()`

## Remediation Steps

- Locate - find `ProcessBuilder`/`Runtime.exec` calls whose argument list contains a value from `@RequestParam`, `@PathVariable`, a request body, or an uploaded filename
- Trace data flow - identify which list element the value becomes, and whether the program treats that position as a bare positional (exploitable) or as an option's value (usually not)
- Replace the unsafe pattern - substitute the JDK equivalent where one exists; this removes the weakness rather than constraining it
- Bind, encode, validate, or authorize - where the tool is genuinely required, validate with an anchored pattern whose first character class excludes `-`, and resolve any path with `toRealPath()` under a resolved base directory
- Break taint after allowlist validation - pass the validated variable or the resolved `Path` into the argument list, never the raw parameter
- Harden configuration - bound the process with `waitFor(timeout, unit)` and `destroyForcibly().waitFor()` (both Java 8+), and redirect output to a file rather than leaving the default pipe unread, since the javadoc warns that on platforms with limited pipe buffers "failure to promptly write the input stream or read the output stream of the process may cause the process to block, or even deadlock"
- Test - plant the tool's own dangerous option as a single argv element (`-K/tmp/attacker.conf`, not `-K /tmp/...`, where the space becomes part of the filename) and assert both rejection and absence of the side effect; confirm the payload fires against the unfixed code first - a `git --upload-pack=` test needs `--no-local` or a non-local URL, since a plain local-path clone bypasses the transport - and check that legitimate values with internal hyphens still work
