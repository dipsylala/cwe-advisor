# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - Java

## LLM Guidance

`ProcessBuilder` and `Runtime.exec(String[])` hand arguments to the program without a shell, which stops command injection and leaves argument injection untouched: the program still parses its own argument vector, so a user-supplied value beginning with `-` is read as an option. The common shape is a service shelling out to `curl`, `git`, `ffmpeg` or `pdftk` for something the JDK or a library already does - and for most of those the fix is to delete the subprocess rather than sanitise its arguments.

## Key Principles

- Prefer a JDK or library equivalent: `java.net.http.HttpClient` instead of `curl`, the ZIP filesystem provider or `java.util.zip` instead of `tar`/`unzip`, an image library instead of a converter - a `URI` or `Path` object is a typed argument, not a token an option parser can reinterpret
- Anchor the first character rather than denylisting a prefix: `Pattern.compile("\\A[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\\z")` with `matches()`, since a denylist of `-`/`--` misses unicode dashes and leading whitespace
- A character-class allowlist that permits `-` anywhere permits it first, and `-o` matches most "URL-shaped" regexes; constrain the leading character explicitly
- Add `--` where the invoked program honours it (`curl`, `git`, `tar`), as a second layer only - `find` has no end-of-options marker and reads a leading `-` as a predicate regardless
- Validate a URL by parsing it: check `scheme` and `host` on the resulting `URI`, not on the raw string, and prefer `URI.create()` over `new URL(String)` (deprecated for removal since Java 20, and `URL.equals` performs DNS resolution)
- Distinguish the two weaknesses when triaging: `Runtime.exec(String)` splits on whitespace and is CWE-78; `ProcessBuilder` with a list is not, and is still this weakness. "Is a shell involved" is the wrong question here
- Severity follows the invoked program's option set - `curl -K` reads an entire config file, `git --upload-pack=` executes a program; a tool with no such option is a much weaker finding
- Where the argument is a path, confine it with `toRealPath()` and `startsWith(base)`: `normalize()` is lexical, so a symlink inside the base directory passes it while `Files.isRegularFile` follows the link to the real target

## Taint Sinks

`new ProcessBuilder(...)`, `Runtime.exec(String[])`, `ProcessBuilder.command()`

## Remediation Steps

- Locate - find `ProcessBuilder`/`Runtime.exec` calls whose argument list contains a value from `@RequestParam`, `@PathVariable`, a request body, or an uploaded filename
- Trace data flow - identify which list element the value becomes, and whether the program treats that position as a bare positional (exploitable) or as an option's value (usually not)
- Replace the unsafe pattern - substitute the JDK equivalent where one exists; this removes the weakness rather than constraining it
- Bind, encode, validate, or authorize - where the tool is genuinely required, validate with an anchored pattern whose first character class excludes `-`, and resolve any path with `toRealPath()` under a resolved base directory
- Break taint after allowlist validation - pass the validated variable or the resolved `Path` into the argument list, never the raw parameter
- Harden configuration - bound the process with `waitFor(timeout, unit)` and `destroyForcibly().waitFor()`, and redirect output to a file rather than leaving the default pipe unread, since a full pipe blocks the child and turns a healthy run into a timeout
- Test - plant the tool's own dangerous option as a single argv element (`-K/tmp/attacker.conf`, not `-K /tmp/...`, which becomes part of the filename) and assert both rejection and absence of the side effect; confirm the payload fires against the unfixed code first, and check that legitimate values with internal hyphens still work
