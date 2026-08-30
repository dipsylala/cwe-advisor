# Findings for the `docs/` corpus

Suggested changes to `docs/`, and nothing else. `docs/` is gitignored here and maintained
elsewhere, so this file is the hand-off channel rather than a change set applied directly.

1. `docs/CWE-401/csharp/index.md` claims CA2000 and CA1816 "are both in the default .NET
   analyzer set." Microsoft's own code-analysis rule reference states otherwise: CA2000
   ("Dispose objects before losing scope") is listed as not enabled by default, and CA1816
   ("Call GC.SuppressFinalize correctly") is enabled only as a suggestion-level default, not a
   warning. Both need enabling deliberately (and raising to error severity) rather than already
   running - "raising warnings to errors for those two rules" presumes a starting state neither
   rule is actually in.

2. `docs/CWE-242/c/index.md` claims `fgets()` "tells the caller when nothing was read... where
   gets() gave the caller no way to distinguish either from a successful empty read." This is
   backwards: both functions return `NULL` indistinguishably on end-of-file or error, and both
   require a separate `feof()`/`ferror()` call to tell the two apart (confirmed against
   cppreference's `gets()`/`fgets()` pages, which document identical return-value semantics for
   this case). `fgets()`'s real advantage over `gets()` is the bounded write, not failure
   reporting. `cwe/242/c/INDEX.md` in this repo carried the identical error until this sweep pass
   corrected it.

3. `docs/CWE-196/c/index.md` states the mixed signed/unsigned comparison rule as "the usual
   arithmetic conversions convert the unsigned operand to the signed type only where that type
   can represent every value it might hold, and in every other case the signed operand is the
   one that converts." This is backwards for the common case. C11 6.3.1.8's actual rule is
   gated on conversion rank, not representability: when the unsigned operand's rank is greater
   than or equal to the signed operand's rank - the ordinary case, e.g. `int` vs `size_t` - the
   signed operand converts to unsigned regardless of whether it could represent every unsigned
   value. Representability only decides the direction in the less common case where the signed
   operand's rank is strictly greater. `cwe/196/c/INDEX.md` in this repo carried the identical
   error until this sweep pass corrected it to state the rank-gated rule.

4. `docs/CWE-183/java/index.md` states the Primary Defence as "Use fully anchored regex patterns
   with `^` and `$`, call `matches()` instead of `find()`" and every "Why this works" section
   repeats that the `^`/`$` anchors are what force the whole-string comparison - e.g. Strict
   Username Validation: "The anchored regex pattern ... uses `^` (start) and `$` (end) anchors to
   ensure the entire string matches exactly, preventing substring matches." Per Oracle's
   Pattern/Matcher javadoc, `Matcher.matches()`/`String.matches()` already require the entire
   input to match regardless of anchors - the anchors add nothing, `matches()` vs `find()` is the
   whole story. Worse, every "secure" example (`USERNAME_PATTERN`, `EMAIL_PATTERN`,
   `FILENAME_PATTERN`, `ID_PATTERN`) anchors with `$` instead of `\z`, so each stays bypassable by
   a trailing line terminator - `"admin\n"` passes `^[a-z0-9_]{3,20}$` under `matches()`. The file
   does contain one accurate caveat ("`$` matches before a final line terminator by default, so
   `\z` is the strict end") but never applies it to any of its own code samples, so the
   corrected fact and the vulnerable examples sit side by side unreconciled. `cwe/183/java/
   INDEX.md` in this repo already carries the corrected framing (anchors are redundant with
   `matches()`; use `\A`/`\z` only where a pattern must carry its own anchors).

5. `docs/CWE-183/javascript/index.md`'s Node.js path-validation "Why this works" write-up
   (around line 208) claims `path.resolve()` "normalizes [the path]... preventing path
   traversal attacks that use techniques like `"../../etc/passwd"`, symbolic links, or
   OS-specific tricks." `path.resolve()` is documented as pure lexical string manipulation - it
   never touches the filesystem and does not resolve symlinks; only `fs.realpath()` /
   `fs.realpathSync()` does that. A symlink placed inside `BASE_DIR` that points outside it will
   pass this function's `startsWith(BASE_DIR + path.sep)` check untouched, so the "prevents...
   symbolic links" claim is false as written and should be removed or replaced with a note that
   symlink escapes need a separate `fs.realpath()` check.

6. `docs/CWE-15/java/index.md` (around lines 60-62) claims that pointing
   `javax.net.ssl.trustStore` at a nonexistent file "silently falls back to the JDK's cacerts."
   Oracle's JSSE Reference Guide describes the opposite: when the property is explicitly set but
   the referenced file cannot be opened, the default `TrustManager` is backed by an *empty*
   truststore, so every TLS handshake fails closed - it trusts nothing. Falling back to `cacerts`
   only happens when the property is left unset entirely. The practical severity is the reverse
   of what's stated: this is an availability/fail-closed failure, not a fail-open trust bypass.
