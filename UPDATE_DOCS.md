# Errors found in `docs/`

Findings from checking `docs/` against current upstream sources, written up for review in the
repository `docs/` came from. Paths and line numbers are as of the copy present in `cwe-advisor`
at the time of writing.

## Scope and method

This is **not** a full audit of all 492 files. It covers three things:

1. Every CVE reference and version assertion found by grepping `docs/`, checked against vendor
   advisories where one exists.
2. The specific claims the `cwe-advisor` knowledge base was corrected on during its top-15 review
   pass, checked in both directions - what `docs/` got wrong, and what it got right that the
   knowledge base did not.
3. A mechanical link check over every relative link in `docs/`.
4. A later sweep of every version assertion in the `cwe-advisor` knowledge base, with each claim
   `docs/` also makes checked against the same source.

Prose accuracy across the roughly 480 files not touched by those passes was not reviewed.

Each finding below was checked by reading the enclosing section, not by grepping for a token and
judging from the lines around it. One earlier finding was withdrawn for exactly that mistake: a
search for `mysql_real_escape_string` matched four lines, while the two sentences stating the
function's removal used the wording "mysql_* functions" and "These functions" and so matched
nothing. Treat any residual finding here as worth confirming in context before acting on it.

## Confirmed errors

### 1. PHP `proc_open` CVE fix versions are wrong, and the follow-up CVE is missing

`docs/CWE-78/php/index.md:438` and `docs/CWE-78/php/index.md:468`

Both give the CVE-2024-1874 fixed versions as **8.1.27, 8.2.16 and 8.3.3**. None of those is
right. The advisory range is 8.1.\* before 8.1.28, 8.2.\* before 8.2.18, 8.3.\* before 8.3.5.

The 8.3 branch number is itself reported inconsistently upstream: the CVE record says "before
8.3.5", Zend lists 8.3.0-8.3.5 as affected (implying 8.3.6), and the oss-sec announcement is
titled "PHP security releases 8.1.28, 8.2.18, & 8.3.6".

More seriously, the fix was bypassed. **CVE-2024-5585** defeats it using a trailing space in the
filename and is patched in **8.1.29, 8.2.20 and 8.3.8** (php-src advisory `GHSA-9fcc-425m-g385`).
`docs/` does not mention it anywhere.

**Impact:** a dependency check written from this page passes a runtime that is still exploitable -
both because the stated floor is below the real one and because the real floor is the 5585 fix,
not the 1874 fix.

**Suggested wording:** anchor on 8.1.29 / 8.2.20 / 8.3.8 and note that the earlier fix is
bypassable, which makes the disputed 8.3.5-vs-8.3.6 question moot.

### 2. `gorilla/csrf` is recommended without its unpatched advisory

`docs/CWE-352/go/index.md` (code examples around :543 and :566) and `docs/CWE-352/index.md`, plus
the reference link at `docs/CWE-352/go/index.md:681`

The page recommends and demonstrates `github.com/gorilla/csrf` with no version guidance and no CVE
mention. Two advisories apply:

- **CVE-2025-24358** - Referer bypass, fixed in v1.7.3 by additionally enforcing same-origin.
- **CVE-2025-47909** - introduced *by* that fix. A host passed to `TrustedOrigins` is accepted over
  both its HTTPS and HTTP origins, because the comparison ignores the scheme.

Go vulnerability report `GO-2025-3884` records CVE-2025-47909 as **"all versions, no known fixed"**
and recommends migrating to `net/http.CrossOriginProtection` (Go 1.25+), or to the backport
`filippo.io/csrf` / the drop-in `filippo.io/csrf/gorilla`.

**Impact:** this is the most actionable item here - the page's primary recommendation is a package
with a currently unpatched CSRF bypass, and no version pin avoids it.

### 3. `_FORTIFY_SOURCE=2` is stale

`docs/CWE-125/c/index.md:160`, `docs/CWE-787/c/index.md:143`, and the equivalent lines in
`docs/CWE-121/c/index.md` and `docs/CWE-134/c/index.md`

Level 3 has existed since GCC 12 and Clang 15 and adds checks for buffer sizes known only at run
time; level 2 covers only what the compiler can size statically. Not wrong, but it leaves the
weaker option as the recommendation. The surrounding note about glibc needing `__OPTIMIZE__` (so
`-O0` silently adds nothing) is correct and worth keeping.

**Suggested wording:** recommend `=3`, noting the GCC 12+ / Clang 15+ requirement and `=2` as the
fallback for older toolchains.

### 4. `java.net.URL` constructors described as "deprecated for removal"

`docs/CWE-88/java/index.md:120-121`

The text reads "the `URL` constructors are deprecated for removal as of Java 20". JDK-8294241 did
deprecate them in Java 20, but the annotation is `@Deprecated(since="20")` **without**
`forRemoval=true` - a soft deprecation. Verified against the JDK 21 javadoc for `URL(String spec)`.
No removal is scheduled and existing code will not stop compiling.

**Impact:** low. The recommendation to prefer `URI.create()` is right; only the justification
overstates it. The stronger argument, which the same sentence already makes, is behavioural:
`URL.equals`/`hashCode` perform DNS resolution.

This error was shared with the `cwe-advisor` knowledge base, which has been corrected.

## Corrections to previously reported `docs/` problems

Two items previously recorded against `docs/` are **not** defects in `docs/` at all - both were
bugs in `cwe-advisor`'s own `scripts/lint.py`, now fixed there.

- **"One genuinely broken link: `docs/CWE-94/javascript/index.md` -> `code`"** is a false positive.
  Line 658 contains `globalThis['ev' + 'al'](code)` inside an inline code span. The linter stripped
  fenced code blocks but not inline spans, so its markdown-link regex matched the `](code)`
  fragment of that expression.
- **"~31 false positives preventing `docs/` from being linted"** were a second bug: the link checker
  did not strip a `#fragment` before testing whether the target file exists.

With both fixed, a pass over `docs/` checks **1196 relative links and finds 0 broken**. `docs/` has
no link rot.

## Checked and found correct

Listed so these are not re-litigated. Each was verified against upstream sources or was more
accurate than the `cwe-advisor` entry covering the same ground.

- **`mysql_real_escape_string` and the PHP 7.0 removal** - correct, and stated twice: the code
  comment at `docs/CWE-89/php/index.md:227` reads `// VULNERABLE - Using deprecated mysql_*
  functions (removed in PHP 7.0)`, and the bullet at :245 reads "These functions were removed in
  PHP 7.0 - always use MySQLi or PDO with prepared statements". This was raised as a finding in an
  earlier draft and withdrawn; the `cwe-advisor` copy was the one behind, and has been corrected.
- **Node.js CVE-2024-27980 versions** (18.20.2, 20.12.2, 21.7.3) - correct.
- **`jdk.lang.Process.allowAmbiguousCommands`** - correct, including that `=false` is what restores
  strict quoting. `cwe-advisor` had this wrong.
- **`escapeshellcmd()` vs `escapeshellarg()`** - correctly distinguished ("they fail differently").
  `cwe-advisor` conflated them.
- **Thymeleaf `th:attr`** - correctly described as auto-escaped. `cwe-advisor` wrongly listed it as
  an escaping opt-out.
- **Laravel `Response::denyAsNotFound()`** - correctly attributed to Laravel, with the
  `AuthorizationException` carrying a 404. `cwe-advisor` had swapped it with Symfony.
- **`os.O_WRONLY | os.O_CREAT | os.O_EXCL`** - correct. `cwe-advisor` omitted `O_WRONLY`, which
  would have made the write fail.
- **`bleach` is `Development Status :: 7 - Inactive`** - correct.
- **ASP.NET Core does not execute uploaded `.aspx`/`.ashx`/`.cshtml`** - correct and measured on
  .NET 10, including the Razor runtime-compilation path into the content root. `cwe-advisor`
  carried the IIS-classic threat model and has since been corrected from this page.
- **`libxml_disable_entity_loader()` handling in `docs/CWE-611/php`** - correct. The samples guard
  the call behind `PHP_VERSION_ID < 80000` and the note at :486 explains that on PHP 8.0+ there is
  nothing for it to do. `cwe-advisor` wrongly claimed the function was *removed* in 8.4 (it is
  deprecated but still present as of 8.5) and has been corrected from this page.
- **`passlib` / `bcrypt` 5.0 breakage** - correct, and more precise than any public summary found:
  the distinction between the harmless trapped `bcrypt.__about__` probe under bcrypt 4.x and the
  hard `ValueError: password cannot be longer than 72 bytes` from the backend self-test under
  bcrypt 5.0 is not stated that clearly elsewhere. `cwe-advisor` was still recommending `passlib`
  and has been corrected from this page.

## Summary

Four errors. Two are worth fixing promptly: gorilla/csrf, because it recommends software with an
unpatched bypass, and the PHP `proc_open` versions, because they produce a false pass in a
dependency check. The other two are lower-consequence wording or staleness. A fifth was raised and
withdrawn - see the `mysql_real_escape_string` entry under "Checked and found correct". The two
previously reported link problems were not `docs/` problems at all.

The broader pattern from checking in both directions: `docs/` was **more** accurate than the
knowledge base built from it on almost every overlapping claim examined. Its errors cluster in
version and CVE metadata rather than in technical explanation - four of the five above are version
or advisory metadata - which is the same class of error the knowledge base's own version sweep
turned up. Version assertions are the thing worth re-checking on a schedule; the prose has held up.

Note the sample is not random: the claims examined were selected because a review had already
flagged them or because the knowledge base asserted the same thing. It supports "`docs/` is a
useful cross-check source", not an error rate for either tree - and the withdrawn finding is a
reminder that the count can move down as well as up.
