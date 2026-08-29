# Findings for the `docs/` corpus

Defects noticed in `docs/` while sweeping this repository's entries against vendor
sources. `docs/` is gitignored here and maintained elsewhere, so this file is the
hand-off channel rather than a change set.

**How these were found.** Step 5 of the triage sweep compares each swept CWE family
against its `docs/` parent. The comparison runs both ways: most of what it surfaces is
a defect *here*, and this file records only the residue pointing the other way. Every
item under "Verified this pass" was traced to a primary source during batches 5-8
(CWE-77, 80, 88, 91, 93, 95, 113, plus 41); the quotes below are from the vendor, not
from recall.

**Scope note.** `docs/` is usually ahead of this repo on operational detail - what a fix
fails to cover, what a test actually proves, which precondition a defence needs. Several
of its points were adopted here this pass. The items below are the narrower set where a
claim does not survive contact with the vendor documentation.

---

## Verified this pass

### 1. `docs/CWE-88/java/index.md:235` - `--` support is wrong for two of the three programs it names

Claim, verbatim:

> **`--` is not universal.** It works for `curl`, `git` and `tar`; `find` has no
> end-of-options marker and reads a leading `-` as a predicate regardless.

Three corrections:

- **git.** `--` is git's revision/path separator, not an end-of-options marker.
  gitcli(7): "Because `--` disambiguates revisions and paths in some commands, it cannot
  be used for those commands to separate options and revisions. You can use
  `--end-of-options` for this". `--end-of-options` arrived in **git 2.24**.
- **tar.** The GNU tar manual documents no `--` terminator at all. It works in practice,
  but the manual offers `--add-file=file` ("useful if file begins with a `-`") and
  `--verbatim-files-from` instead, so a reader checking the vendor finds nothing.
- **find.** It is not that `find` "has no end-of-options marker" - findutils documents
  the marker as existing and not working: "A double dash '--' could theoretically be used
  to signal that any remaining arguments are not options, but this does not really work
  due to the way find determines the end of the list of starting point arguments". The
  same paragraph names three remedies the page omits: prefix the value with `./`, use an
  absolute path, or use the GNU option `-files0-from`.

Why it matters: as written, the bullet tells a reader `--` closes the finding for git and
tar, and leaves `find` with no remedy at all. Only curl documents `--` as an
end-of-options marker for its own arguments.

Source: <https://www.gnu.org/software/findutils/manual/find.html> ("Starting points"),
<https://git-scm.com/docs/gitcli>, <https://www.gnu.org/software/tar/manual/tar.html>,
<https://curl.se/docs/manpage.html>.

### 2. `docs/CWE-113/index.md:175` and `docs/CWE-113/php/index.md:9` - the PHP generalisation has an exception that inverts it

Claim, verbatim (php page):

> **PHP does not reject the value - it discards the whole header and carries on.**

The measurement behind it is correct: for the payload shown, with the CRLF mid-string,
the header is dropped. The generalisation is what over-reaches.

In php-src `main/SAPI.c`, `sapi_header_op` runs a trailing-whitespace strip **before**
the CR/LF safety check:

```c
/* cut off trailing spaces, linefeeds and carriage-returns */
if (header_line_len && isspace((unsigned char)header_line[header_line_len - 1])) {
```

`isspace()` covers `\r` and `\n`. So a value whose only newline trails is silently
trimmed and the header **is** sent - `header("Location: /a\r\n")` emits `Location: /a`
with no warning. That is the strip-rather-than-reject behaviour the same page argues
against two bullets earlier.

Suggested addition: the drop applies to injection-shaped input; a trailing newline is
trimmed instead, which is a third behaviour again.

### 3. `docs/CWE-113/index.md:175`, `java/index.md:9,340`, `csharp/index.md:269` - the Tomcat/Jetty rewrite is broader than "CR and LF"

Claim, verbatim (java page):

> `setHeader`, `addHeader` and `setContentType` all accept a value containing `\r\n`
> without complaint and replace each newline with a space as the header is written.

Correct for CR and LF, but both containers replace considerably more:

- **Tomcat**, `Http11OutputBuffer.write(MessageBytes)`: every control character except
  TAB, plus DEL - `if ((buffer[i] > -1 && buffer[i] <= 31 && buffer[i] != 9) || buffer[i] == 127)`.
- **Jetty**, `HttpGenerator.putSanitisedValue`: `if (c > 0xff || (c <= 0x1F && c != '\t'))`,
  so any code point above 0xFF goes too. Jetty also sanitises header **names**, and uses
  `.` there rather than a space (`putSanitisedName`).

Two consequences worth carrying:

- A reader may infer that a control character other than CR/LF survives. Mostly it does not -
  but the containers differ, and **an earlier revision of this file got that wrong**: Tomcat
  filters DEL (0x7F), Jetty does not. The safe statement true of both is "every C0 control
  character except TAB". This is also why the Unicode line terminators are not an HTTP
  response-splitting vector on either container - they cannot reach the wire as themselves.
- Tomcat's filter had a bounds defect (`bc.getLength()` where `bc.getEnd()` was meant),
  so with a non-zero offset trailing bytes went unfiltered. Fixed in **Tomcat 11.0.23,
  10.1.56 and 9.0.119**, and not mentioned in the changelog. A page giving measured
  behaviour should probably carry that floor.

Also worth noting: Tomcat's filter is conditional on `mb.getType() != MessageBytes.T_BYTES`,
so a value already held as bytes bypasses it.

### 4. `docs/CWE-91/javascript/index.md:203` - imprecise on how xmlbuilder2 handles names

Claim, verbatim:

> xmlbuilder2 auto-escapes text and attribute values, not names, so a name built from
> input is a different, unaudited code path.

Measured on xmlbuilder2 4.0.3: `.ele()` and `.att()` **validate** names and throw
(`Invalid XML name: a<b>c`) rather than passing them through. So a malformed name fails
loudly rather than injecting.

The real exposure is the subtler one that `docs/CWE-91/python/index.md` already states
correctly for ElementTree: a name that *is* a valid XML name still lets an attacker
choose which element gets created. Aligning the JavaScript wording with the Python page
would fix it.

Related, and absent from that page: `.ele()` given a single string argument parses it as
markup rather than treating it as an element name - `ele('<foo><bar/></foo>')` inserts the
subtree. That is a genuine unaudited path.

---

## Carried over from earlier passes - both now withdrawn

Recorded in this repo's `TODO.md` from the batch 1-4 reconciliation and reproduced here without
re-verification. **Both have since been checked and neither stands.**

- ~~The CWE-943 root says "never enable" server-side JavaScript.~~ **Withdrawn - no defect.**
  `docs/CWE-943/index.md:39` reads "Never enable server-side code execution features (such as
  MongoDB's `$where`) **with any part of the expression derived from user input**". The
  qualifier was intact; the `TODO.md` note dropped it and this file carried the drop forward.
- ~~`docs/` states that .NET Framework processes DTDs by default; true only below 4.5.2.~~
  **Withdrawn as stated.** `CWE-611/csharp/index.md:31,53` do want a version qualifier, but
  "true only below 4.5.2" conflates the `XmlResolver` default with DTD parsing itself, and no
  primary source was reached for either. Needs its own pass rather than a swap of one
  imprecise claim for another.

---

## Systematic gap: version floors

Not a per-file defect, but the single highest-value thing to act on. `docs/` carries
almost no version or advisory metadata, and across eight sweep batches that was the
category where this repo most often had to add something rather than correct something.

**Treat this table as a starting list, not a change set.** These are advisory-derived floors
as of the sweep, and floors move - re-check each row against the vendor before adopting it.
Note also that *floor* and *latest release* are different numbers: the floor is the lowest
version carrying every known fix, which is the actionable one, and CLAUDE.md's rule is that
"use the latest version" is not a fix.

Floors traced to vendor releases this pass, on subjects `docs/` covers without them:

| Subject | Floor / status |
|---|---|
| `bleach` (Python sanitizer) | **End of maintenance.** 6.4.0 (June 2026) is final; repo archived; an open `linkify` advisory has no fix and no prospect of one. Successor is `nh3` |
| DOMPurify | **3.4.13** - the highest *fixed* version across its advisories, so the minimum safe one. Latest release is 3.4.14, which carries no advisory of its own |
| jsdom, for server-side DOMPurify | **20.0.0+**; DOMPurify's README says happy-dom "is not considered safe" |
| HtmlSanitizer (.NET) | **9.2.1039**. The advisory-derived floor is 9.0.967, but the record undercounts twice: the highest-severity issue has no CVE, and the `SanitizeDom` bypass fixed in 9.2.1039 was never filed |
| FreeMarker auto-escaping | **2.3.24+**, and off by default (`undefined` output format "does no escaping") |
| Jakarta Mail SMTP injection | CVE-2025-7962, fixed in `org.eclipse.angus:smtp` **2.0.4** / `com.sun.mail:jakarta.mail` **2.0.2** and **1.6.8** - the implementation artifact, not the API one |
| PyYAML | **5.4** (last `FullLoader` RCE fix), **6.0** (`Loader` becomes mandatory) |
| Jinja2 sandbox | **3.1.6** |
| Spring `UriComponentsBuilder` | **6.1.6 / 6.0.19 / 5.3.34** - three CVEs, each bypassing the last |
| Spring `redirect:` open redirect | **7.0.9** on 7.0.x, covering both CVEs - 41844 alone landed in 7.0.8. On 6.2.x, 6.2.19 closes 41844 only; 47887's fix there is Enterprise-only. 6.1.x and older have no OSS fix for either |
| Node `child_process` on Windows | **18.20.4 / 20.15.1 / 22.4.1** (CVE-2024-27980, then CVE-2024-36138 bypassing it) |
| PHP `proc_open` array form on Windows | **8.1.29 / 8.2.20 / 8.3.8** (CVE-2024-1874, then CVE-2024-5585) |
| CGI.pm `escapeHTML` | **4.21** - before it, `'` was escaped only for ISO-8859-1/Windows-1252 charsets |
| Python `email` header rejection | **3.8.20 / 3.9.20 / 3.10.15 / 3.11.10 / 3.12.5 / 3.13** (CVE-2024-6923) |

---

## Where `docs/` was ahead

Included so this file is not read as a one-directional critique. Adopted into this repo
during batches 5-8:

- `ffmpeg` has no `--opt=value` form, so a single injected argv element cannot carry its
  own value - a named false-positive case for CWE-88.
- `tar --checkpoint-action=exec=` is inert without a companion `--checkpoint=N`, so the
  payload people reach for passes against a broken fix and a working one alike.
- `--help` returns 0 on most tools, so a leak arrives looking like a successful response.
- `UrlEncoder` applied to a whole URL breaks every legitimate redirect while every
  malicious-input test still passes.
- `value.matches(".*[\r\n].*")` is false for `\r\n`, because `.` does not cross a line
  terminator.
- PHP's `header_register_callback` runs after application code and can reintroduce
  attacker-controlled text into a validated header.
- The framing that CWE-80 names only element content, so one finding is a reason to sweep
  the contexts it does not name.
