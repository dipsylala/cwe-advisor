# TO_REVIEW

Scan memory for the accuracy review of `cwe/` against the human-readable corpus in
`FlawFixingGuidance/` (gitignored sibling clone). One row per CWE in scope; the row is the record
of what has been read, so a later session can resume without re-reading anything.

This file tracks *this* review campaign only. Durable authoring rules live in `CLAUDE.md`, other
pending work in `TODO.md`.

## Scope

Ranks 1-20 of [MITRE's 2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html),
which is the priority set `evals/README.md` already uses. 89 files in `cwe/` are in scope
(20 root entries minus CWE-122, which has no entry, plus their language files).

## Scan procedure

For one CWE, per scan:

1. Read `cwe/{id}/INDEX.md` and every `cwe/{id}/{lang}/INDEX.md` whole. Read the counterpart
   `FlawFixingGuidance/docs/CWE-{id}/index.md` and `.../{lang}/index.md` whole. Whole files, not
   greps: the recurring defect is one bullet contradicting another two screens away.
2. Compare for the five finding shapes below, and for anything `CLAUDE.md`'s *Remediation Claims*
   section names.
3. Verify before editing (see the disagreement rule). A finding is a claim to check, not a diff to
   apply.
4. Fix what is confirmed, keeping the diff small and the entry's scope intact.
5. Run `python scripts/lint.py`.
6. Update this file's row: status, date, files read, findings found/fixed. **Record zero findings
   explicitly** - "read, found nothing" and "never opened" are otherwise indistinguishable.

### Finding shapes to compare for

- **Contradiction.** The two corpora state incompatible facts about the same API, default, version
  floor, or deprecation state.
- **Missing sink.** FFG names a vulnerable sink or safe replacement API that the advisor entry's
  `Taint Sinks` list or `Remediation Steps` omit.
- **Stale claim.** A version, CVE, advisory, or maintenance status that FFG has since corrected, or
  that either corpus carries without a vendor trace.
- **Known-bad shape.** Guidance matching something `CLAUDE.md` already catalogues as wrong:
  allowlist prescribed as a default defence, a format/protocol swap led with as the primary fix,
  the framework's own recommended API listed as a taint sink, a test that passes against unfixed
  code.
- **Coverage gap.** A language FFG covers and the advisor does not, or the reverse.

### Disagreement rule

FFG is a prompt to look, not an authority. It is a separately authored corpus with its own error
catalogue (`FlawFixingGuidance/REVIEW_GOTCHAS.md`), so where the two disagree, the vendor doc or a
runtime reproduction settles it - JDK 26, Go 1.25, Node 24, PHP 8.5 and `uv` are on PATH here; C,
C++ and Ruby are not. Both corpora being wrong in the same way is the case a comparison alone
cannot see, which is why `CLAUDE.md`'s claim rules still apply to every edit this campaign makes.

## Status

`-` = not started. Language columns list what each corpus carries; a difference is itself a
finding. FFG `tests/` directories are fixtures, not guidance, and are out of scope.

| Rank | CWE | Name | Advisor languages | FFG languages | Status | Last scan | Findings |
|---|---|---|---|---|---|---|---|
| 1 | 79 | Cross-site Scripting | csharp, go, java, javascript, perl, php, python | same | done (8/8 read) | 2026-09-20 | 5 found, 5 fixed |
| 2 | 89 | SQL Injection | csharp, go, java, javascript, php, python | same | done (7/7 read) | 2026-09-20 | 3 found, 3 fixed |
| 3 | 352 | Cross-Site Request Forgery | csharp, go, java, javascript, python | same | - | - | - |
| 4 | 862 | Missing Authorization | csharp, go, java, javascript, php, python | same | - | - | - |
| 5 | 787 | Out-of-bounds Write | c, cpp | same | - | - | - |
| 6 | 22 | Path Traversal | csharp, go, java, javascript, php, python | same | - | - | - |
| 7 | 416 | Use After Free | c, cpp | same | - | - | - |
| 8 | 125 | Out-of-bounds Read | c, cpp | same | - | - | - |
| 9 | 78 | OS Command Injection | csharp, go, java, javascript, php, python | same | - | - | - |
| 10 | 94 | Code Injection | csharp, java, javascript, php, python | same | - | - | - |
| 11 | 120 | Classic Buffer Overflow | none (router to 121/787) | no FFG page | - | - | - |
| 12 | 434 | Unrestricted File Upload | csharp, go, java, javascript, php, python | same | - | - | - |
| 13 | 476 | NULL Pointer Dereference | c, cpp, java | none (root page only) | - | - | - |
| 14 | 121 | Stack-based Buffer Overflow | c, cpp | same | - | - | - |
| 15 | 502 | Deserialization of Untrusted Data | csharp, go, java, javascript, php, python | same | - | - | - |
| 16 | 122 | Heap-based Buffer Overflow | no entry | no FFG page | - | - | - |
| 17 | 863 | Incorrect Authorization | csharp, go, java, javascript, php, python | same | - | - | - |
| 18 | 20 | Improper Input Validation | none | none | - | - | - |
| 19 | 284 | Improper Access Control | none | none | - | - | - |
| 20 | 200 | Exposure of Sensitive Information | none | none | - | - | - |

## Cross-cutting checks

Per `CLAUDE.md`, some defects are invisible to a per-file read because each file is internally
consistent. Run these once the per-CWE rows are done, and record the outcome here:

- **862 vs 863** (ranks 4 and 17) must agree on the status an ownership failure returns, across
  every shared language. They have disagreed before.
- **787, 125, 121, 122, 120** (the memory-safety cluster) must agree on hardening flag levels and
  on which entry owns which destination. `120` routes rather than duplicates; check `122`'s absence
  is deliberate and that nothing routes to it.
- **79 vs 80 vs 83** share an XSS sink vocabulary; 80 and 83 are out of scope by rank but a change
  to 79's sink list has to stay consistent with them.
- **22 vs 41 vs 73** likewise for path handling.

## Open questions

- CWE-122 (rank 16) has no entry in either corpus. Decide whether it gets its own entry or a router
  entry pointing at 787, the way 120 does.
- CWE-20, 284 and 200 (ranks 18-20) are root-only in both corpora. Confirm that is deliberate
  before treating the missing language files as a gap.

## Findings log

Findings that were confirmed but not fixed in the scan that found them, and decisions worth
carrying forward. Fixed findings live in `git log`; a shape that recurs twice belongs in
`CLAUDE.md`'s *Remediation Claims* section instead of here.

### 2026-09-20, CWE-89

Read all 7 advisor files and their 7 FFG counterparts. Fixed: the `FromSqlRaw($"...{value}...")`
overload trap (csharp), metamodel-resolved identifiers via `Root.get(name)` and Hibernate's
`Order.asc(Class, String)` (java), and the claim that an array bound to one `?` never expands into an
`IN` list (javascript - mysql2's client-side `query()` does expand it, confirmed with
`mysql2.format`). Root, go, php and python came back clean.

Carried forward:

- **Identifier handling is where this CWE's entries are thin, not parameterisation.** All seven files
  get prepared statements right. Every finding was in the part of the query a placeholder cannot
  reach: the EF Core overload that silently concatenates, the JPA metamodel API that makes the
  allowlist unnecessary for the injection half, the driver-specific `IN` behaviour. Check the
  identifier half first on the remaining SQL-adjacent entries (`943`, `564`, `90`, `91`).
- **A fix can contradict the bullet three lines below it.** The first draft of the csharp addition
  read "`FromSqlRaw($"...")` is always a defect", which the next bullet flatly contradicts - EF Core
  documents interpolating an allowlist-resolved identifier into `FromSqlRaw` as the correct pattern.
  Caught by rereading the file, which is what `CLAUDE.md` already requires and what a per-bullet
  patch skips.
- **FFG's reasoning is sometimes wrong where its conclusion is right.** It says to set
  `PDO::ATTR_EMULATE_PREPARES` in the constructor rather than by `setAttribute()` "because the
  connection is already open by then" - that argument holds for the charset, which the advisor entry
  already ties to the DSN, but emulation is a client-side setting read at `prepare()` time. The
  advisor entry was left as it stands.

### 2026-09-20, CWE-79

Read all 8 advisor files and their 8 FFG counterparts. Fixed in `git log`: the DOMPurify floor
(javascript), the HtmlSanitizer NuGet id and floor (csharp), the OWASP Java HTML Sanitizer version
(java), the JSON-into-`<script>` guidance (perl), and `json_encode()`'s own quoting (php). Root, go
and python came back clean.

Carried forward:

- **The library metadata is what aged, not the technique.** Three of the five findings were a named
  library version and a fourth was that library's package id; none was a wrong description of XSS.
  Two of the three versions were stale rather than wrong when written - `20240325.1` acquired
  CVE-2025-66021 after the entry named it, and DOMPurify shipped ten advisories past the floor the
  entry gave. Re-checking every named version against OSV or the vendor's release list is the
  highest-yield single pass over a CWE, and it is mechanical.
- **Defects found in FFG, not fixed here** (they belong in that repo): its Flask autoescape list
  omits `.svg` (`Flask.select_jinja_autoescape` ends with `.svg`, confirmed on 3.1.3); its Perl page
  says no Perl JSON module has a `JSON_HEX_TAG` equivalent, but `JSON::PP`'s `escape_slash(1)` emits
  `<\/script>` (confirmed on JSON::PP 4.16); and its Go, Java and JavaScript pages all recommend a
  `script-src 'self'` CSP, which is the allowlist form MDN says does not effectively mitigate XSS -
  the advisor entries are already stricter here and were left alone.
- **FFG is worth reading even where it is wrong.** The Perl finding came from FFG arguing the
  opposite of the advisor entry; checking which was right showed both were, in different halves.
