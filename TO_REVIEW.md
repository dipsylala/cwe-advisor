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
| 3 | 352 | Cross-Site Request Forgery | csharp, go, java, javascript, python | same | done (6/6 read) | 2026-09-20 | 5 found, 5 fixed |
| 4 | 862 | Missing Authorization | csharp, go, java, javascript, php, python | same | done (7/7 read) | 2026-09-20 | 9 found, 8 fixed |
| 5 | 787 | Out-of-bounds Write | c, cpp | same | done (3/3 read) | 2026-09-20 | 3 found, 3 fixed |
| 6 | 22 | Path Traversal | csharp, go, java, javascript, php, python | same | - | - | - |
| 7 | 416 | Use After Free | c, cpp | same | - | - | - |
| 8 | 125 | Out-of-bounds Read | c, cpp | same | done (3/3 read) | 2026-09-20 | 1 found, 1 fixed |
| 9 | 78 | OS Command Injection | csharp, go, java, javascript, php, python | same | done (7/7 read) | 2026-09-20 | 7 found, 6 fixed, 1 reported |
| 10 | 94 | Code Injection | csharp, java, javascript, php, python | same | scanned, NOT applied | 2026-09-20 | 22 found, 0 fixed |
| 11 | 120 | Classic Buffer Overflow | none (router to 121/787) | no FFG page | done (1/1 read) | 2026-09-20 | 0 findings |
| 12 | 434 | Unrestricted File Upload | csharp, go, java, javascript, php, python | same | - | - | - |
| 13 | 476 | NULL Pointer Dereference | c, cpp, java | none (root page only) | done (4/4 read) | 2026-09-20 | 5 found, 5 fixed |
| 14 | 121 | Stack-based Buffer Overflow | c, cpp | same | done (3/3 read) | 2026-09-20 | 3 found, 3 fixed |
| 15 | 502 | Deserialization of Untrusted Data | csharp, go, java, javascript, php, python | same | scanned, NOT applied | 2026-09-20 | 13 found, 0 fixed |
| 16 | 122 | Heap-based Buffer Overflow | router entry, added | no FFG page | done (1/1) | 2026-09-20 | entry created |
| 17 | 863 | Incorrect Authorization | csharp, go, java, javascript, php, python | same | done (7/7 read) | 2026-09-20 | 9 found, 6 fixed |
| 18 | 20 | Improper Input Validation | none | none | done (1/1 read) | 2026-09-20 | 3 found, 3 fixed |
| 19 | 284 | Improper Access Control | none | none | done (1/1 read) | 2026-09-20 | 1 found, 1 fixed |
| 20 | 200 | Exposure of Sensitive Information | none | none | done (1/1 read) | 2026-09-20 | 4 found, 4 fixed |

## Cross-cutting checks

Per `CLAUDE.md`, some defects are invisible to a per-file read because each file is internally
consistent. Run these once the per-CWE rows are done, and record the outcome here:

- **862 vs 863** (ranks 4 and 17) - DONE 2026-09-20. They had drifted again, in `java` this time:
  862 said a non-owner gets the 404 of an owner-scoped repository query, 863 said 403 from a SpEL
  bean that loads then compares, and 863/java was the only 863 language answering 403 where go,
  javascript, php and python all answer 404. Both now prescribe the owner-scoped lookup for a
  guessable identifier and reserve 403 for the role gate. `863/csharp` had no status doctrine at all
  and now does.
- **787, 125, 121, 122, 120** (the memory-safety cluster) - DONE 2026-09-20. Routing is coherent:
  `120` routes stack destinations to `121` and everything else to `787`, and `787` explicitly claims
  the unnamed children including the heap variant `122`, so `122` having no entry is deliberate and
  nothing routes to a missing file. `_FORTIFY_SOURCE` is `=3` everywhere with the right toolchain
  caveat. One divergence remains open, below.
- **Taint Sinks naming the framework's own fix APIs** - DONE 2026-09-20 for the `862`/`863` family
  (12 files). `CLAUDE.md` allows the names to stay, because grepping for them is how the routes that
  *do* carry a check get found, but requires the entry to say what a hit is not. Only `863/csharp`
  did, for one name. Each list now ends with a sentence separating the sinks proper (route and
  handler registrations; the sources) from the fix APIs and the values correct code returns. The same
  audit has not been run on any other family.
- **79 vs 80 vs 83** share an XSS sink vocabulary; 80 and 83 are out of scope by rank but a change
  to 79's sink list has to stay consistent with them.
- **22 vs 41 vs 73** likewise for path handling.
- **77 vs 78 on the leading hyphen** - open. `cwe/77` says to reject a leading hyphen in any value
  becoming a command argument; `cwe/78` says to insert `--` first, which rejects nothing, and to
  reject a leading `-` only where the program does not honour `--`. Same family, opposite default.
  `78`'s form is strictly more precise, but `77` covers non-shell interpreters where `--` is often
  not honoured, so the divergence may be legitimate rather than drift. Settling it needs a survey of
  which interpreters in `77`'s scope honour `--`; not attempted.

## Open questions

- ~~CWE-122 router entry~~ - DONE 2026-09-20. `cwe/122/INDEX.md` written on `cwe/120`'s routing model:
  it defers the write itself to CWE-787 and carries only what is specific to a heap destination - the
  allocation arithmetic, `realloc`'s shrink-and-invalidate behaviour, and the detection point that
  matters (`-fstack-protector-strong` guards a frame, so it does nothing here; ASan's redzones are
  what find it). MITRE has CWE-122 as ALLOWED at Variant level, unlike its Discouraged ancestors, so
  the entry says a finding filed there stays there. `references/cwe-identifier.md` now has the row,
  and `cwe/120` and `cwe/787` were updated to route to it rather than around it - including `120`'s
  LLM Guidance and its last Key Principle, which my own first edit left naming only 121/787.
- **`-O1` vs `-O2` for `_FORTIFY_SOURCE`, across the whole C family.** `121/c`, `125/c`, `787/c` and
  `823/c` say `-O1` or higher; `134/c`, `170/c`, `242/c` and `477/c` say `-O2` or higher. glibc's
  `features.h` gates only on `__OPTIMIZE__ > 0`, which `-O1` satisfies, so activation is settled -
  but whether level 3's `__builtin_dynamic_object_size` is meaningfully weaker at `-O1` than at
  `-O2` is NOT, and needs a compiler this machine does not have. Left divergent rather than
  normalised on an unverified claim.
- CWE-20, 284 and 200 (ranks 18-20) are root-only in both corpora. Confirm that is deliberate
  before treating the missing language files as a gap.

## Known debt from this campaign

- **Six language files are over the ~800 word guideline and this campaign put them there**:
  `cwe/78/php` 928 (was 797), `cwe/862/java` 909 (was 821), `cwe/863/java` 863 (was 728),
  `cwe/78/python` 858 (was 731), `cwe/78/csharp` 856 (was 768), `cwe/862/csharp` 838 (was 740). The
  linter does not fail until 950, so nothing is broken, and `cwe/78/php` is the one to watch. The
  additions were correctness fixes applied on top of files that were already dense; each was trimmed
  once already. What they want now is a pass read for redundancy rather than for defects, which is a
  different job and was not attempted here. The remaining wave-2 CWEs (94, 434, 502, 22) will make
  this worse before it gets better.

## Findings log

Findings that were confirmed but not fixed in the scan that found them, and decisions worth
carrying forward. Fixed findings live in `git log`; a shape that recurs twice belongs in
`CLAUDE.md`'s *Remediation Claims* section instead of here.

### 2026-09-20, wave 2: CWE-78

Six of seven findings applied. The seventh is the `77` vs `78` hyphen doctrine, recorded above as a
cross-cutting item because fixing it means changing `cwe/77`, and whether it should change is an open
question rather than a defect.

- **The `shell=True` concession is gone**, replaced by what the reproduction shows. This is the case
  now written into `CLAUDE.md`: the entry quoted CPython correctly and CPython is wrong.
- **Every language file's only test bullet was "verify the replacement provides the same
  functionality"** - satisfied by the vulnerable original by definition. All five now send
  metacharacters and a leading `-` and assert on the arguments the child received; the root had no
  test step at all and now has one.
- **`Replace all ...` / `Delete ... code`** in the five Key Principles and Replace steps predated the
  keep-and-execute-safely doctrine that had been added to the same files' LLM Guidance, so the
  sections an LLM acts on told it to delete the `ping` call the guidance two screens up says must
  stay. Now conditional on that decision, mirroring the root's step 2.
- **"validate all inputs"** survived as an unqualified step in five files - the eval-run-17
  regression `CLAUDE.md` names - and `go`'s LLM Guidance said "plus allowlist validation" while its
  own Key Principles said the opposite. All now carry the root's conditional wording.
- **`escapeshellarg()` on Windows rewrites the value**: `%`, `!` and `"` become spaces, so
  `100%!x"y` arrives as `100  x y`. Reproduced on PHP 8.5.8. The entry had said only that its quoting
  is "platform-dependent", which does not tell a model the function corrupts legitimate data.
- **Sink coverage**: `javascript` omitted `spawnSync()`/`execFileSync()` and qualified `spawn()` with
  "(with `shell: true`)" although the file's own batch-file and CWE-88 bullets apply without a shell;
  `python` omitted `check_output()`/`check_call()`.

### 2026-09-20, wave 1 (agent-gathered evidence, applied by this session)

Nine read-only agents were given one CWE each, told to read both corpora whole, to verify against a
vendor source or a runtime, and to separate confirmed from suspected. Findings were re-verified here
before any edit. What the wave produced is in
`<scratchpad>/wave1/cwe-*.md`; what it changed is in `git log`.

**Applied: 862, 863, 476, 20, 284, 200.**

The dominant shape, found independently in six files across the 862/863 pair, is the one this
campaign already hit in `cwe/352/go`: **the Remediation Steps prescribe one mechanism and the Test
step asserts the result of a different one.** In `862/csharp`, `862/java`, `862/python`, `862/php`,
`863/java` and `863/python` the steps prescribe a load-then-compare authorization check, which
answers 403, while the test asserts the 404 that an owner-scoped lookup produces - a lookup no step
prescribed. An LLM executing those steps ships the existence oracle the root entry warns about and
then fails the entry's own test. Every one of those files is internally plausible; only reading the
steps against the test catches it.

Other applied findings worth carrying:

- **`getOrDefault` does not close an unboxing NPE** where the map can hold nulls - it returns the
  stored null and `intValue()` still throws (reproduced on JDK 26). `476/java` prescribed it as the
  fix for the `Map.get` case.
- **`UserManager.GetUserId(User)` is not "mapping-independent"** - it reads
  `IdentityOptions.ClaimsIdentity.UserIdClaimType`, which defaults to the same
  `ClaimTypes.NameIdentifier` the surrounding sentence had just said is absent (dotnet/aspnetcore
  `UserManager.cs:446`). `863/csharp` offered it as the way round inbound-claim mapping.
- **`\z` is a compile error in Python's `re` before 3.14** (`bad escape \z`, reproduced on 3.13.12).
  `cwe/20` offered it as one of three interchangeable whole-string anchors.
- **`hasRole('ADMIN') or isOwner(...)` widens an admin-only endpoint to every owner.** `863/java`
  gave it as the canonical expression. Whether owners may act at all is a product decision the fix
  must not make.
- **`snprintf(NULL, 0, ...)` is the standard's own sizing idiom**, not undefined behaviour;
  `476/c` listed it beside `memcpy` as UB-on-null and as a taint sink.
- **MITRE marks CWE-284 and CWE-200 Discouraged** (Pillar and Class respectively, both confirmed on
  cwe.mitre.org). Both entries routed correctly but never said the ID should not be the reported one,
  so an autonomous write-up would keep it.

**Not applied, and the reason is volume.** `cwe/94` returned 22 confirmed defects, `cwe/434` 17,
`cwe/502` 13, `cwe/22` 8 and `cwe/78` 7, each traced to a runtime or a vendor source. Those are five
remediation jobs, not a triage pass - see the wave-1 files.

One of them is worth pulling out here because it is a new shape rather than a new instance.
`cwe/78/python` tells the model that CPython's security-considerations section advises passing
`shell=True` for a Windows batch file with untrusted arguments "so Python can escape the special
characters". The docs do say exactly that ("consider passing shell=True to allow Python to escape
special characters", citing gh-114539). It does not work. Reproduced on 3.13.12 against a `.bat`
echoing `%1`, with the payload `x"&echo INJECTED&"`:

```text
shell=False   ARG IS: "x\"     INJECTED      <- the injected echo ran
shell=True    ARG IS: "x\"     INJECTED      <- byte-identical
```

`list2cmdline` escapes the quote as `\"`, which `cmd.exe` does not honour, and `shell=True` adds a
`cmd.exe /c` wrapper over the same escaping rather than any additional quoting. So the entry is
faithfully relaying its vendor's own incorrect advice, and it licenses the `shell=True` the root
entry forbids - while the same file's next-but-one bullet states the correct position (a `.bat`
re-enters `cmd.exe`, so an argument list gives no protection; invoke the wrapped executable instead).
CLAUDE.md's rule already covers this - a vendor doc establishes that a rule exists, not that it
produces the claimed result - but every instance so far has been a *paraphrase* going wrong. This one
is accurate to the source and still false, which is the case that rule does not yet name.

Process note for the next wave: the agents were substantially right. Every claim spot-checked here -
the Java reproductions, the aspnetcore source, the Spring Security jar diff, the Python regex, the
MITRE pages - held up. The value added by re-verifying was not catching agent errors but choosing
which findings to act on and writing the replacement prose, which is where this session's own
near-miss happened in rank 2.

### 2026-09-20, memory-safety cluster (ranks 5, 8, 11, 14, 16)

Read `cwe/120`, `121`, `125`, `787` roots and the `c`/`cpp` files under 121, 125 and 787, plus the
FFG counterparts for 121. Handled here rather than fanned out: there is no C or C++ toolchain on this
machine, so every claim is settled by reading a vendor source, and the flag consistency check needs
all five entries held at once.

Three findings, all in the `_FORTIFY_SOURCE` guidance, all settled against glibc's own
`include/features.h` (fetched from sourceware at HEAD and at the `glibc-2.34` tag):

- **"at `-O0` it silently does nothing" was wrong in one word.** `features.h` emits
  `#warning _FORTIFY_SOURCE requires compiling with optimization (-O)`. Not silent - and the
  difference matters to a developer checking whether their hardening is live, because the entry told
  them there was no signal to look for. Was in `121/c` and `787/c`.
- **"fall back to `=2` on older toolchains" told the model to do work glibc already does.**
  `features.h` degrades an unsupported `=3` to level 2 itself, with
  `#warning _FORTIFY_SOURCE > 2 is treated like 2 on this platform`. So `=3` is safe to set
  unconditionally and toolchain detection is unnecessary. Present identically in nine C files;
  swept all nine, which is four outside the top-20 - `CLAUDE.md`'s "sweep doctrine across the family"
  rule against leaving known-imprecise text in siblings.
- **`121/c` said `strlcpy`/`strlcat` "where available"** while its sibling `787/c` carried the
  floor. Now both say BSD, macOS and glibc 2.38+, confirmed in glibc's 2.38 NEWS ("The strlcpy and
  strlcat functions have been added").

One contradiction surfaced by the fix itself: `787/c`'s Key Principles said `_FORTIFY_SOURCE`
"catch[es] mistakes where the size is statically known", which is level 2's scope and is
contradicted by the same file's level-3 guidance. Rewritten to the canary point, which is the part
that was actually load-bearing.

Carried forward:

- **A hardening-flag claim is checkable against one header.** `include/features.h` is the whole
  decision procedure for `_FORTIFY_SOURCE` - level selection, toolchain gates, every warning it
  emits - and it is 20KB. Any future claim about this flag should be settled there rather than from
  a blog post or recall, and the same is likely true of other glibc feature-test macros.
- **The word "silently" is a claim.** It asserts the absence of a diagnostic, which is exactly the
  kind of thing a vendor source settles and a plausibility reread does not.

### 2026-09-20, CWE-352

Read all 6 advisor files and their 6 FFG counterparts. Four findings were in `go`, one in the root.
csharp, java, javascript and python came back clean, and their sharper claims were re-verified rather
than assumed: `AntiforgeryOptions.HeaderName` does default to `RequestVerificationToken` (aspnetcore
source), `CsrfConfigurer.spa()` exists in Spring Security 7.1.1 and `SpaCsrfTokenRequestHandler` ships
in neither 6.5.7 nor 7.1.1 (javap), and `csrf-csrf` v4 does export `generateCsrfToken` and does throw
without `getSessionIdentifier` (ran it).

Carried forward:

- **An entry can be updated in the half a reader reaches last.** `go`'s LLM Guidance and Key
  Principles had been moved to `net/http.CrossOriginProtection`, including the finding that
  `gorilla/csrf` has an unfixed CVE and must be replaced. Its Remediation Steps still said to add
  `csrf.Protect(...)` and render `csrf.TemplateField(r)` - so the steps prescribed adopting the
  library the principles above them say to rip out, and prescribed it in the one form
  (`filippo.io/csrf/gorilla`) where those calls return stubs. The steps section is where an LLM
  actually acts; check it against the principles whenever a primary defence changes.
- **The test step has to test the fix that was prescribed.** The same file told the model to verify
  with "missing, forged, and expired tokens" under a primary fix that has no tokens at all. Replaced
  with a header replay, including the `Sec-Fetch-Site: same-site` case - reproduced on Go 1.25.5,
  where it returns 403 while a `SameSite=Strict` cookie would still have been sent, so it is the
  assertion that distinguishes the check from the cookie flag. The same run confirmed requests with
  neither header are allowed (200) and that the `Origin` fallback compares hosts, not schemes.
- **Check whether a wrapper survives how the server is started.** `gin.Engine.Run()` builds its own
  `http.Server` around `engine.Handler()` and `echo.Echo.Start()` passes the `Echo` itself, so
  wrapping a handler and then calling `r.Run()` compiles, serves every route and applies no check
  (read from both projects' sources). This is the `CLAUDE.md` "ask what the edit does when applied"
  rule in a shape worth looking for elsewhere: middleware that is constructed but never on the path.
- **The root entry had no verification step at all**, unlike every sibling root read so far. Added
  three assertions, the load-bearing one being a token minted in one session replayed in another.

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
