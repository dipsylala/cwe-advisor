# TODO

What remains of the top-15 CWE review (MITRE Top 25 ranks 1-15) and the `Safe Pattern`
retirement. Every graded finding from that review has been applied, along with the sweep audit's
regressions and the version-sensitive items it depended on.

The review's `docs/` process findings have been dropped rather than actioned: `docs/` is temporary
scaffolding carried over from another repository, so it being untracked, carrying its own errors,
and being skipped by the linter are all expected rather than defects. Entries here are expected to
stand on their own against current sources, which is how this pass verified them.

## 1. Open

### Extend the graded review to the rest of the MITRE Top 25

The first pass was described as covering ranks 1-15. Checked against the list, it actually covered
**ranks 1-14**; CWE-269 was never touched. Two further entries look covered but are not: CWE-918
received one `CURLPROTO_HTTPS` fix from the sweep audit, and CWE-306 gained language entries
without its root being graded.

Remaining, in rank order:

| Rank | CWE | Entry | Language dirs | Note |
|---|---|---|---|---|
| 15 | CWE-269 Improper Privilege Management | yes | 0 | Missed by the first pass. Router-style entry, like CWE-20/119 |
| 16 | CWE-502 Deserialization | yes | 6 | Full graded review |
| 17 | CWE-200 Information Exposure | yes | 0 | Abstract; check it routes rather than remediates |
| 18 | CWE-863 Incorrect Authorization | yes | 6 | Pairs with CWE-862, already reviewed - check they agree |
| 19 | CWE-918 SSRF | yes | 6 | Only the sweep-audit fix so far; needs a graded pass |
| 20 | CWE-119 Buffer bounds | yes | 0 | Router to 125/787/121; verify the mapping is complete |
| 21 | CWE-476 NULL Pointer Dereference | yes | 0 | Warrants `c`/`cpp`/`java` entries |
| 22 | CWE-798 Hard-coded Credentials | yes | 6 | Full graded review |
| 23 | CWE-190 Integer Overflow | yes | 3 | Only c/cpp/java; likely needs go/csharp |
| 24 | CWE-400 Uncontrolled Resource Consumption | **missing** | - | Not in the knowledge base at all |
| 25 | CWE-306 Missing Authentication | yes | 6 | Language entries added this session; root not graded |

### Coverage gaps surfaced by building the eval corpus

Mapping OWASP Benchmark's categories onto the knowledge base exposed three gaps, all outside the
Top 25 and none previously recorded:

- **CWE-643 (XPath Injection) has no entry at all.** It is a Benchmark category with 15 true
  positives, so it is a weakness real scanners report.
- **CWE-327 and CWE-501 have root guidance but no language directories.** CWE-328 likewise.

None is a defect in existing guidance; they are absences. Recorded here rather than fixed, since
adding entries is authoring work and a separate decision.

Two things worth settling before starting:

- **CWE-400 is absent.** It is the only Top 25 entry with no directory. Creating it is authoring
  work rather than review work, so it is a separate decision from the rest of this list.
- **MITRE rank is a proxy, not the real signal.** The Top 25 is derived from CVE/KEV data - what
  gets exploited in the wild - whereas this skill receives whatever a SAST tool flags in
  application code. If scanner output is available showing which CWEs actually arrive, that beats
  MITRE ordering for prioritising this list. Absent it, rank order is consistent with the first
  pass and defensible.

Beyond rank 25 there are roughly 160 further entries whose prose has never been reviewed. The
version-claim sweep covered all of them for that one error class only.
## Done this session (context)

- `Safe Pattern` retired across all 307 language files; guidance is prose-only. Spec, template and
  linter updated to match.
- `SKILL.md`: C++ now routes to `cpp/` (12 directories were unreachable); router CWEs now re-enter
  to load the child entry, with `20/INDEX.md` given the numbered mapping that hop needs.
- CWE-94 and CWE-287 reconciled against the updated docs, including the user-enumeration timing
  oracle across all seven CWE-287 files.
- Three criticals fixed: `22/java` double decode (plus NFC removal from root/csharp/javascript),
  `434/java` `Files.probeContentType()`, `79/perl` Template Toolkit vs HTML::Mason.
- `PROGRESS.md` removed (its pass was complete).
- `89/csharp:25` fixed: `Parameters.Add(...)` now assigns `.Value` on the returned parameter, and
  `size` is scoped to variable-length types.
- The sweep's 248 removed code blocks were audited for detail lost with them, using a detector
  calibrated against the `89/csharp` defect and hand-verified afterwards. Five entries had lost
  something (`434/javascript`, `434/php`, `918/php`, `326/go`, `114/c`); all five are now fixed.
  Everything else survived the rewrite, in several cases more completely than the block stated it.
  The A/B validation of guidance quality with blocks vs without was never run.
- All graded review findings applied across CWE-22, 78, 79, 89, 125/416/787, 352, 434, 862, and the
  20/77/94/287 group. Three claims were corrected against current sources while doing so: the PHP
  `proc_open` fix versions are 8.1.28/8.2.18/8.3.5 with a further bypass fixed in 8.1.29/8.2.20/8.3.8
  (CVE-2024-5585), `gorilla/csrf` has no fixed release for CVE-2025-47909, and ASP.NET Core does not
  execute uploaded `.aspx`/`.cshtml` at all - unknown content types 404.
- Version-claim sweep completed across all 187 CWE directories: 110 version assertions in 61 files
  extracted mechanically, routine standard-library floors taken as read, and the 13 specific enough
  to be wrong verified against upstream sources. Two were wrong, both now fixed - `88/java` called
  the `java.net.URL` constructors "deprecated for removal" when JDK 20 marked them
  `@Deprecated(since="20")` without `forRemoval`, and `611/php` said
  `libxml_disable_entity_loader()` was removed in 8.4 when it is deprecated since 8.0 and still
  present in 8.5 (that bullet also described `LIBXML_NO_XXE` as disabling entity substitution when
  it blocks external entity loading). Eleven checked out: Python 3.14 `\z`, Java 18
  `Runtime.exec(String)`, Go 1.24 `crypto/rand` panic, PHP 8.4 `LIBXML_NO_XXE`, `tarfile` filter
  default from 3.14, `closefrom` in glibc 2.34, XStream 1.4.7/1.4.18, AWS SDK for Java v1 end of
  support, Node CVE-2016-2216, PHP 5.1.2 `header()`, and the Spring Security `sessionFixation()`
  default. The `88/java` error was shared with `docs/`, which has since been corrected there.
- `SKILL.md` hardened on two evidenced defects: Step 5 no longer licenses supplying a library
  version from model recall (the failure mode behind three wrong version claims found this
  session), and Step 4 now treats a non-exploitable trace as a valid outcome in *both* modes -
  previously that path existed only in `references/tone.md`, which autonomous mode never reads,
  so CI runs had no way to conclude a finding was a false positive. `autonomous-output.md` gained
  a `verdict` field separating `not_exploitable` from `undetermined`. Go added to the Step 3
  language table (29 entries, more than C or C++, both already listed).
- `306/` given the same six language entries its siblings `287/` and `862/` carry (csharp, go, java,
  javascript, php, python), each covering where routes escape the framework's auth wiring.
- Two corrections from reading `docs/`: the CVE-2024-1874 fix version for the PHP 8.3 branch is
  reported inconsistently (8.3.5 vs 8.3.6), so `78/php` now anchors on the CVE-2024-5585 floor
  instead; and `434/csharp` names Razor runtime compilation as the content-root code-execution path.
- `CLAUDE.md` now states that `77/{language}` covers non-shell interpreters only, with shell sinks
  routed to `78/`; `scripts/lint.py` strips a `#fragment` before checking a link target exists.
