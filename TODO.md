# TODO

What remains of the top-15 CWE review (MITRE Top 25 ranks 1-15) and the `Safe Pattern`
retirement. Every graded finding from that review has been applied, along with the sweep audit's
regressions and the version-sensitive items it depended on.

The review's `docs/` process findings have been dropped rather than actioned: `docs/` is temporary
scaffolding carried over from another repository, so it being untracked, carrying its own errors,
and being skipped by the linter are all expected rather than defects. Entries here are expected to
stand on their own against current sources, which is how this pass verified them.

## 1. Open

Nothing outstanding.

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
- `306/` given the same six language entries its siblings `287/` and `862/` carry (csharp, go, java,
  javascript, php, python), each covering where routes escape the framework's auth wiring.
- Two corrections from reading `docs/`: the CVE-2024-1874 fix version for the PHP 8.3 branch is
  reported inconsistently (8.3.5 vs 8.3.6), so `78/php` now anchors on the CVE-2024-5585 floor
  instead; and `434/csharp` names Razor runtime compilation as the content-root code-execution path.
- `CLAUDE.md` now states that `77/{language}` covers non-shell interpreters only, with shell sinks
  routed to `78/`; `scripts/lint.py` strips a `#fragment` before checking a link target exists.
