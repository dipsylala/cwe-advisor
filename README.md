# CWE Advisor

A local knowledge base of CWE (Common Weakness Enumeration) remediation guidance, used by the
`cwe-advisor` skill to help developers understand and fix security vulnerabilities directly in
their editor.

## What it does

When a developer mentions a CWE ID, a vulnerability name (SQL injection, XSS, path traversal,
CSRF, deserialization, and so on), or pastes a SAST/DAST finding, the skill:

1. Maps the mention to the right CWE ID.
2. Loads general guidance on the vulnerability class, plus language-specific guidance if the
   developer's code or stack is known.
3. Explains the weakness and the reasoning behind the fix.
4. Offers to apply the fix - checking for vulnerable library versions along the way and tracing
   the actual data flow in the developer's code, not just pattern-matching the finding.

It works equally well for a quick conceptual question ("what is CWE-352?") or a live fix on
real code.

## Structure

```text
cwe/
  {CWE_ID}/
    INDEX.md          general, language-agnostic guidance
    {language}/
      INDEX.md        language- or platform-specific guidance
```

Every CWE covered has a root `INDEX.md`. Language folders are added only where the fix genuinely
differs by ecosystem - some CWEs (memory-safety weaknesses, broad access-control classes) stay
root-only because the remediation approach doesn't vary much by language.

Languages and platforms currently covered: `android`, `c`, `csharp`, `go`, `java`, `javascript`,
`perl`, `php`, `python`, `ruby`.

## Contributing

Adding or editing an entry? See [CLAUDE.md](CLAUDE.md) for the authoring spec - directory
conventions, required sections, tone, and the quality bar entries are held to. The short version:
guidance should teach the LLM what to do, not restate security concepts it already knows, and
should point at the specific fix rather than a general essay on the vulnerability class.

After cloning, run `git config core.hooksPath .githooks` once to enable the pre-commit structural
lint (`scripts/lint.py`) - it checks required headings, root-file code fences, broken links, and
that `references/cwe-identifier.md` stays in sync with the CWE directories under `cwe/`.

## Validation harness

`evals/` (the case corpus, harness runbook, and past run results) is a separate repo,
[cwe-advisor-evals](https://github.com/dipsylala/cwe-advisor-evals), linked in here as a git
submodule so a plain clone of this repo - which is what using the skill actually requires - stays
small. Using the skill needs nothing under `evals/`; only editing entries and wanting to validate a
change against the harness does. To fetch it: `git submodule update --init` (or clone this repo with
`--recurse-submodules`).

Every run scores each fix on two axes, 0-2, averaged across three independent blind judges:
**fix_quality** - does the fix actually close the reported vulnerability with an appropriate API for
the sink - and **no_harm** - does it do that without silently breaking or changing something else
the caller depended on (a dropped argument, a changed return value, an endpoint that stops working
for legitimate use).

The baseline measurement is run 17 (September 2026): 372 cases across 27 CWEs and nine
languages, both arms on Haiku 4.5, every fix applied to its fixture and built before judging,
three blind Sonnet 5 judges per write-up.

| Model | Corpus | No guidance - fix_quality | Guided - fix_quality | No guidance - no_harm | Guided - no_harm |
| --- | --- | --- | --- | --- | --- |
| Haiku 4.5 (run 17) | 372 cases | 1.80 | 1.91 | 1.76 | 1.74 |

Guidance is ahead on fix quality for 64 cases and behind on 22, with the gain concentrated on the
harder cases (the contract-carrying top-15 set goes 1.73 to 1.91) and on CWE-94 (1.38 to 1.83).
No-harm is level. The guided arm's no-harm losses sat in allowlists the CWE-77, 78 and 90 entries
prescribed and the rubric scores as narrowing - resolved in run 18 by making allowlists a
product decision rather than a default step - and in whole-file rewrites that changed something
beside the sink. The compile gate found 16 unguided and 18 guided
fixes that do not build, caught eleven the judge panel had passed unanimously, and turned up two
entries naming a class without its package (`cwe/94/java`, `cwe/79/java`), both fixed.

Two targeted runs then edited the entries against the judge notes and re-sampled the guided arm
on every case whose entry changed - 179 of the 372, with run 17's unguided text kept as the
frozen control. Run 18 named the package of every third-party class the Java entries recommend
and made allowlists conditional in the CWE-22, 77, 78 and 90 entries. Run 19 went through every
remaining guided loss in the notes: the CWE-78 language files had prescribed a TCP probe "instead
of ping", which changes what reachable means; the CWE-22 files still prescribed a `..` test
beside a containment check; seven C# and JDK namespaces were missing; a dozen API shapes the
judges had verified against real packages were absent. Each edit was verified against the
library before it was written, and two more entry defects were found by the run's own notes
(Commons Net's `FTPClient` frames nothing; `SimpleEvaluationContext` has no `setRootObject`).

Taking each case's most recent guided text against the same control, by language (clean = all
three judges gave 2 on both axes; "does not build" is the compile gate, unguided / guided):

| Language | Cases | fix_quality | no_harm | Clean | Does not build |
| --- | --- | --- | --- | --- | --- |
| C | 22 | 1.92 → 1.98 | 1.79 → 1.94 | 18 → 19 | 0 / 0 |
| C++ | 19 | 1.88 → 2.00 | 1.84 → 1.91 | 16 → 18 | 1 / 1 |
| C# | 54 | 1.73 → 1.94 | 1.68 → 1.78 | 34 → 40 | 2 / 2 |
| Go | 43 | 1.79 → 1.98 | 1.67 → 1.81 | 28 → 34 | 6 / 0 |
| Java | 86 | 1.78 → 1.84 | 1.80 → 1.75 | 56 → 59 | 4 / 4 |
| JavaScript | 48 | 1.79 → 1.89 | 1.86 → 1.85 | 35 → 38 | 0 / 0 |
| Perl | 4 | 1.50 → 2.00 | 1.50 → 2.00 | 3 → 4 | 1 / 0 |
| PHP | 44 | 1.92 → 1.95 | 1.80 → 1.87 | 35 → 35 | 2 / 0 |
| Python | 52 | 1.79 → 1.92 | 1.72 → 1.84 | 31 → 41 | 0 / 0 |
| All | 372 | 1.80 → 1.92 | 1.76 → 1.82 | 256 → 288 | 16 / 7 |

Guidance is now ahead on both axes overall: fix quality on 63 cases against 19 behind, no-harm on
62 against 46. The no-harm gap it opened in run 17 closed on the cases whose entries were edited
(1.64 to 1.78 against a 1.79 control on run 19's 138), and the guided arm's build failures fell
from 18 to 7, below the control's 16. What moved was every loss an entry could name - a
namespace, a placeholder syntax, "ping has no library equivalent" - and what did not was the arm
inventing a member on the fixture's own type, swapping the language of stored rules (CWE-94), or
changing a constructor's signature and saying so, which the rubric scores as a change all the
same. Java is the one language still behind on no-harm, on the CWE-94 and CWE-434 cases. The
composite mixes three judge panels; the control's drift across them is 0.03 or less. See
`evals/RESULTS-v18.md` and `evals/RESULTS-v19.md`.

Sixteen earlier runs shaped the harness - the frozen unguided control, the stated contract in the
judge's header, bundled judging by a restricted agent, the compile gate - and were removed at the
run-17 boundary because the current corpus, format and judging no longer share a scale with them.
They remain in the evals repository's git history, and `evals/HARNESS.md` keeps what they taught.
Sonnet 5, on earlier corpora, saturated fix quality regardless of guidance and has not been
measured on the current setup. See `evals/README.md` and `evals/RESULTS-v17.md`.
