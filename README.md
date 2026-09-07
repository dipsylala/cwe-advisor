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

The current measurement is run 17 (September 2026): 372 cases across 27 CWEs and nine languages,
both arms on Haiku 4.5, every fix applied to its fixture and built before judging, three blind
Sonnet 5 judges per write-up.

| Model | Corpus | No guidance - fix_quality | Guided - fix_quality | No guidance - no_harm | Guided - no_harm |
| --- | --- | --- | --- | --- | --- |
| Haiku 4.5 (run 17) | 372 cases | 1.80 | 1.91 | 1.76 | 1.74 |

Guidance is ahead on fix quality for 64 cases and behind on 22, with the gain concentrated on the
harder cases (the contract-carrying top-15 set goes 1.73 to 1.91) and on CWE-94 (1.38 to 1.83).
No-harm is level. The guided arm's no-harm losses sit in allowlists the CWE-77, 78 and 90 entries
prescribe and the rubric scores as narrowing - an open doctrine question - and in whole-file
rewrites that changed something beside the sink. The compile gate found 16 unguided and 18 guided
fixes that do not build, caught eleven the judge panel had passed unanimously, and turned up two
entries naming a class without its package (`cwe/94/java`, `cwe/79/java`), both fixed.

By language, no guidance → guided (clean = all three judges gave 2 on both axes; "does not
build" is the compile gate):

| Language | Cases | fix_quality | no_harm | Clean | Does not build |
| --- | --- | --- | --- | --- | --- |
| C | 22 | 1.92 → 1.97 | 1.79 → 1.91 | 18 → 18 | 0 / 0 |
| C++ | 19 | 1.88 → 2.00 | 1.84 → 1.91 | 16 → 18 | 1 / 1 |
| C# | 54 | 1.73 → 1.93 | 1.68 → 1.72 | 34 → 35 | 2 / 6 |
| Go | 43 | 1.79 → 1.93 | 1.67 → 1.78 | 28 → 34 | 6 / 0 |
| Java | 86 | 1.78 → 1.83 | 1.80 → 1.63 | 56 → 54 | 4 / 10 |
| JavaScript | 48 | 1.79 → 1.89 | 1.86 → 1.69 | 35 → 31 | 0 / 1 |
| Perl | 4 | 1.50 → 2.00 | 1.50 → 2.00 | 3 → 4 | 1 / 0 |
| PHP | 44 | 1.92 → 1.98 | 1.80 → 1.84 | 35 → 34 | 2 / 0 |
| Python | 52 | 1.79 → 1.92 | 1.72 → 1.74 | 31 → 35 | 0 / 1 |

Fix quality is level or better with guidance in every language; no-harm moves within the judges'
disagreement range either way. Where the guided arm does lose no-harm, the causes are the same
across languages, in order of size: it reaches for the library or API the entry names and gets
it wrong (the build failures above, four of them the two package defects); it adds the allowlists
the CWE-22, 77, 78 and 90 entries prescribe, which the rubric scores as narrowing; and it rewrites
more of the file, which is more places to change behaviour.

Run 18 acted on the first two and re-ran the guided arm on the 115 affected cases beside run 17's
frozen text. Naming the package of every third-party class the Java entries recommend took the
guided arm on those 37 cases from 1.53 / 1.60 to 1.84 / 1.81 and its build failures from eight to
three. Making allowlists conditional in the CWE-22, 77, 78 and 90 entries did what it said - the
guided arm stopped adding them, and the judges' narrowing verdicts fell from twelve to two - but
no-harm on those 78 cases stayed flat (1.66 to 1.68): the losses moved to behaviour changes made
while replacing a shell call with a library, which the entries already warn against in prose.
That bucket needs a mechanical check, not another bullet. See `evals/RESULTS-v18.md`.

Sixteen earlier runs shaped the harness - the frozen unguided control, the stated contract in the
judge's header, bundled judging by a restricted agent, the compile gate - and were removed at the
run-17 boundary because the current corpus, format and judging no longer share a scale with them.
They remain in the evals repository's git history, and `evals/HARNESS.md` keeps what they taught.
Sonnet 5, on earlier corpora, saturated fix quality regardless of guidance and has not been
measured on the current setup. See `evals/README.md` and `evals/RESULTS-v17.md`.
