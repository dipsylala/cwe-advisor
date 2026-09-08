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
[cwe-advisor-evals](https://github.com/dipsylala/cwe-advisor-evals). Using the skill needs
nothing under `evals/`; only editing entries and wanting to validate a change against the
harness does. To fetch it: `git submodule update --init` (or clone this repo with
`--recurse-submodules`).

Every run scores each fix on two axes, 0-2, averaged across three independent blind judges:

- **fix_quality** - does the fix actually close the reported vulnerability, using an API appropriate
  to that sink? A fix that does not build scores 0, as does one that leaves the vector open. A fix
  that closes it awkwardly, or with the wrong mechanism for the sink, scores 1.
- **no_harm** - does it do that without breaking or changing anything else the caller depended on?
  A dropped argument, a changed return value or response shape, an endpoint that stops working for
  legitimate input, or a fix that closes one weakness and opens another. Two rules carry most of
  the weight. Adding a restriction the contract never asked for - an allowlist, a length bound, a
  newly required parameter - scores 1 even when the write-up states it. And stating a change that
  stops legitimate use moves it from 0 to 1, never to 2: disclosure earns a point because a
  reviewer or a gate can catch it before it ships, but it does not make the change harmless.

Scores are only comparable within a run. Each run fixes one arm model and one judge panel, and a
number from one run should not be read against a number from another, including the earlier runs
recorded in `evals/`.

### Current measurement: runs 20 and 21

Two fresh arm pairs on the same 372 cases across 27 CWEs and nine languages, the same prompts and
the same rubric, differing only in the arm model, so guidance and model strength can be read
against each other. Every fix is applied to its fixture and built before judging. Judged off
Sonnet, because a model scoring its own output has an obvious problem: Fable throughout run 20,
and Fable plus Opus 5 in run 21 on a measured offset of 0.03.

| Arm model | fix_quality | no_harm | Does not build |
| --- | --- | --- | --- |
| Sonnet 5 (run 20) | 1.92 → 1.94 | 1.70 → 1.76 | 7 → 3 |
| Haiku 4.5 (run 21) | 1.74 → 1.88 | 1.67 → 1.69 | 16 → 10 |

Guidance recovers most of the distance between the two model tiers on fix quality. Unguided, Haiku
trails Sonnet by 0.18; guided, by 0.06.

Where the help lands depends on how much headroom the model has. Sonnet's fix quality is already
saturated, with 343 of 372 cases tied between its arms, so its gain shows up on no-harm and on the
compile gate instead, while Haiku takes it on fix quality. The two readings agree rather than
conflict: the entries supply the right API for the sink, which a weaker model needs and a stronger
one mostly knows, and contract discipline, which neither has by default.

No-harm is the axis neither model handles well, guided or not, and the cause is now consistent
across three judge models: both models add a restriction the sink's contract never asked for - a
hostname allowlist, a timeout, a size cap - and the rubric counts that as a change. The entries
stopped prescribing that in run 18, and the arms supply it from their own priors, so editing the
entries further will not move it.

By language, unguided to guided within each run:

| Language | Cases | Sonnet fix_quality | Sonnet no_harm | Haiku fix_quality | Haiku no_harm |
| --- | --- | --- | --- | --- | --- |
| C | 22 | 1.95 → 2.00 | 1.86 → 1.95 | 1.91 → 1.89 | 1.77 → 1.74 |
| C++ | 19 | 1.98 → 2.00 | 1.84 → 1.91 | 1.95 → 1.95 | 1.89 → 1.95 |
| C# | 54 | 1.85 → 1.94 | 1.54 → 1.73 | 1.66 → 1.79 | 1.61 → 1.64 |
| Go | 43 | 1.93 → 1.98 | 1.76 → 1.71 | 1.58 → 1.78 | 1.65 → 1.70 |
| Java | 86 | 1.84 → 1.85 | 1.71 → 1.72 | 1.73 → 1.87 | 1.66 → 1.68 |
| JavaScript | 48 | 1.91 → 1.99 | 1.59 → 1.75 | 1.78 → 1.88 | 1.64 → 1.56 |
| Perl | 4 | 2.00 → 1.83 | 1.92 → 2.00 | 2.00 → 1.75 | 2.00 → 1.92 |
| PHP | 44 | 2.00 → 1.95 | 1.77 → 1.76 | 1.77 → 1.98 | 1.68 → 1.76 |
| Python | 52 | 2.00 → 1.96 | 1.69 → 1.74 | 1.75 → 1.94 | 1.62 → 1.71 |
| All | 372 | 1.92 → 1.94 | 1.70 → 1.76 | 1.74 → 1.88 | 1.67 → 1.69 |

Haiku's fix-quality gains are largest where a language has a lot of library surface to get wrong:
PHP 1.77 to 1.98, Go 1.58 to 1.78, Python 1.75 to 1.94, Java 1.73 to 1.87. Sonnet starts near the
ceiling in those same languages and gains little, taking its improvement on no-harm in C# and
JavaScript instead. C and C++ are near the ceiling for both models unguided, so guidance has
almost nothing to add.

Ten of the 36 cells lose ground, and the size separates them. Six move by 0.05 or less, among them
Sonnet's PHP and Python fix quality, which start at exactly 2.00 unguided and so have nowhere to
go but down; the largest of that group is Sonnet's Go no-harm, 1.76 to 1.71, on fixes that swap a
library and change what the caller receives. Four moves are bigger, and one of those is Haiku's
JavaScript no-harm, 1.64 to 1.56, the same library-swap shape.

The other three are all Perl, and Perl is a defect rather than sampling noise. All four Perl cases
are CWE-79, and on one of them every guided write-up produced
`encode_entities($cgi->param('note'))`, which takes fix quality to 1.83 for Sonnet and 1.75 for
Haiku. `param()` returns every value of a repeated parameter in list context, so
`?note=<payload>&note=q` calls `encode_entities('<payload>', 'q')`, where the second value becomes
the unsafe-character set and the payload is emitted unescaped - confirmed here against real
HTML::Entities. The entry named list context and the second argument separately without ever
connecting them, and prescribed the vulnerable shape; it now prescribes forcing scalar context.
Unmeasured, since it postdates the run. See `evals/RESULTS-v20.md` and `evals/RESULTS-v21.md`.

Nineteen earlier runs built the harness and shaped the entries: the frozen unguided control, the
stated contract in the judge's header, bundled judging by a restricted agent, the compile gate, and
the entry sweeps that runs 18 and 19 measured. Runs 17 to 19 are recorded in the evals repository;
runs 1 to 16 were removed at the run-17 boundary, where the corpus and format stopped sharing a
scale with them, and remain in its git history. `evals/HARNESS.md` keeps what they all taught, and
`evals/README.md` carries the per-run table.
