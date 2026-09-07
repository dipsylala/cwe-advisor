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

Sixteen runs so far. Sonnet 5 saturates fix quality regardless of guidance, on both the original
79-case corpus (run 5) and the 203-case one (run 9). The corpus has since grown to 372 cases, and
on Haiku 4.5 the current result - runs 13 to 15, after a round of guidance fixes traced from run
11 - is a modest fix-quality edge for guidance and, for the first time on Haiku, a level no_harm
score:

| Model | Corpus | No guidance - fix_quality | Guided - fix_quality | No guidance - no_harm | Guided - no_harm |
| --- | --- | --- | --- | --- | --- |
| Sonnet 5 (run 9) | 203 cases | 1.98 | 1.98 | 1.88 | 1.91 |
| Haiku 4.5 (run 10) | 203 cases | 1.85 | 1.90 | 1.87 | 1.83 |
| Haiku 4.5 (run 11) | 372 cases | 1.82 | 1.89 | 1.81 | 1.79 |
| Haiku 4.5 (run 13) | 372 cases | 1.79 | 1.88 | 1.76 | 1.77 |
| Haiku 4.5 (runs 13 + 14 composite) | 372 cases - run 13, with the 14 cases in the 4 slots fixed after it taken from run 14's post-edit sets | 1.79 | 1.90 | 1.75 | 1.78 |
| Haiku 4.5 (run 15) | 372 cases - the composite above re-judged as a frozen control beside a fresh guided sample, one panel | 1.75 | 1.89 | 1.72 | 1.73 |
| Haiku 4.5 (run 16) | 372 cases - same frozen control, fresh guided sample, scored by the new bundled judging protocol whose judges compile; comparable to the rows above only through the frozen sets | 1.74 | 1.84 | 1.67 | 1.66 |
| Haiku 4.5 (run 17) | 372 cases - fresh unguided and guided samples in the complete-file format, every fix compile-gated; a format boundary, so a new scale comparable to the rows above in direction only | 1.80 | 1.91 | 1.76 | 1.74 |

The Haiku history is a loop of measure, trace, fix, re-measure. Run 7 (79 cases) found a large
fix-quality gap (1.84 vs. 1.97), driven by the ungoverned model calling library functions that don't
exist - verified against the real `ldap3` and `ldapjs` packages. That shrank to a near-tie when the
corpus nearly tripled (run 8), because on three entries the guidance itself caused the defect it
exists to prevent; fixing them and re-running the identical corpus (run 10) recovered the cases
they were written for, checked against the re-generated code rather than the aggregate. Run 11
repeated the exercise on the 372-case corpus and traced the guided arm's remaining losses to eight
entries - most notably every CWE-502 entry leading with a wire-format swap (native serialization to
JSON) that silently empties existing data when the producers aren't in the change. Run 12 re-ran
just the 47 affected cases after the fixes (9 of 13 targets went to a clean score), and run 13
re-ran the whole corpus: on the 47 edited-slot cases the guided arm went 1.76/1.57 to 1.90/1.82
while the unguided control stayed flat, and on the 325 untouched cases both arms drifted down by the
same amount - which is the noise floor, not guidance.

Run 13 also changed the judging: judges now see each case's stated contract (`must_preserve`) and
score no_harm against it. The table above is the whole corpus; the effect is concentrated in the
98 cases (of 372) that carry a contract, where the unguided arm's no_harm fell from 1.83 in run 11
to 1.56 - fixes that silently truncate or clamp where the contract says reject - while the guided
arm held at 1.72. Averaged over all 372 cases that becomes the 1.76 vs. 1.77 in the table. That is the first guided no_harm edge seen on Haiku, and it was being hidden by
judges accepting silent truncation as clean. What remains is mostly model slips rather than entry
gaps - invented API names, wrong method signatures, a caller not updated - and on Haiku a guidance
bullet is a probability, not a switch: the same entry is followed in one sample and ignored in the
next. Run 13 also turned up four entry gaps in slots nothing had touched (a non-existent npm
package, a Flask import removed in 3.x, a missing AST node, a counter stored in the object it was
meant to validate); run 14 re-ran those 14 cases after fixing them and three of the four went to a
clean score, the fourth to 2.00/1.67.

Run 15 tested the cheapest fix for the model-slip bucket - a SKILL.md step asking the model to
source every name its fix introduces and reread the code as a compiler would - and found no effect:
24 cases carry a judge note about a non-existent or non-compiling identifier in the unguided arm, in
the guided arm before the step, and in the guided arm after it. That bucket needs a compile gate, not
prose. Run 15 also changed the design: the unguided arm is now a frozen sample re-judged beside each
new guided sample, so the row above differs from the composite row by the judge panel alone
(-0.01 to -0.04), the first time that contribution has been isolated.

Run 16 tried the next cheapest thing - the step now tells the model to copy the fix to scratch and
run the compiler - and found the same nothing: 68 of 372 agents ran any checker, the two inspected
ran it on the wrong file, and the slip count went 24 to 25. What did change in run 16 is the judging.
Judges now receive one prepared bundle per segment (write-ups plus case files), run as a restricted
agent with no web or MCP surface, and verify claims by building; identical frozen text scored
0.05 lower on no_harm under that panel because it catches compile errors the reading panel passed,
at about a third of the cost per write-up. So the rows for run 16 sit on a stricter scale than the
rows above it, and the frozen control is what makes them comparable. See `evals/README.md` and
`evals/RESULTS-v11.md` through `RESULTS-v17.md`.

Run 17 built the gate that prose could not: write-ups now carry every changed file in full, and a
script applies them to the fixture and runs the language's compiler or type checker. On fresh
Haiku 4.5 samples of both arms, 16 of 372 unguided and 18 of 372 guided fixes do not build - the
same one in twenty either way, but in different shapes. The unguided arm invents helper methods and
leaves Go variables unused; the guided arm reaches for the library the entry names and mis-imports
it, and four of its failures traced to two entries (`cwe/94/java`, `cwe/79/java`) naming a class
without its package, the first entry defects found by a compiler rather than a judge. Both are
fixed. Judged on the same fresh samples, guidance lifts fix quality from 1.80 to 1.91 (ahead on 64
cases, behind on 22) and leaves no-harm level at 1.76 against 1.74; the guided arm's no-harm losses
sit in allowlists the CWE-77, 78 and 90 entries prescribe and the rubric scores as narrowing, an
open doctrine question, and in whole-file rewrites that changed something beside the sink. The
gate caught eleven non-compiling fixes the three-judge panel passed unanimously and missed
nothing the judges caught, so from run 18 the judges take the gate's verdict and stop compiling.
See `evals/RESULTS-v17.md`.
