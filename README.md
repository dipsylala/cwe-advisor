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

Ten runs so far. Sonnet 5 saturates fix quality regardless of guidance, on both the original
79-case corpus (run 5) and the full 203-case one (run 9); the current Haiku 4.5 result, on the same
full corpus, is a small edge for guidance:

| Model | Corpus | No guidance - fix_quality | Guided - fix_quality | No guidance - no_harm | Guided - no_harm |
| --- | --- | --- | --- | --- | --- |
| Sonnet 5 (run 9) | 203 cases | 1.98 | 1.98 | 1.88 | 1.91 |
| Haiku 4.5 (run 10) | 203 cases | 1.85 | 1.90 | 1.87 | 1.83 |

An earlier Haiku run (run 7, a smaller 79-case corpus) had found a larger fix-quality gap
(1.84 vs. 1.97), driven by the ungoverned model calling library functions that don't exist - verified
against the real `ldap3` and `ldapjs` packages, not taken from a judge's word. That gap shrank to a
near-tie once the corpus nearly tripled (run 8): guidance still helped on most of the added cases,
but on three entries the guidance itself caused the kind of defect it exists to prevent - a Java API
call missing a required argument the entry never stated, a JavaScript fix that embedded a raw
Unicode character the entry never showed how to escape, and a C# CSRF fix that left a JSON endpoint
unvalidated because the entry didn't say the middleware it named doesn't cover that case. All three
are now fixed, and run 10 re-ran the identical corpus and model pairing to check: two of the three
closed cleanly, verified case-by-case against the actual re-generated code (not just the aggregate
number moving) - the third recovered partially, since Haiku independently made the same
Unicode-escaping mistake again in fresh code even once the guidance text was already correct. See
`evals/README.md`, `evals/RESULTS-v9.md`, and `evals/RESULTS-v10.md`.
