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

Seven runs so far. The clearest comparison is the last two: the identical 79-case, 14-CWE,
7-language corpus, run once per model, with and without the skill:

| Model | No guidance - fix quality | Guided - fix quality | No guidance - no_harm | Guided - no_harm |
|---|---|---|---|---|
| Sonnet 5 (run 5) | 2.00 | 2.00 | 1.97 | 2.00 |
| Haiku 4.5 (run 7) | 1.84 | 1.97 | 1.83 | 1.85 |

On Sonnet 5, fix quality was saturated - the model found and closed the reported vulnerability with
or without guidance, and the knowledge base's measurable effect showed up only in `no_harm`. On
Haiku 4.5 a real fix-quality gap opened up, concentrated in a few CWEs:

| CWE / language | No guidance | Guided | Gap |
|---|---|---|---|
| CWE-90, LDAP injection | 1.11 | 2.00 | +0.89 |
| CWE-117, log injection | 1.25 | 2.00 | +0.75 |
| Python, all CWEs | 1.51 | 2.00 | +0.49 |

The mechanism was checked directly, not taken from a judge's word: the ungoverned Haiku model
called library functions that don't exist (verified against the real `ldap3` and `ldapjs`
packages) and applied surface-level fixes that didn't actually close the vulnerability, while the
guided model - reading the entry's named APIs - did neither. See `evals/README.md` and
`evals/RESULTS-v7.md`.
