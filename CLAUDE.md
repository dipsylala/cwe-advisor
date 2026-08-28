# CLAUDE.md

This repository is a local CWE remediation knowledge base used by the `cwe-advisor` skill. Each entry teaches an LLM how to help a developer remediate one CWE, with optional language-specific guidance.

## Repository Shape

```text
{CWE_ID}/
  INDEX.md
  {language}/
    INDEX.md
```

- CWE directories are numeric only, for example `89/` or `352/`.
- The root `{CWE_ID}/INDEX.md` is language-agnostic guidance.
- Language folders are lowercase ecosystem names. Existing folders include `c`, `cpp`, `csharp`, `java`, `android`, `javascript`, `perl`, `php`, `python`, `go`, and `ruby`.
- Language-specific files supplement the root guidance; they do not replace it.
- [references/cwe-identifier.md](references/cwe-identifier.md) maps vulnerability names and common industry synonyms (e.g. "SQLi", "XSS", "SSRF") to CWE IDs, so SKILL.md Step 1 can resolve a description without asking the developer to look up the number.

## SKILL.md Maintenance

SKILL.md is loaded in full on every invocation, so keep it a thin workflow driver rather than a repository for procedural detail.

- Keep guidance that applies on every invocation (e.g. the Operating Mode determination) inline in SKILL.md - moving it out would mean it's sometimes skipped.
- Move step-specific procedural detail and data that a step's happy path never touches into `references/*.md`, and link to it from the step - see [references/data-flow-trace.md](references/data-flow-trace.md) for the Step 4 fallback, [references/cwe-identifier.md](references/cwe-identifier.md) for Step 1's no-CWE-number path, [references/tone.md](references/tone.md) for Step 5's interactive-mode presentation guidance, and [references/autonomous-output.md](references/autonomous-output.md) for Step 5's autonomous-mode output format. The deciding factor is whether a single invocation needs it, not how often the branch is taken in aggregate across invocations.
- When a `references/*.md` file is added, removed, or renamed, update the link in SKILL.md and rerun `python scripts/lint.py` to catch broken links.

## Authoring Principles

Write to teach the LLM what to do, not what it already knows - every sentence should add information it cannot reliably infer on its own.

- Write for an LLM that will edit real developer code. Prefer direct remediation instructions over background explanation.
- Keep each sentence useful for fixing code. Avoid repeating generic security facts the model already knows.
- Guide, don't dictate: describe the approach - what to locate, what pattern to replace, what mechanism to use - so the LLM reasons its way to an idiomatic, context-aware fix rather than copying a provided snippet verbatim.
- Cover the common case, not the encyclopaedia: target the most common, highest-impact form of the vulnerability. Omitting edge cases and exotic scenarios is intentional - covering them lengthens the entry without improving the fix rate for typical findings.
- General CWE files should be guidance-only and should not include code examples.
- Language-specific files are prose. Concrete syntax goes inline in a bullet, not in a code block.
- Prefer vendor-neutral guidance in root files and framework/API-specific guidance in language files.
- Be prescriptive about sources, sinks, data flow, replacement patterns, validation, and verification.
- When guidance depends on a named third-party library, name it explicitly so future remediation can include an SCA or manifest version check.
- Use calm, precise remediation language. Lead with the path forward and avoid alarm phrasing or blame.
- Keep root guidance under about 500 words and language guidance under about 800 words.
- Use ASCII unless an existing file already uses non-ASCII terminology that needs to be preserved.

## Root CWE File

Create `{CWE_ID}/INDEX.md` from [templates/general-cwe.md](templates/general-cwe.md).

Required sections:

1. `# CWE-{ID}: {Vulnerability Name}`
2. `## LLM Guidance`
3. `## Key Principles`
4. `## Remediation Steps`

Content expectations:

- `LLM Guidance`: 2-4 concise sentences explaining how the weakness appears and the core remediation strategy.
- `Key Principles`: 4-6 bullets covering the primary defence, what to avoid, input/output handling, and defence-in-depth.
- `Remediation Steps`: 4-8 ordered-by-workflow bullets from locating the issue through testing the fix.

Use `Remediation Steps` for new files. Some older entries use `Actionable Steps`; do not copy that heading into new guidance unless intentionally preserving an existing file's structure during a narrow edit.

## Language-Specific File

Create `{CWE_ID}/{language}/INDEX.md` from [templates/language-cwe.md](templates/language-cwe.md).

Required sections:

1. `# CWE-{ID}: {Vulnerability Name} - {Language}`
2. `## LLM Guidance`
3. `## Key Principles`
4. `## Taint Sinks`
5. `## Remediation Steps`

Content expectations:

- Mention real APIs, functions, classes, annotations, framework settings, or package names.
- Name common vulnerable sinks and safe replacement APIs for that language.
- `Taint Sinks`: a short, comma-separated list of the concrete function/method/API names that are the dangerous operation for this CWE in this language (as inline code), so an LLM tracing data flow can search for them with whatever tool it has - grep, symbol search, or otherwise. Reference data, not prose explanation; do not restate it as a sentence elsewhere in the file.
- If the fix requires a specific library, package, or framework component, identify that dependency by name and prefer maintained, commonly used options.
- Language files carry no code blocks. Put concrete syntax - API names, argument shapes, magic string formats such as `"host:port:ip"`, escape values, a callback's required return - as inline code inside a `Key Principles` or `Remediation Steps` bullet.
- Prose carries what a sample cannot: why an order matters, what a check collides with, which branch applies. That generalizes to the developer's actual code, where a sample only exhibits one instance of the fix and dates faster than the prose around it.
- Prefer modern framework-native protections, but account for common legacy APIs when they are likely scanner findings.

## Maintenance Workflow

1. Confirm the CWE ID and vulnerability name against the existing directory naming pattern.
2. Check whether `{CWE_ID}/INDEX.md` already exists before creating a new directory.
3. Read nearby or related entries for tone and specificity, for example injection, XSS, path traversal, CSRF, or crypto entries.
4. Create or update the root guidance first.
5. Add only the language folders that have meaningful, language-specific guidance.
6. Keep concrete syntax as inline code inside a bullet; neither root nor language files carry code blocks.
7. For entries that mention third-party libraries, check that the guidance supports a future dependency version review.
8. Review for duplicated generic explanation, missing source/sink tracing, vague validation advice, and unsupported framework claims.
9. Add or update the corresponding row in [references/cwe-identifier.md](references/cwe-identifier.md): CWE ID, official name, and any common industry synonyms a developer might type instead of the number. Leave the aliases column as `-` if the official name has no common shorthand - do not restate words already in the name.
10. Run `python scripts/lint.py` and fix any reported errors before finishing. It is a deterministic, non-LLM check for required headings, code fences in any entry, broken Markdown links, and `references/cwe-identifier.md` staying in sync with the CWE directories - it does not check writing quality or technical accuracy.

## Quality Checklist

- The root file teaches the vulnerability class without relying on code snippets.
- Language files name concrete APIs and safe replacement patterns.
- Remediation steps start with locating the source, sink, and data flow.
- The fix guidance distinguishes primary defences from secondary validation or hardening.
- Named library guidance makes dependency version checks possible.
- Recommended fixes do not introduce unrelated vulnerabilities.
- Concrete syntax an LLM cannot derive - argument shapes, string formats, escape values - is present as inline code rather than assumed.
- The entry is concise enough to be loaded as LLM context.
- New languages use existing folder names when applicable.
- The entry doesn't explain background the LLM already knows, repeat information covered elsewhere in the same entry, or replace guidance with a worked example where guidance alone would suffice.

## Editing Existing Entries

- Preserve the scope of the requested change.
- Do not rewrite unrelated sections just to normalize style.
- If an entry has clear correctness issues, fix them directly and keep the diff small.
- When adding a language-specific file, make sure it agrees with the root CWE guidance and does not contradict sibling language entries.
