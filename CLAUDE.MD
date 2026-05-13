# CLAUDE.MD

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
- Language folders are lowercase ecosystem names. Existing folders include `c`, `csharp`, `java`, `javascript`, `perl`, `php`, `python`, and `ruby`.
- Language-specific files supplement the root guidance; they do not replace it.

## Authoring Principles

- Write for an LLM that will edit real developer code. Prefer direct remediation instructions over background explanation.
- Keep each sentence useful for fixing code. Avoid repeating generic security facts the model already knows.
- General CWE files should be guidance-only and should not include code examples.
- Language-specific files should include a minimal `Safe Pattern` section with correct API usage.
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
4. `## Remediation Steps`
5. `## Safe Pattern`

Content expectations:

- Mention real APIs, functions, classes, annotations, framework settings, or package names.
- Name common vulnerable sinks and safe replacement APIs for that language.
- If the safe pattern requires a specific library, package, or framework component, identify that dependency by name and prefer maintained, commonly used options.
- Show the smallest useful safe example. Include imports only when they clarify the API surface.
- Mark examples with comments such as `SAFE:`. Include unsafe examples only when they materially improve contrast.
- Prefer modern framework-native protections, but account for common legacy APIs when they are likely scanner findings.

## Maintenance Workflow

1. Confirm the CWE ID and vulnerability name against the existing directory naming pattern.
2. Check whether `{CWE_ID}/INDEX.md` already exists before creating a new directory.
3. Read nearby or related entries for tone and specificity, for example injection, XSS, path traversal, CSRF, or crypto entries.
4. Create or update the root guidance first.
5. Add only the language folders that have meaningful, language-specific guidance.
6. Keep code samples short, syntactically valid, and focused on safe remediation.
7. For entries that mention third-party libraries, check that the guidance supports a future dependency version review.
8. Review for duplicated generic explanation, missing source/sink tracing, vague validation advice, and unsupported framework claims.
9. Verify Markdown paths and headings before finishing.

## Quality Checklist

- The root file teaches the vulnerability class without relying on code snippets.
- Language files name concrete APIs and safe replacement patterns.
- Remediation steps start with locating the source, sink, and data flow.
- The fix guidance distinguishes primary defences from secondary validation or hardening.
- Named library guidance makes dependency version checks possible.
- Safe patterns do not introduce unrelated vulnerabilities.
- The entry is concise enough to be loaded as LLM context.
- New languages use existing folder names when applicable.

## Editing Existing Entries

- Preserve the scope of the requested change.
- Do not rewrite unrelated sections just to normalize style.
- If an entry has clear correctness issues, fix them directly and keep the diff small.
- When adding a language-specific file, make sure it agrees with the root CWE guidance and does not contradict sibling language entries.
