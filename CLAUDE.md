# CLAUDE.md

This repository is a local CWE remediation knowledge base used by the `cwe-advisor` skill. Each entry teaches an LLM how to help a developer remediate one CWE, with optional language-specific guidance.

## Repository Shape

```text
cwe/
  {CWE_ID}/
    INDEX.md
    {language}/
      INDEX.md
```

- CWE directories are numeric only and all live under `cwe/`, for example `cwe/89/` or `cwe/352/`. Paths below are written relative to `cwe/` unless stated otherwise.
- The root `cwe/{CWE_ID}/INDEX.md` is language-agnostic guidance.
- Language folders are lowercase ecosystem names. Existing folders include `c`, `cpp`, `csharp`, `java`, `android`, `javascript`, `perl`, `php`, `python`, `go`, and `ruby`.
- Language-specific files supplement the root guidance; they do not replace it.
- `cwe/77/{language}` deliberately covers non-shell command interpreters only. `cwe/77/INDEX.md` routes shell sinks to CWE-78, so shell guidance belongs under `cwe/78/` and should not be duplicated into `cwe/77/`.
- [evals/](evals/) holds the validation harness: externally authored test cases, the pre-registered rubric, and run results. It is not part of the knowledge base and is skipped by the linter.
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

Create `cwe/{CWE_ID}/INDEX.md` from [templates/general-cwe.md](templates/general-cwe.md).

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

Create `cwe/{CWE_ID}/{language}/INDEX.md` from [templates/language-cwe.md](templates/language-cwe.md).

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

## Version and Advisory Claims

Version and advisory metadata is where entries have gone wrong most often - the errors cluster
here rather than in technical explanation, and it is the part a developer acts on without
re-checking. Every rule below comes from an error found in this repository.

- **Cite the release that shipped the fix, not the CVE record's affected range.** The two
  disagree. CVE-2024-1874's record reads "8.3.\* before 8.3.5" while the security release
  carrying the fix was 8.3.6. A release number is actionable; an affected-range boundary is
  off-by-one whenever the fix landed in the following patch.
- **State the operative floor, not the first fix.** A fix can be bypassed, and a fix can introduce
  a new weakness. CVE-2024-5585 defeated the CVE-2024-1874 fix; `gorilla/csrf` v1.7.3 closed
  CVE-2025-24358 and opened CVE-2025-47909; `net/http.CrossOriginProtection` needed Go 1.25.1
  after a bypass in 1.25.0. Give the version carrying the fix *and* every known bypass of it, and
  say why the earlier one is not enough.
- **A library may have no fixed release at all.** `gorilla/csrf` has none for CVE-2025-47909.
  Say so and name the replacement: an upgrade instruction is wrong there, and "use the latest
  version" is not a fix.
- **Distinguish deprecated, deprecated for removal, and removed.** Three states, and entries have
  confused all three. `libxml_disable_entity_loader()` is deprecated since PHP 8.0 and still
  present; `java.net.URL`'s public constructors are `@Deprecated(since="20")` without
  `forRemoval=true`; the `mysql_*` extension really was removed, in PHP 7.0. Calling a live API
  "removed" turns working code into a false finding, and calling a soft deprecation "for removal"
  overstates the migration's urgency.
- **Trace every version claim to the vendor, not to recall.** A release announcement, an advisory,
  or the API's own documentation. SKILL.md Step 5 forbids the model from supplying a version from
  its own knowledge, which only works if the entry carries one.

## Remediation Claims

Version metadata is where entries went wrong most often; this is where they went wrong next.
Twelve sweep batches traced 126 language entries to vendor sources and every one carried a
defect. Each rule below is a shape that recurred, stated as the check that would have caught it.

- **Apply the prescribed edit literally, to a real tree, before writing it down.** Three failure
  modes, all shipped. A *no-op*: `cwe/287/go` said to take the session with `gorilla/sessions`
  `store.New` rather than `store.Get` so a planted cookie is discarded, but `New` decodes the
  cookie and sets `IsNew = false` exactly as `Get` does. A *panic*: `cwe/306/go` prescribed a
  `grpc.UnaryInterceptor` and a chi `Use()` that both fail on code already carrying one. And an
  edit that *breaks the application*: `cwe/522/php` said to add `Deny from all` to `.htaccess`,
  which is Apache 2.2 syntax supplied in 2.4 only by the deprecated `mod_access_compat` and has
  no filename scoping of its own - written bare it denies the whole directory. Ask what the edit
  does when applied, not whether it is correct in principle.
- **State the default before prescribing a change to it.** `AllowAutoRedirect` is true; `fetch`
  follows redirects; `CURLOPT_FOLLOWLOCATION` is already off; Django autoescaping is on, so
  "enable autoescaping" is usually a no-op while the `|safe` marker is the live issue; PHP's
  `session.use_strict_mode` is off. An entry that omits the default cannot tell the model whether
  the finding is real.
- **Do not list the framework's own recommended API as a taint sink.** Eight instances so far:
  `user.IsInRole()`, which appears in Microsoft's own resource-based handler sample;
  `@login_not_required`, which Django requires on the login view; `__return_true`, which
  WordPress core's own notice prescribes for a public route; `PASSWORD_HASHERS` "strongest
  first", which would flag Django's shipped default. Each points the model at correct code.
  Deletion is not always the fix - grepping for the name can be how the exceptions get audited -
  but then the entry has to say what the finding is *not*.
- **Check what a prescribed test proves against the unfixed code.** `cwe/93/javascript` said to
  confirm no extra header appears; it does not appear either way, because Nodemailer replaces the
  CRLF with a space - meanwhile the envelope has been rewritten to the attacker alone.
  `cwe/80/javascript` tested with `<script>`, which `innerHTML` never executes. A test that
  passes before the fix verifies nothing.
- **Check the reasons, not only the conclusion.** All four CWE-88 entries argued for a
  first-character allowlist because a denylist "misses `--`, unicode dashes, and leading
  whitespace". `--` does begin with a dash, and getopt treats only ASCII `0x2D` as an option
  introducer. The advice was right and every stated reason was wrong, which a reread for
  plausibility passes.
- **A constant shared across a family behaves differently in each ecosystem.** bcrypt's 72-byte
  ceiling is one fact with five behaviours: PHP truncates silently, Spring throws on encode and
  skips the check on match, Go rejects with `ErrPasswordTooLong`, Python's `bcrypt` 5.0 raises
  where it used to truncate, and `bcryptjs` neither enforces nor documents it. A sentence written
  once and copied across the language files will be wrong in most of them.
- **Sweep doctrine across the family rather than file by file.** CWE-862 and CWE-863 disagreed on
  the status an ownership failure returns - 404 in one, 403 in the other - in both their `go` and
  `javascript` pairs. No per-file review finds that, because each file is internally consistent.
- **Prefer rejecting a bad value to stripping it.** Stripping turns the value into a different
  valid one: Nodemailer's CRLF-to-space rewrite produces RFC 5322 group syntax, so the injected
  recipient survives sanitization.
- **A named library can stop.** `bleach` ended maintenance in June 2026 with an open advisory
  that will never be fixed. "Use a sanitization library" needs the library checked for
  maintenance status, not just named.
- **A hardening flag's recommended level can be stale even where the file is otherwise correct.**
  `_FORTIFY_SOURCE=2` recurred across eight independently-authored C files (`170`, `242`, `477`,
  `676`, `134`) after already being corrected to `=3` in three siblings (`125`, `787`, `121`).
  Level 3 is a documented strict superset of level 2 (GCC 12+/glibc 2.35+ or Clang 9+/glibc
  2.33+, falling back to `=2` on older toolchains) with no downside beyond rare performance
  overhead - when a file recommends a weaker level of a tiered hardening flag, check whether the
  stronger level is a strict superset before treating the weaker one as sufficient, and sweep
  every sibling file for the same flag rather than fixing it once.

## Maintenance Workflow

1. Confirm the CWE ID and vulnerability name against the existing directory naming pattern.
2. Check whether `cwe/{CWE_ID}/INDEX.md` already exists before creating a new directory.
3. Read nearby or related entries for tone and specificity, for example injection, XSS, path traversal, CSRF, or crypto entries.
4. Create or update the root guidance first.
5. Add only the language folders that have meaningful, language-specific guidance.
6. Keep concrete syntax as inline code inside a bullet; neither root nor language files carry code blocks.
7. For entries that mention third-party libraries, check that the guidance supports a future dependency version review.
8. Review for duplicated generic explanation, missing source/sink tracing, vague validation advice, and unsupported framework claims.
9. When checking whether an entry already covers something, search for the claim rather than the term. A grep for a function name finds the lines naming it, not the sentence two lines above that states its status - a review finding was raised and withdrawn for exactly that, because the statement was worded "these functions" and matched no search for the function.
10. Add or update the corresponding row in [references/cwe-identifier.md](references/cwe-identifier.md): CWE ID, official name, and any common industry synonyms a developer might type instead of the number. Leave the aliases column as `-` if the official name has no common shorthand - do not restate words already in the name.
11. Run `python scripts/lint.py` and fix any reported errors before finishing. It is a deterministic, non-LLM check for required headings, code fences in any entry, broken Markdown links, and `references/cwe-identifier.md` staying in sync with the CWE directories - it does not check writing quality or technical accuracy.

## Quality Checklist

- The root file teaches the vulnerability class without relying on code snippets.
- Language files name concrete APIs and safe replacement patterns.
- Remediation steps start with locating the source, sink, and data flow.
- The fix guidance distinguishes primary defences from secondary validation or hardening.
- Named library guidance makes dependency version checks possible, and any version given is the operative floor traced to a vendor release or advisory.
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
- After editing a `Key Principles` bullet, read the whole file before committing. Patching per bullet is how an entry starts arguing with its own `Remediation Steps`, and the linter cannot see it - five entries were left self-contradicting that way.
