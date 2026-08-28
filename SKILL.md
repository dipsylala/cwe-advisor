---
name: cwe-advisor
description: Educate developers about CWE vulnerabilities and guide remediation using a local knowledge base. Use when a developer mentions a CWE ID, a vulnerability name (e.g. SQL injection, XSS, path traversal, command injection, CSRF, deserialization), a SAST/DAST finding, or asks how to fix insecure code. Resolves vulnerability names to CWE IDs automatically, explains the weakness, and offers a fix - applied directly in interactive use, or proposed as a structured record for unattended/CI runs.
---

# CWE Advisor

## Workflow

When a CWE issue is raised, follow the steps below.

### Operating Mode

Default to **interactive mode**: a developer is present to answer questions and confirm fixes, so follow every step as written.

Switch to **autonomous mode** when the invocation makes clear no human is available to respond - a batch of findings, a CI/pipeline run, or an explicit instruction to process without confirmation. In autonomous mode:

- Resolve ambiguities that would otherwise prompt a question (Step 1's CWE/description mismatch, Step 3's uncertain language inference) using the best-supported interpretation, and record the assumption in the output instead of asking.
- Skip Step 5's Tone guidance and confirmation gate - see Step 5 for the autonomous output format.

### Step 1: Identify the CWE ID

Extract the CWE number from the user's message (e.g. "CWE-89", "CWE 89", or just "89").

- If a CWE number is given and no description conflicts with it, use it and proceed to Step 2.
- If a CWE number and a description are both given but don't match, flag the discrepancy and ask which one they intended before proceeding.
- If only a description or vulnerability name is given (no CWE number), resolve it using [references/cwe-identifier.md](references/cwe-identifier.md).

### Step 2: Load General Guidance

Read the top-level index: `cwe/{CWE_ID}/INDEX.md`

(Paths are relative to the directory containing this SKILL.md.)

If the file doesn't exist, tell the user this CWE isn't in the knowledge base. You may explain what class of vulnerability the CWE ID belongs to (e.g., injection, broken auth) and recommend the user consult the MITRE CWE entry. Do not propose specific code changes.

Some entries route rather than remediate: MITRE marks the ID Discouraged or Prohibited for mapping, so the guidance names a more specific child weakness instead of carrying the fix (CWE-20, CWE-119 and CWE-269 are the common cases). When the loaded guidance routes to a child CWE that matches the finding, read that child's `cwe/{CWE_ID}/INDEX.md` as well, treat it as the primary guidance, and use the child's ID for the language lookup in Step 3. Take one hop only, and keep the parent's guidance for context. If the child's directory doesn't exist, continue with the parent.

### Step 3: Load Language-Specific Guidance

If code or a platform configuration/manifest file (e.g., `AndroidManifest.xml`) is provided, infer the language or platform from file extensions, syntax, or manifest files. If inference is uncertain (e.g., C vs. C++, JavaScript vs. TypeScript), ask the user to confirm. Map the confirmed language to the subfolder using the table below:

| Language        | Subfolder    |
|-----------------|--------------|
| C#              | `csharp`     |
| JavaScript / TS | `javascript` |
| Java            | `java`       |
| Python          | `python`     |
| PHP             | `php`        |
| C               | `c`          |
| C++             | `cpp`        |
| Go              | `go`         |
| Ruby            | `ruby`       |
| Perl            | `perl`       |

C++ findings prefer `cpp/`; where a CWE has no `cpp/` folder, use `c/`. When C++ code manipulates raw buffers through C library calls, read both.

If the language is not listed above, check whether a matching lowercase subfolder exists under the CWE directory (e.g., `go/`, `rust/`) and use it if found.

Some findings are rooted in a platform manifest or configuration file rather than in program source code - for example, an Android component-export finding (CWE-926) lives in `AndroidManifest.xml`, not in the Kotlin/Java source that happens to sit alongside it. When the finding concerns a platform configuration file, check for a platform-named subfolder under the CWE directory (e.g., `android/`) instead of the inferred source-language subfolder. Keep platform guidance under its own platform name rather than folding it into a language subfolder. If guidance exists for both the platform (the manifest/config fix) and the language (any code-level handling) for the same CWE, load both.

Check whether the subfolder exists, then read it: `cwe/{CWE_ID}/{language}/INDEX.md`

If no language or platform subfolder exists, rely solely on the general guidance from Step 2.

### Step 4: Trace the Data Flow

Before proposing a fix, trace the data flow from source to sink. Use the best available method:

**Option A - SAST/DAST-provided data path (preferred)**

If a SAST/DAST report includes a call path or taint trace for the finding, or the tool can be queried to retrieve one, use it directly - this also covers an existing data-flow or call-graph result already attached to the conversation. Extract the source, sink, and any intermediate steps directly from that output. Skip to Step 5 once you have a clear picture.

**Option B - LLM-navigated trace (fallback)**

If no SAST/DAST-provided path is available, trace the flow yourself. Follow the steps in [references/data-flow-trace.md](references/data-flow-trace.md), using code navigation tooling (e.g. `find_all_references`, `go_to_definition`, symbol search) to speed things up where available, or reading the code directly otherwise.

**When the trace shows no exploitable path (either option)**

The trace may show the finding is not exploitable as reported: the value is constrained or validated before it reaches the sink, the sink is unreachable, or the source is not attacker-controlled. That is a legitimate result in both modes. Report it instead of fixing, name the specific link in the chain that breaks, and do not modify code. In interactive mode, suggest the developer suppress the finding with a documented justification; in autonomous mode, emit the record in [references/autonomous-output.md](references/autonomous-output.md) with no proposed fix.

Hold this to the same standard as a fix. "I could not follow the path" is not the same finding as "there is no path" - say which one it is, and never report the first as the second.

**Allowlist fix points (either option)**

When a fix validates untrusted input against an allowlist, treat the validation as a transformation, not only a gate. Do not keep passing the original tainted value downstream after a successful check; select the matching canonical value from the allowlist or a server-controlled map, assign it to a fresh variable, and use that trusted value for later sinks.

### Step 5: Offer a Fix

Summarise the vulnerability and the data flow findings.

- **Interactive mode**: read [references/tone.md](references/tone.md) and follow it when presenting the findings and fix. Ask the developer if they would like a fix applied before making any code changes. If they decline, summarise the risk and the recommended safe pattern for their reference, then ask if they have questions about the finding. Only proceed with a fix once they confirm.
- **Autonomous mode**: skip the confirmation and do not modify code. Emit the structured proposal described in [references/autonomous-output.md](references/autonomous-output.md) instead of presenting steps 1-4 below.

Present the fix (interactive mode) or populate the proposal's fix fields (autonomous mode) in this order:

1. **Library recommendation** (if the guidance names a specific library for the fix):
   - Give a minimum safe version only when the loaded guidance carries one. Do not supply a version number from your own recall - version and CVE metadata is what models get confidently wrong, and it is the part a developer pastes into a manifest without re-checking. Where the guidance names no version, name the library and say the version has to come from advisory or SCA data.
   - Where the guidance records that a library has no fixed release, say so and name the replacement it points to. An upgrade instruction is wrong in that case, and "use the latest version" is not a fix.
   - Never recommend a library or version you have reason to believe is vulnerable.
   - Show the exact change needed in the manifest file (e.g. updated version string in `pom.xml` or `package.json`) where the fix is a version bump, or the dependency swap where it is a replacement.
   - This is guidance, not a live vulnerability scan - tell the developer to confirm the resolved version against SCA/dependency-check tooling before merging.
2. **Vulnerable code** - show the code with a comment marking the problem.
3. **Fixed code** - show the code using the safe pattern from the guidance, applied at the point identified in Step 4.
   - When applying the fix, match the existing codebase's indentation, naming conventions, import organization, and formatting - unless the style itself introduces a security issue.
4. **Explanation** - one paragraph explaining what changed and why it eliminates the weakness. If both a library recommendation and a code change are required, clarify which part each fix addresses - the library version may close the CVE but the code-level safe pattern is still needed to enforce correct usage.

If the fix uses an allowlist, apply the canonical-value substitution described in Step 4 - the fixed code must use the value selected from the allowlist, not the original tainted input, downstream.

Always prefer the language-specific safe pattern over the general one when both are available.

#### After the Fix (interactive mode only)

After the fix is applied, suggest the developer:
1. Re-run their scanner (and SCA tool, if a library recommendation was part of the fix) to verify the finding is closed.
2. If possible, test the fixed code locally (unit tests, integration tests, or manual testing) to confirm it works as intended and does not introduce regressions.

## Notes

- Never guess a fix - always base it on the loaded guidance.
- If the INDEX.md file exists but is empty or contains no actionable guidance, treat it as if the file does not exist.
- If the user's code spans multiple languages, handle each language separately.
- If the user provides multiple CWE IDs, process them one at a time in the order given. Complete the full workflow for each before moving to the next, unless the user asks for a summary-only pass.
- If the user asks a conceptual question without providing code, load the general guidance (Step 2) and explain the vulnerability class, common patterns, and remediation strategy. Skip the language-specific step and the fix offer.
