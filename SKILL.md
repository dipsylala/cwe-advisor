---
name: cwe-advisor
description: Educate developers about CWE vulnerabilities and guide remediation using a local knowledge base. Use when a developer mentions a CWE ID, a vulnerability name (e.g. SQL injection, XSS, path traversal, command injection, CSRF, deserialization), a SAST/DAST finding, or asks how to fix insecure code. Maps vulnerability names to CWE IDs automatically. Explains the vulnerability, teaches underlying security concepts, and optionally applies fixes to the developer's code.
---

# CWE Advisor

## Quick Start

When a developer reports a CWE issue, follow the workflow below.

## Workflow

### Step 1: Identify the CWE ID

Extract the CWE number from the user's message (e.g. "CWE-89", "CWE 89", or just "89").
If only a description is given, ask the user to confirm the CWE number.
If the user provides a CWE number and a description that don't match, flag the discrepancy and ask which one they intended before proceeding.

### Step 2: Load General Guidance

Read the top-level index:

```
{CWE_ID}/INDEX.md
```

(Paths are relative to the directory containing this SKILL.md.)

If the file doesn't exist, tell the user this CWE isn't in the knowledge base. You may explain what class of vulnerability the CWE ID belongs to (e.g., injection, broken auth) and recommend the user consult the MITRE CWE entry. Do not propose specific code changes.

### Step 3: Load Language-Specific Guidance

If code is provided, infer the language from file extensions, syntax, or manifest files. If inference is uncertain (e.g., C vs. C++, JavaScript vs. TypeScript), ask the user to confirm. Map the confirmed language to the subfolder using the table below:

| Language        | Subfolder    |
|-----------------|--------------|
| C#              | `csharp`     |
| JavaScript / TS | `javascript` |
| Java            | `java`       |
| Python          | `python`     |
| PHP             | `php`        |
| C / C++         | `c`          |
| Ruby            | `ruby`       |
| Perl            | `perl`       |

If the language is not listed above, check whether a matching lowercase subfolder exists under the CWE directory (e.g., `go/`, `rust/`). If it exists, use it. If not, rely solely on the general guidance from Step 2.

Check whether the subfolder exists, then read it:

```
{CWE_ID}/{language}/INDEX.md
```

If no language subfolder exists, rely solely on the general guidance from Step 2.

### Step 4: Check Library Dependencies

After loading the guidance, check whether the loaded guidance (Steps 2–3) references any specific third-party library by name (e.g. SnakeYAML, Jackson, Log4j, OpenSSL, Newtonsoft.Json). If it does, **you must offer** to run an SCA scan or read existing SCA results for that library before proceeding.

**Ask:** *"The guidance references [library name]. Would you like me to check whether the version in use is safe - either by running an SCA scan or reading any existing SCA results?"*

**When to skip this step:** If the developer indicates they have already verified the dependency version, or if the guidance mentions a library as a general example (not a specific recommendation for their stack), you can skip the detailed SCA check.

If the guidance does not name a specific library, skip the rest of this step and proceed to Step 5.

If the developer agrees, gather dependency information in this order:

**Option A — Use an available SCA skill (preferred)**

1. Check the list of loaded skills and available MCP servers. If any skill or server provides SCA or dependency-analysis capabilities (e.g. Veracode, Snyk, Trivy), invoke it to retrieve dependency findings relevant to the libraries mentioned in the guidance. Extract:
   - Library name and version currently in use
   - Whether the version is flagged as vulnerable (CVE or advisory)
   - The minimum safe version recommended by the tool
   - If the SCA skill returns an error or no results, fall back to Option B below and note that the SCA scan was unavailable.

**Option B — Read manifest files (fallback)**

Search the workspace for dependency manifests and read the relevant library versions:

| Ecosystem   | Files to check                                          |
|-------------|---------------------------------------------------------|
| Java        | `pom.xml`, `build.gradle`, `build.gradle.kts`           |
| JavaScript  | `package.json`, `package-lock.json`, `yarn.lock`        |
| Python      | `requirements.txt`, `pyproject.toml`, `Pipfile`         |
| C#          | `*.csproj`, `packages.config`, `Directory.Packages.props` |
| PHP         | `composer.json`, `composer.lock`                        |
| C / C++     | `vcpkg.json`, `conanfile.txt`, `CMakeLists.txt`         |

Extract the declared version of any library referenced in the guidance. If multiple manifests exist, prefer lock files over loose version ranges. If a lock file and a manifest declare different versions for the same library, use the lock file version and note the discrepancy to the user.

**After gathering dependency information:**

1. Note which libraries are relevant to the finding.
2. If a vulnerable version is detected, record the vulnerable version and the safe upgrade target. Carry this into Step 6 so the fix includes both the library upgrade and the code-level remediation.
3. If a library upgrade is required but the developer indicates it is blocked by broader dependency constraints, acknowledge this directly. Note that a code-level workaround might be possible (or might not, depending on the vulnerability), so the developer can plan escalation early.
4. If the version cannot be determined (no manifest found, no SCA output), flag this and recommend the developer verify it manually.

### Step 5: Trace the Data Flow

Before proposing a fix, trace the data flow from source to sink. Use the best available method:

**Option A — Use available tooling (preferred)**

If any of the following are available, use them first:
- A SAST/DAST report that includes a call path or taint trace for the finding
- Code navigation tools (e.g. `find_all_references`, `go_to_definition`, symbol search) to follow the variable through the call graph
- An existing data-flow or call-graph result attached to the conversation

If any of these are available, extract the source, sink, and any intermediate steps directly from that output. Skip to Step 6 once you have a clear picture.

**Option B — Manual trace (fallback)**

If no tooling or results are available, trace the flow by hand:

1. **Start at the sink** — locate the exact operation the scanner flagged (e.g. SQL query, shell exec, file write). This is your fixed reference point.
2. **Trace backwards** — follow the data through function calls, assignments, and transformations back towards the entry point. Note every place the value passes through without validation or sanitisation — these are candidate fix points.
3. **Identify the source** — where does the untrusted input originally enter the application (HTTP request, file, environment variable, IPC, etc.)?
4. **Find the best fix point** — the first trust boundary the data crosses (e.g., HTTP handler, CLI parser, file reader) where input can be validated before reaching any sink. If no clear trust boundary exists, choose the earliest function in the call chain where the raw input is available in a form that can be validated.
5. **Break taint after allowlist validation** — when a fix validates untrusted input against an allowlist, treat the validation as a transformation, not only a gate. Do not keep passing the original tainted value downstream after a successful check; select the matching canonical value from the allowlist or a server-controlled map, assign it to a fresh variable, and use that trusted value for later sinks.
6. **Forward pass for other sinks** — from that fix point, briefly check whether the same input flows to any other dangerous operations that would also need covering.

Either way, the goal is the same: determine where to apply the fix and whether a single change is sufficient.

### Step 6: Offer a Fix

#### Tone

Security findings often arrive as unexpected mandatory blockers. Developers may feel defensive, sceptical about exploitability, or daunted by the migration effort involved. When presenting findings and fixes:

- **Lead with the path forward**, not the severity. The developer knows it must be addressed; focus on how.
- **Acknowledge migration cost** — replacing a serializer, refactoring an auth flow, or switching a crypto primitive is real work. Say so plainly rather than making it sound trivial.
- **Use calm, precise language** — avoid alarm phrasing like "DANGEROUS" or "critical vulnerability". Prefer: "this pattern is unsafe because X, and the fix is Y."
- **Validate pushback on exploitability** — if a developer argues their context reduces risk ("this is internal-only"), acknowledge the point before explaining why the safe pattern is still the right path regardless.
- **Handle false-positive claims** — if the developer provides evidence that the finding is a false positive (e.g., the input is already validated upstream, the sink is unreachable), re-examine the data flow with that context. If the trace confirms no exploitable path, acknowledge the false positive and suggest the developer suppress the finding with a documented justification.
- **Don't assign blame** — frame findings as patterns to update, not mistakes to own.

The goal is a developer who understands the problem and feels equipped to fix it, not one who is alarmed or defensive.

---

Summarise the vulnerability and the data flow findings, then **ask the developer if they would like a fix applied** before making any code changes.

If the developer declines, summarise the risk and the recommended safe pattern for their reference, then ask if they have questions about the finding.

Only proceed with a fix once they confirm. Present the fix in this order:

1. **Library upgrade** (if a vulnerable library version was identified in Step 4):
   - State the current version, the vulnerability (CVE or advisory if known), and the minimum safe version.
   - Show the exact change needed in the manifest file (e.g. updated version string in `pom.xml` or `package.json`).
2. **Vulnerable code** — show the code with a comment marking the problem.
3. **Fixed code** — show the code using the safe pattern from the guidance, applied at the point identified in Step 5.
   - When applying the fix, match the existing codebase's indentation, naming conventions, import organization, and formatting — unless the style itself introduces a security issue.
4. **Explanation** — one paragraph explaining what changed and why it eliminates the weakness. If both a library upgrade and a code change are required, clarify which part each fix addresses — the library upgrade may close the CVE but the code-level safe pattern is still needed to enforce correct usage.

If the fix uses an allowlist, the fixed code must use the value selected from the allowlist downstream. Avoid patterns that check `allowed.Contains(input)` or `allowed.includes(input)` and then pass `input` to the sink; prefer lookup or map patterns that return a canonical allowed value and pass that trusted value onward.

Always prefer the language-specific safe pattern over the general one when both are available.

#### After the Fix

After the fix is applied, suggest the developer:
1. Re-run their scanner to verify the finding is closed.
2. If possible, test the fixed code locally (unit tests, integration tests, or manual testing) to confirm it works as intended and does not introduce regressions.

## Notes

- Never guess a fix — always base it on the loaded guidance.
- If the INDEX.md file exists but is empty or contains no actionable guidance, treat it as if the file does not exist.
- If the user's code spans multiple languages, handle each language separately.
- If the user provides multiple CWE IDs, process them one at a time in the order given. Complete the full workflow for each before moving to the next, unless the user asks for a summary-only pass.
- If the user asks a conceptual question without providing code, load the general guidance (Step 2) and explain the vulnerability class, common patterns, and remediation strategy. Skip the language-specific step and the fix offer.
- After applying the fix, suggest the developer re-run their scanner and SCA tool to verify.
