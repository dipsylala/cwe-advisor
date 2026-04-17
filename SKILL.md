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

### Step 2: Load General Guidance

Read the top-level index:

```
{CWE_ID}/INDEX.md
```

(Paths are relative to the directory containing this SKILL.md.)

If the file doesn't exist, tell the user this CWE isn't in the knowledge base and offer general advice.

### Step 3: Load Language-Specific Guidance

Detect the language from the provided code or ask. Map it to the subfolder name:

| Language        | Subfolder    |
|-----------------|--------------|
| C#              | `csharp`     |
| JavaScript / TS | `javascript` |
| Java            | `java`       |
| Python          | `python`     |
| PHP             | `php`        |
| C / C++         | `c`          |

Check whether the subfolder exists, then read it:

```
{CWE_ID}/{language}/INDEX.md
```

If no language subfolder exists, rely solely on the general guidance from Step 2.

### Step 4: Check Library Dependencies

After loading the guidance, check whether the loaded guidance (Steps 2–3) references any specific third-party library by name (e.g. SnakeYAML, Jackson, Log4j, OpenSSL, Newtonsoft.Json). If it does, **you must offer** to run an SCA scan or read existing SCA results for that library before proceeding.

**Ask:** *"The guidance references [library name]. Would you like me to check whether the version in use is safe — either by running an SCA scan or reading any existing SCA results?"*

If the guidance does not name a specific library, skip the rest of this step and proceed to Step 5.

If the developer agrees:

**Option A — Use an available SCA skill (preferred)**

Check whether any SCA or dependency-analysis skill is available in the current environment (e.g. a Snyk, OWASP Dependency-Check, Veracode, Trivy, or similar tool integration). If one is available, invoke it to retrieve dependency findings relevant to the libraries mentioned in the guidance loaded in Steps 2–3. Extract:
- Library name and version currently in use
- Whether the version is flagged as vulnerable (CVE or advisory)
- The minimum safe version recommended by the tool

**Option B — Read manifest files (fallback)**

If no SCA skill is available, search the workspace for dependency manifests and read the relevant library versions:

| Ecosystem   | Files to check                                          |
|-------------|---------------------------------------------------------|
| Java        | `pom.xml`, `build.gradle`, `build.gradle.kts`           |
| JavaScript  | `package.json`, `package-lock.json`, `yarn.lock`        |
| Python      | `requirements.txt`, `pyproject.toml`, `Pipfile`         |
| C#          | `*.csproj`, `packages.config`, `Directory.Packages.props` |
| PHP         | `composer.json`, `composer.lock`                        |
| C / C++     | `vcpkg.json`, `conanfile.txt`, `CMakeLists.txt`         |

Extract the declared version of any library referenced in the guidance. If multiple manifests exist, prefer lock files over loose version ranges.

**After gathering dependency information:**

1. Note which libraries are relevant to the finding.
2. If a vulnerable version is detected, record the vulnerable version and the safe upgrade target. Carry this into Step 6 so the fix includes both the library upgrade and the code-level remediation.
3. If the version cannot be determined (no manifest found, no SCA output), flag this and recommend the developer verify it manually.

### Step 5: Trace the Data Flow

Before proposing a fix, trace the data flow from source to sink. Use the best available method:

**Option A — Use available tooling (preferred)**

If any of the following are available, use them first:
- A SAST/DAST report that includes a call path or taint trace for the finding
- Code navigation tools (e.g. `find_all_references`, `go_to_definition`, symbol search) to follow the variable through the call graph
- An existing data-flow or call-graph result attached to the conversation

Extract the source, sink, and any intermediate steps directly from that output. Skip to Step 6 once you have a clear picture.

**Option B — Manual trace (fallback)**

If no tooling or results are available, trace the flow by hand:

1. **Start at the sink** — locate the exact operation the scanner flagged (e.g. SQL query, shell exec, file write). This is your fixed reference point.
2. **Trace backwards** — follow the data through function calls, assignments, and transformations back towards the entry point. Note every place the value could have been validated or sanitised but wasn't.
3. **Identify the source** — where does the untrusted input originally enter the application (HTTP request, file, environment variable, IPC, etc.)?
4. **Find the best fix point** — the nearest upstream location where validation is both feasible and reliable. This is usually the first trust boundary the data crosses, not the sink itself.
5. **Forward pass for other sinks** — from that fix point, briefly check whether the same input flows to any other dangerous operations that would also need covering.

Either way, the goal is the same: determine where to apply the fix and whether a single change is sufficient.

### Step 6: Offer a Fix

#### Tone

Security findings often arrive as unexpected mandatory blockers. Developers may feel defensive, sceptical about exploitability, or daunted by the migration effort involved. When presenting findings and fixes:

- **Lead with the path forward**, not the severity. The developer knows it must be addressed; focus on how.
- **Acknowledge migration cost** — replacing a serializer, refactoring an auth flow, or switching a crypto primitive is real work. Say so plainly rather than making it sound trivial.
- **Use calm, precise language** — avoid alarm phrasing like "DANGEROUS" or "critical vulnerability". Prefer: "this pattern is unsafe because X, and the fix is Y."
- **Validate pushback on exploitability** — if a developer argues their context reduces risk ("this is internal-only"), acknowledge the point before explaining why the safe pattern is still the right path regardless.
- **Don't assign blame** — frame findings as patterns to update, not mistakes to own.

The goal is a developer who understands the problem and feels equipped to fix it, not one who is alarmed or defensive.

---

Summarise the vulnerability and the data flow findings, then **ask the developer if they would like a fix applied** before making any code changes.

Only proceed once they confirm. Then:

1. **If a vulnerable library version was identified in Step 4**, show the upgrade first:
   - State the current version, the vulnerability (CVE or advisory if known), and the minimum safe version.
   - Show the exact change needed in the manifest file (e.g. updated version string in `pom.xml` or `package.json`).
2. Show the **vulnerable** code with a comment marking the problem.
3. Show the **fixed** code using the safe pattern from the guidance, applied at the point identified in Step 5.
4. Briefly explain what changed and why it eliminates the weakness. If both a library upgrade and a code change are required, clarify which part each fix addresses — the library upgrade may close the CVE but the code-level safe pattern is still needed to enforce correct usage.

Always prefer the language-specific safe pattern over the general one when both are available.

## Notes

- Never guess a fix — always base it on the loaded guidance.
- If the user's code spans multiple languages, handle each language separately.
- After applying the fix, suggest the developer re-run their scanner and SCA tool to verify.
