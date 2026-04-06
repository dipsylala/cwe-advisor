---
name: cwe-advisor
description: Educate developers about CWE vulnerabilities and guide remediation using a local knowledge base. Use when a developer reports a CWE ID from a security scan, SAST/DAST finding, wants to understand a weakness, or asks for help with a specific CWE number. Explains the vulnerability, teaches underlying security concepts, and optionally applies fixes to the developer's code.
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

### Step 4: Trace the Data Flow

Before proposing a fix, start at the vulnerable sink and work backwards to the source:

1. **Start at the sink** — locate the exact operation the scanner flagged (e.g. SQL query, shell exec, file write). This is your fixed reference point.
2. **Trace backwards** — follow the data through function calls, assignments, and transformations back towards the entry point. Note every place the value could have been validated or sanitised but wasn't.
3. **Identify the source** — where does the untrusted input originally enter the application (HTTP request, file, environment variable, IPC, etc.)?
4. **Find the best fix point** — the nearest upstream location where validation is both feasible and reliable. This is usually the first trust boundary the data crosses, not the sink itself.
5. **Forward pass for other sinks** — from that fix point, briefly check whether the same input flows to any other dangerous operations that would also need covering.

This analysis determines where to apply the fix and whether a single change is sufficient.

### Step 5: Offer a Fix

Summarise the vulnerability and the data flow findings, then **ask the developer if they would like a fix applied** before making any code changes.

Only proceed once they confirm. Then:

1. Show the **vulnerable** code with a comment marking the problem.
2. Show the **fixed** code using the safe pattern from the guidance, applied at the point identified in Step 4.
3. Briefly explain what changed and why it eliminates the weakness.

Always prefer the language-specific safe pattern over the general one when both are available.

## Notes

- Never guess a fix — always base it on the loaded guidance.
- If the user's code spans multiple languages, handle each language separately.
- After applying the fix, suggest the developer re-run their scanner to verify.
