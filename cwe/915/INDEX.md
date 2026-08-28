# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

## LLM Guidance

This vulnerability occurs when user input dynamically modifies object attributes or properties, allowing attackers to alter application behavior or access unauthorized data. In ASP.NET applications specifically, this same failure mode is also covered under CWE-1174 (ASP.NET Misconfiguration: Improper Model Validation), where it is fixed via the framework's `[Bind]` allowlist and model-binding configuration. Never allow mass assignment of object attributes; allowlist permitted fields and enforce invariants server-side.

## Key Principles

- Use explicit allowlists to restrict which object attributes can be modified by user input
- Reject dynamic attribute assignment patterns that accept arbitrary property names from untrusted sources
- Enforce security-critical attributes (isAdmin, role, price, balance) server-side, never from client input
- Validate both property names and values before modification
- Prefer explicit property binding over reflection-based or dynamic assignment
- Bind an explicit allowlist of fields rather than the whole request object, and take the values from the parsed result - re-spreading the original body after validating it puts the payload straight back
- Server-owned fields (role, price, owner, status, timestamps, identifiers) are never bindable, whatever the form on screen contains
- Where the attacker controls *what type is constructed* rather than which fields of an expected one get set, the finding is CWE-502; in JavaScript the same shape reaching `Object.prototype` is CWE-1321

## Remediation Steps

- Locate the vulnerability - Review flaw details for file, line number, and code pattern. Trace data flow from source (HTTP parameters, JSON, form data) to sink - dynamic/reflective attribute assignment or mass-assignment model binding (see the language-specific guidance's Taint Sinks for concrete function names)

- Identify risk - Determine if attackers can modify security-critical attributes that control authorization, pricing, or application state

- Implement allowlist - Define explicitly permitted attributes that users can modify, rejecting all others by default

- Replace dynamic assignment - Use explicit property setters or data transfer objects (DTOs) with known fields instead of dynamic reflection or dictionary-based assignment

- Enforce server-side validation - Validate property values and maintain security invariants regardless of client input

- Test protection - Verify that unauthorized attribute modification attempts are blocked and logged
