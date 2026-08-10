# CWE-385: Covert Timing Channel

## LLM Guidance

A covert timing channel arises when processing time, response latency, or other observable timing differs based on a secret value - for example, a comparison that exits as soon as it finds a mismatched byte, or a branch taken only when a guess is correct. An attacker who can measure timing across many attempts can infer the secret one step at a time, even without ever seeing it directly. Fix this by making any code path that touches a secret value take the same time and access the same memory regardless of what the secret is, rather than trying to mask the leak with added delay.

## Key Principles

- Use a constant-time comparison for secrets (password hashes, HMACs, tokens, session identifiers, signatures) instead of a standard equality operator that short-circuits on the first differing byte
- Avoid branching, early returns, or variable-length loops whose duration depends on a secret value
- Do not rely on random delays or jitter alone to hide timing; statistical averaging over many requests defeats jitter, so the variance must be removed at its source
- Apply the same discipline to memory access patterns during secret comparison, not just instruction timing, since cache-timing differences can also leak information
- Add rate limiting, generic error responses, and monitoring for repeated near-miss attempts as defense-in-depth, not as the primary fix

## Remediation Steps

- Locate - Identify comparisons or conditional logic involving a secret value (key material, token, hash, password) paired with an externally observable timing signal (response latency, error timing, function duration)
- Trace data flow - Follow how the secret is compared, branched on, or used to determine loop length or operation count
- Identify the unsafe pattern - Look for equality operators or comparison functions that return as soon as they find a mismatch
- Replace with the safe pattern - Use a constant-time comparison primitive from the language or crypto library that always processes the full length regardless of match
- Remove secret-dependent branching - Restructure logic so the execution path and memory access pattern do not vary with the secret's value
- Add secondary controls - Apply rate limiting and logging on sensitive endpoints where repeated probing would be needed to exploit any residual timing signal
- Test - Measure timing across many trials with correct and incorrect inputs and confirm no statistically significant difference remains
