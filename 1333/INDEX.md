# CWE-1333: Inefficient Regular Expression Complexity

## LLM Guidance

This weakness occurs when a regular expression is logically correct but has worst-case exponential or high-degree polynomial matching time, so an attacker who controls the input can craft a string that triggers catastrophic backtracking and consumes disproportionate CPU time (ReDoS). It commonly hides inside nested or overlapping quantifiers applied to attacker-controlled input, especially within larger patterns such as email or path validators. The primary fix is to rewrite the pattern to remove the backtracking ambiguity; length limits and execution timeouts are defense-in-depth, not substitutes for the fix.

## Key Principles

- Eliminate nested and overlapping quantifiers as the primary defence; do not rely on a timeout alone
- Avoid quantifiers applied to a group that itself allows the same characters matched by an outer quantifier, such as `(a+)+`, `(a*)*`, or `(a|a)*`
- Rewrite ambiguous repetition as a single unambiguous quantifier wherever the intended match allows it
- Prefer a non-backtracking or linear-time regex engine for patterns applied to untrusted input, where the language or runtime offers one
- Bound the risk with an input length limit and an execution timeout on the regex call, treating a timeout as a rejection, not a silent pass-through
- Check every sub-pattern in composed or library-provided regexes, not just the top-level pattern, since a nested quantifier can be hidden inside a named sub-expression

## Remediation Steps

- Locate - Identify where the regular expression is applied to attacker-controlled input (request parameters, headers, uploaded content) and the matching call itself
- Trace data flow - Confirm whether the input reaching the regex engine is already length-limited or otherwise constrained upstream
- Identify the unsafe pattern - Look for nested quantifiers, overlapping alternation, or ambiguous repetition, including inside sub-patterns pulled from shared libraries
- Replace with the safe pattern - Rewrite the expression to remove the ambiguity, or replace it with an equivalent non-backtracking engine or a simpler string operation if full regex expressiveness is not required
- Add secondary controls - Enforce a maximum input length before the value reaches the regex engine and set an execution timeout that rejects on expiry
- Test - Construct a worst-case adversarial string for the original pattern and confirm matching time now grows linearly, not exponentially, as input length increases; re-run any regex-complexity linter available
