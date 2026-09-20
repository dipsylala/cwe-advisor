# CWE-185: Incorrect Regular Expression

## LLM Guidance

A matching-logic bug: the pattern does not accept or reject what its author intended, and where it gates a security decision that gap becomes a validation bypass. A pattern that is logically correct but backtracks catastrophically on hostile input is CWE-1333 instead - both present as "bad regex", but one is a correctness bug and the other an availability bug.

## Key Principles

- Anchor the pattern to the whole string (or use a full-match API) unless a substring match is genuinely intended
- Escape every literal metacharacter that should be taken literally; an unescaped metacharacter matches more than intended
- Group alternation explicitly with parentheses so anchors apply to every branch: alternation has the lowest precedence of any regex operator, so `^report|invoice\.pdf$` parses as `(^report)` or `(invoice\.pdf$)` and each branch inherits only one anchor - `reportXYZ` and `XYZinvoice.pdf` both pass
- Escape every branch, not just the one that was written first: `a\.b|c.d` escapes the dot in one alternative and leaves it as a wildcard in the other
- Treat a negated character class as excluding only the listed characters, not everything unsafe
- Prefer a maintained URL, IP address, or path parser over a hand-written pattern for structured formats
- Reserve regex for genuinely simple, fixed-shape formats
- `$` is not an end-of-input anchor in every engine - it also matches before a final newline in Python, .NET and PCRE, so `^[a-z]+$` accepts a permitted value with a newline appended, and that newline is the byte that splits a header, a log line, or a mail command downstream. Use the whole-string call (`re.fullmatch()`, `Matcher.matches()`) or `\A...\z`

## Remediation Steps

- Locate - Find the regex used as an accept/reject gate, extraction step, or routing decision, and identify what data it evaluates
- Trace data flow - Identify the source of the input reaching the pattern and the decision the match result controls
- Identify the unsafe pattern - Missing anchors, an unescaped metacharacter, or alternation/quantifier scope that does not match the intended logic
- Replace with the safe pattern - Rewrite the pattern with full-string anchors, escaped literals, and explicitly grouped alternation, or replace it with a structured parser for URLs, IPs, or paths
- Break taint after allowlist validation - Where the regex is an allowlist check, use the matched or canonicalized value for downstream use, not the original raw input
- Add secondary controls - For semantically bounded values, such as IP octets, validate the numeric range in addition to the pattern shape
- Test - Verify the pattern accepts every legitimate input shape including boundary cases, and rejects near-miss malicious input such as a valid prefix with a malicious suffix or an encoded variant. The cheapest mechanical check for the anchor case: feed every allowlist pattern its own permitted value with a newline appended and assert rejection
