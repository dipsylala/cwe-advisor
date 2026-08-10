# CWE-185: Incorrect Regular Expression

## LLM Guidance

This weakness occurs when a regular expression's matching logic does not do what the developer intended - missing anchors, unescaped metacharacters, misgrouped alternation, or a character class that is too broad or too narrow. When the pattern gates a security decision, that logic gap becomes a validation bypass: input the check was meant to reject gets accepted, or the reverse. The fix is to anchor and escape the pattern correctly, verify alternation and quantifier scope match intent, and prefer a purpose-built parser over regex for structured formats.

## Key Principles

- Anchor the pattern to the whole string (or use a full-match API) unless a substring match is genuinely intended
- Escape every literal metacharacter that should be taken literally; an unescaped metacharacter matches more than intended
- Group alternation explicitly with parentheses so anchors apply to every branch, not just one
- Treat a negated character class as excluding only the listed characters, not everything unsafe
- Prefer a maintained URL, IP address, or path parser over a hand-written pattern for structured formats
- Reserve regex for genuinely simple, fixed-shape formats

## Remediation Steps

- Locate - Find the regex used as an accept/reject gate, extraction step, or routing decision, and identify what data it evaluates
- Trace data flow - Identify the source of the input reaching the pattern and the decision the match result controls
- Identify the unsafe pattern - Missing anchors, an unescaped metacharacter, or alternation/quantifier scope that does not match the intended logic
- Replace with the safe pattern - Rewrite the pattern with full-string anchors, escaped literals, and explicitly grouped alternation, or replace it with a structured parser for URLs, IPs, or paths
- Break taint after allowlist validation - Where the regex is an allowlist check, use the matched or canonicalized value for downstream use, not the original raw input
- Add secondary controls - For semantically bounded values, such as IP octets, validate the numeric range in addition to the pattern shape
- Test - Verify the pattern accepts every legitimate input shape including boundary cases, and rejects near-miss malicious input such as a valid prefix with a malicious suffix or an encoded variant
