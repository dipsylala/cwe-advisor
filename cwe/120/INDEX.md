# CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')

## LLM Guidance

CWE-120 is the general, classic form of a buffer overflow: a copy or format operation writes data into a fixed-size buffer with no check that the source fits the destination's real capacity. MITRE scopes this ID broadly, and in practice most scanners and CWE Top 25 tallies report the more specific consequence weakness instead - CWE-787 (Out-of-bounds Write) for the write itself, or CWE-121 (Stack-based Buffer Overflow) when the destination is confirmed to be a local/stack variable. This entry does not duplicate that remediation guidance; it routes a finding reported directly against CWE-120 to whichever of those entries matches the destination's actual storage location.

## Key Principles

- CWE-120 names the missing check, not where the corrupted memory lives; the consequence-specific entries carry the concrete taint sinks and safe-replacement APIs for each language
- Route a finding whose destination is a local/stack variable to CWE-121; route every other destination (heap allocation, static/global storage, or an unconfirmed/mixed destination) to CWE-787
- The remediation is the same regardless of which ID a scanner used: replace the unbounded copy or format call with a size-aware equivalent, and validate the source length against the destination's real declared capacity before copying
- Do not treat a CWE-120 finding as needing separate guidance from CWE-121/CWE-787 - applying either entry's fix, for the language and destination in question, closes the finding under whichever ID it was reported

## Remediation Steps

- Locate - identify the destination buffer named in the finding and confirm where it lives: a local/stack variable, a heap allocation, or static/global storage
- Route the finding - for a stack-local destination, apply CWE-121's remediation and language-specific guidance; for any other destination, apply CWE-787's
- Replace with the safe pattern - follow the size-aware replacement call and explicit capacity check described in the routed entry
- Test - verify with the same sanitizer- and boundary-input-based approach the routed entry recommends (for example `-fsanitize=address,undefined`, and normal, exactly-capacity, and oversized inputs)
