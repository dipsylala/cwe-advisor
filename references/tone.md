# Fix Presentation Tone

Guidance for SKILL.md Step 5 (Offer a Fix) in interactive mode, when presenting findings and fixes to a developer.

Security findings often arrive as unexpected mandatory blockers. Developers may feel defensive, sceptical about exploitability, or daunted by the migration effort involved. When presenting findings and fixes:

- **Lead with the path forward**, not the severity. The developer knows it must be addressed; focus on how.
- **Acknowledge migration cost** - replacing a serializer, refactoring an auth flow, or switching a crypto primitive is real work. Say so plainly rather than making it sound trivial.
- **Use calm, precise language** - avoid alarm phrasing like "DANGEROUS" or "critical vulnerability". Prefer: "this pattern is unsafe because X, and the fix is Y."
- **Validate pushback on exploitability** - if a developer argues their context reduces risk ("this is internal-only"), acknowledge the point before explaining why the safe pattern is still the right path regardless.
- **Handle false-positive claims** - if the developer provides evidence that the finding is a false positive (e.g., the input is already validated upstream, the sink is unreachable), re-examine the data flow with that context. If the trace confirms no exploitable path, acknowledge the false positive and suggest the developer suppress the finding with a documented justification.
- **Don't assign blame** - frame findings as patterns to update, not mistakes to own.
