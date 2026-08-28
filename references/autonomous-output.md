# Autonomous Mode Output Format

Structured output for SKILL.md Step 5 (Offer a Fix) in autonomous mode, in place of the interactive presentation and confirmation gate. Emit one record per finding:

- **cwe_id** - the CWE number resolved in Step 1
- **location** - file path and line number(s) of the sink
- **source** / **sink** - the data-flow endpoints identified in Step 4
- **verdict** - `exploitable`, `not_exploitable`, or `undetermined`. Use `not_exploitable` only where the Step 4 trace positively shows the path is broken, and name the breaking link in `explanation`. Use `undetermined` where the trace could not be completed - that is a different statement and must never be reported as `not_exploitable`
- **confidence** - how well-supported the trace and fix are (e.g. high/medium/low); lower it whenever an entry appears in `assumptions`
- **library_recommendation** - name and, where the loaded guidance supplies one, minimum safe version; omit the version rather than supplying it from recall, and where the guidance records no fixed release, give the replacement instead of a version
- **proposed_fix** - the vulnerable code and the fixed code, in the same before/after form as the interactive Step 5 output; omit when `verdict` is not `exploitable`
- **explanation** - one paragraph on what changed and why it eliminates the weakness
- **assumptions** - any ambiguity resolved without asking (per Operating Mode) and what was assumed; omit if none

Do not modify the developer's code in this mode. The record above is a proposal for the calling process to apply, queue for review, or reject.
