# Autonomous Mode Output Format

Structured output for SKILL.md Step 5 (Offer a Fix) in autonomous mode, in place of the interactive presentation and confirmation gate. Emit one record per finding:

- **cwe_id** - the CWE number resolved in Step 1
- **location** - file path and line number(s) of the sink
- **source** / **sink** - the data-flow endpoints identified in Step 4
- **confidence** - how well-supported the trace and fix are (e.g. high/medium/low); lower it whenever an entry appears in `assumptions`
- **library_recommendation** - name and minimum safe version, if the guidance names a specific library; omit otherwise
- **proposed_fix** - the vulnerable code and the fixed code, in the same before/after form as the interactive Step 5 output
- **explanation** - one paragraph on what changed and why it eliminates the weakness
- **assumptions** - any ambiguity resolved without asking (per Operating Mode) and what was assumed; omit if none

Do not modify the developer's code in this mode. The record above is a proposal for the calling process to apply, queue for review, or reject.
