# CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

## LLM Guidance

What separates this from its neighbours is that the application never calls an evaluator. A value it handled as ordinary data reaches a layer that interpolates expressions - a view template, a validation message, a rule or label rendered later - and that layer evaluates it, so there is no `eval` in the diff to find and the call site looks like string handling. Where the code deliberately evaluates attacker-supplied expression text, the entry is CWE-94, or CWE-95 where the sink is an eval-style function; a shell is CWE-78.

## Key Principles

- Name the layer that evaluates before proposing a fix: the finding is at the boundary where the value enters something later interpolated, which is usually several frames away from where the payload arrives
- The fix is to stop the value being *parsed* as expression text, not to remove characters from it - a denylist on `${` misses the `#{` deferred syntax, a payload assembled across two fields, and any value the framework decodes again after the check
- Where a value must appear inside an evaluated template, bind it as a variable the engine resolves at evaluation time rather than substituting it into the template beforehand; substitution runs first, so a value spliced in that way becomes part of the expression rather than an argument to it
- A restricted evaluation mode is a reduction rather than a boundary: the level that resolves only variables or properties still evaluates arithmetic, and the vendors offering one generally say so themselves
- State the engine's current default before changing it: several expression interpolators ship with evaluation disabled or restricted, in which case the finding is a configuration that re-enabled it rather than the call site the scanner flagged

## Remediation Steps

- Locate - find the interpolating layer, not the assignment the scanner reported: the template, message, label or rule body that the framework evaluates, and the configuration that decides whether it evaluates at all
- Trace data flow - follow the value from its source to the point where it is placed into that template, and note every decode, copy or re-render between the two
- Identify the unsafe pattern - untrusted text becoming part of the template itself, rather than a value the template refers to
- Check the default first - determine whether the engine evaluates expressions in this position out of the box; where it does not, the defect is the setting that turned it on and lowering that setting is the fix
- Replace with the safe pattern - keep the template static and supply the value through the engine's variable-binding mechanism, or stop interpolating that string entirely where it carries no expressions by design
- Add secondary controls - narrow what the evaluation context exposes, and run the process with least privilege and no ambient credentials, so an expression that does evaluate reaches as little as possible
- Test - assert on the rendered result rather than on an exception, because an engine that refuses a disabled feature commonly logs and emits the raw template instead of throwing; confirm a payload appears literally in the output and that a legitimate value still renders, since a template that stopped interpolating altogether passes the first check and fails the feature
