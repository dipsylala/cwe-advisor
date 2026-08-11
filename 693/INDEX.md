# CWE-693: Protection Mechanism Failure

## LLM Guidance

Protection mechanism failure occurs when a security control exists in the codebase or configuration but is disabled, only partially applied, or can be bypassed - for example, authentication middleware wired into some routes but not others, a security feature left off because of a debug flag, or a validation rule with an alternate code path that skips it. This differs from simply lacking a control (see the more specific CWE for that, e.g. CWE-306 for missing authentication or CWE-862 for missing authorization) - the defining trait here is that the mechanism is present but not consistently enforced. The core fix is finding every path that should invoke the control and confirming it is actually applied on each one, not layering on unrelated defences.

## Key Principles

- Name the specific mechanism at issue (middleware, filter, config flag, WAF rule) and confirm where in the codebase or configuration it is defined
- Confirm the mechanism is applied on every code path to the protected resource, not just the primary or documented one - secondary routes, legacy endpoints, and alternate API versions are common gaps
- Check for conditional disablement: debug flags, environment checks, or feature toggles that can turn the mechanism off outside the intended environment
- Prefer global enforcement (e.g., middleware registered at the router/framework level) over per-route application, which is easy to miss on new code
- Never rely on a mechanism that can be skipped through request manipulation, alternate routing, or client-controlled configuration

## Remediation Steps

- Identify the mechanism - locate the specific control that exists but is not consistently enforced, and confirm its intended scope
- Map every code path to the protected resource - secondary routes, admin backdoors, legacy endpoints, alternate API versions - and check whether the mechanism is wired into each one
- Check for conditional disablement - search for debug flags, environment checks, or feature toggles that can turn the mechanism off
- Apply the mechanism uniformly - move it to a global enforcement point (router-level middleware, framework filter) instead of per-route opt-in where the framework supports it
- Test bypass scenarios - attempt to reach the protected resource through every path found above and confirm the mechanism blocks each one
- Document the enforcement point so future routes are added inside its scope by default
