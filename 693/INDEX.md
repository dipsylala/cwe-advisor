# CWE-693: Protection Mechanism Failure

## LLM Guidance

Protection mechanism failure is a broad parent weakness covering any case where a security control does not do its job - including a control that is entirely absent, one that is disabled or only partially applied, or one that can be bypassed through an alternate code path. Official CWE hierarchy places entries like CWE-306 (missing authentication) and CWE-862 (missing authorization) as children of this weakness, so "the mechanism was never applied at all" is squarely in scope here too, not excluded from it. That said, when a finding names a more specific mechanism - authentication middleware wired into some routes but not others, a security feature left off because of a debug flag, a validation rule with a bypassable alternate path - prefer the more targeted entry (CWE-306, CWE-862, CWE-863, or others) if one matches; use this entry's guidance when the finding doesn't map cleanly to a narrower CWE, or spans multiple protection mechanisms. The core fix is finding every path that should invoke the control and confirming it is actually applied on each one, not layering on unrelated defences.

## Key Principles

- Name the specific mechanism at issue (middleware, filter, config flag, WAF rule) and confirm where in the codebase or configuration it is defined
- Confirm the mechanism is applied on every code path to the protected resource, not just the primary or documented one - secondary routes, legacy endpoints, and alternate API versions are common gaps
- Check for conditional disablement: debug flags, environment checks, or feature toggles that can turn the mechanism off outside the intended environment
- Prefer global enforcement (e.g., middleware registered at the router/framework level) over per-route application, which is easy to miss on new code
- Never rely on a mechanism that can be skipped through request manipulation, alternate routing, or client-controlled configuration
- MITRE marks this Pillar Discouraged: file the descendant instead - missing encryption CWE-311, inadequate strength CWE-326, a broken algorithm CWE-327, weak randomness CWE-330, unverified authenticity CWE-345, obscurity as the control CWE-656, a downgraded negotiation CWE-757, a control the client is trusted to apply CWE-602, and a server-side check whose input the caller supplies CWE-807
- A check on the server whose *input* is not is the recurring shape: a role read from a cookie means the server is asking the caller whether the caller is an administrator and believing the answer
- Check the error paths as well as the happy path - a control that is skipped when an exception is thrown, or that covers one disallowed value rather than the whole class, is bypassed without being removed

## Remediation Steps

- Identify the mechanism - locate the specific control that exists but is not consistently enforced, and confirm its intended scope
- Map every code path to the protected resource - secondary routes, admin backdoors, legacy endpoints, alternate API versions - and check whether the mechanism is wired into each one
- Check for conditional disablement - search for debug flags, environment checks, or feature toggles that can turn the mechanism off
- Apply the mechanism uniformly - move it to a global enforcement point (router-level middleware, framework filter) instead of per-route opt-in where the framework supports it
- Test bypass scenarios - attempt to reach the protected resource through every path found above and confirm the mechanism blocks each one
- Document the enforcement point so future routes are added inside its scope by default
