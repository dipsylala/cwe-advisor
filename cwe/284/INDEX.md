# CWE-284: Improper Access Control

## LLM Guidance

CWE-284 is the broad parent weakness for any failure to properly restrict access to a resource: authentication gaps, authorization logic errors, misconfigured access control lists (ACLs), leaked or over-broad capabilities, and resource-level permission models that don't map correctly to who should be allowed to do what. Where a finding names a more specific mechanism, remediate with that entry's targeted guidance instead: a missing or incorrect authorization check is CWE-285/862/863, missing authentication is CWE-306/287, and an object-reference bypass is CWE-639. Use this entry when the access-control failure doesn't fit a narrower category - for example, an ACL or capability model that grants access along the wrong dimension (by resource type instead of a specific resource, or via a capability the actor should no longer hold).

## Key Principles

- Prefer the most specific applicable CWE for the actual failure mode (missing check, incorrect check, missing authentication, IDOR); use this entry's guidance when none of those fit precisely
- Model access control as an explicit policy (ACL, RBAC, ABAC, capability list) evaluated for every resource and operation, not as scattered ad hoc checks
- Grant access along the correct dimension - by specific resource and operation, not merely by resource type or role membership
- Never allow a capability or permission to persist beyond the scope or duration it was granted for
- Apply deny-by-default and re-evaluate access on every request rather than caching an authorization decision beyond its intended lifetime
- Route to the specific descendant: no check runs on the path is CWE-862, a check runs with wrong logic is CWE-863, an unauthenticated critical function is CWE-306, a resource's permission bits are wrong is CWE-732, a user-controlled object key is trusted is CWE-639/CWE-566, privilege acquisition or drop is CWE-269, resource ownership is CWE-282, request-origin trust is CWE-346, and a privileged API or scripting bridge reachable without a check is CWE-749

## Remediation Steps

- Identify the access-control failure - Determine whether this is a missing check, an incorrect check, a missing identity check, or a broader ACL/capability-model design flaw, and redirect to the matching narrower CWE if one applies
- Map the resource and actor model - Identify every resource type, specific resource instance, and actor role or capability involved
- Design or correct the policy - Define which actors may perform which operations on which specific resources, not just resource types
- Implement server-side enforcement - Ensure the policy is evaluated on every access path (UI, API, background job, admin tool), not just the primary one
- Constrain capability lifetime - Ensure granted permissions or capabilities expire or are revocable, and are not retained beyond their intended scope
- Test - Attempt access using accounts with different roles and capabilities and confirm the policy is enforced consistently across every access path
