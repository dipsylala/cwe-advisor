# CWE-269: Improper Privilege Management

## LLM Guidance

This vulnerability occurs when a process, service, or account holds more privilege than its current task requires, keeps elevated privilege after the privileged operation is complete, or can have its privilege level raised through an unprotected path. It is a lifecycle problem: the standing privilege level granted to an identity over time, not a single resource's permission bits and not a single request's authorization check. Fix by granting only the minimum privilege needed to start, dropping to a lower privilege level immediately after the privileged step finishes, and gating any privilege change behind an authenticated, authorized, auditable path with a defined expiry or revocation.

## Key Principles

- Apply least privilege as the primary defence: start processes, services, and accounts with the minimum privilege level required, not the broadest available
- Drop elevated privilege immediately after the operation that required it completes; do not let a process or session keep running at a higher level than its remaining work needs
- Treat privilege elevation as a controlled transition: require explicit authorization, log who requested and approved it, and bind temporary grants to an expiry or revocation step
- This is not CWE-732 (Incorrect Permission Assignment for Critical Resource): CWE-732 is about a resource's permission bits or ACL being wrong; CWE-269 is about the standing privilege level of the process or account acting on resources
- This is not CWE-862/CWE-863 (Missing/Incorrect Authorization): those CWEs govern whether a single request should be allowed at the caller's current privilege level; CWE-269 governs whether that privilege level was acquired, retained, or escalated correctly over time
- Prefer capability-scoped or role-scoped grants over broad administrative or root-equivalent privilege, even when the broader grant is more convenient

## Remediation Steps

- Locate - identify the process, service, or account and the point where it acquires elevated privilege (setuid/setgid call, service account role, admin flag, container capability)
- Trace the privilege lifecycle - determine when elevated privilege is acquired, what operation actually requires it, and whether the code path ever releases it
- Identify the unsafe pattern - name the issue: privilege never dropped after use, privilege broader than the operation needs, or an unauthenticated/unauthorized path that can change privilege level
- Replace with the safe pattern - acquire minimum privilege immediately before the privileged operation and drop to a lower-privileged identity immediately after; scope service accounts and containers to the narrowest role or capability set that satisfies the task
- Gate elevation paths - require authentication and authorization on any endpoint or function that grants, changes, or renews privilege, and make elevation requests auditable
- Bound temporary grants - attach an expiry or explicit revocation mechanism so a temporary elevation cannot become a permanent standing privilege
- Add secondary controls - log privilege acquisition and drop events, alert on processes holding elevated privilege longer than expected, and review privileged accounts periodically for drift
- Test - verify the process or account cannot perform privileged actions after the drop point, and that elevation paths reject unauthorized or expired requests
