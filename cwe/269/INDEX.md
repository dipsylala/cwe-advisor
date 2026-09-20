# CWE-269: Improper Privilege Management

## LLM Guidance

MITRE marks this Class Discouraged for new findings: prefer the child that fits - a component configured to run over-privileged for its whole lifetime is CWE-250, a privilege not dropped after the operation that needed it is CWE-272, an unverified drop is CWE-273, and mishandling a privilege that was *denied* is CWE-274. What this family covers is the standing privilege level of an identity over time: not a resource's permission bits, which is CWE-732, and not a single request's authorization check, which is CWE-862 and CWE-863.

## Key Principles

- Apply least privilege as the primary defence: start processes, services, and accounts with the minimum privilege level required, not the broadest available
- Drop elevated privilege immediately after the operation that required it completes; do not let a process or session keep running at a higher level than its remaining work needs
- Treat privilege elevation as a controlled transition: require explicit authorization, log who requested and approved it, and bind temporary grants to an expiry or revocation step
- Prefer capability-scoped or role-scoped grants over broad administrative or root-equivalent privilege, even when the broader grant is more convenient
- Scope the elevation to the call, not the request: wrapping a whole handler in an elevated context because one internal step needs it puts every line of untrusted-input handling at the higher level
- Treat a broad cloud role or container capability set chosen for convenience as the finding itself - any compromise of that component then becomes a full-account compromise

## Remediation Steps

- Locate - identify the process, service, or account and the point where it acquires elevated privilege (setuid/setgid call, service account role, admin flag, container capability)
- Trace the privilege lifecycle - determine when elevated privilege is acquired, what operation actually requires it, and whether the code path ever releases it
- Identify the unsafe pattern - name the issue: privilege never dropped after use, privilege broader than the operation needs, or an unauthenticated/unauthorized path that can change privilege level
- Replace with the safe pattern - acquire minimum privilege immediately before the privileged operation and drop to a lower-privileged identity immediately after; scope service accounts and containers to the narrowest role or capability set that satisfies the task
- Gate elevation paths - require authentication and authorization on any endpoint or function that grants, changes, or renews privilege, and make elevation requests auditable
- Bound temporary grants - attach an expiry or explicit revocation mechanism so a temporary elevation cannot become a permanent standing privilege
- Add secondary controls - log privilege acquisition and drop events, alert on processes holding elevated privilege longer than expected, and review privileged accounts periodically for drift
- Test - verify the process or account cannot perform privileged actions after the drop point, and that elevation paths reject unauthorized or expired requests
