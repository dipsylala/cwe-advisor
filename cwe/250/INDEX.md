# CWE-250: Execution with Unnecessary Privileges

## LLM Guidance

This weakness is a standing configuration condition: a process, service, container, or account is set up to run with more privilege than any of its operations actually require, for its entire operational lifetime, rather than a single privileged step that was never dropped. Because the excess privilege is present at every moment the component runs, any other vulnerability reachable from it (an injection flaw, a deserialization bug, a compromised dependency) inherits that same elevated access. The remediation is to determine the actual minimum privilege the component needs by auditing what it does, and configure its identity to hold exactly that level from startup, not a broader one narrowed later.

## Key Principles

- Primary defence: determine the minimum privilege a component needs from its actual operations, and configure its identity to hold exactly that level from the start.
- Do not grant a broad privilege "temporarily" to unblock setup or development with a plan to narrow it later; the narrowing step is easy to skip and the broad grant tends to become permanent.
- Do not share one broad account or role across multiple components; a compromise of any one of them then grants every other component's access too.
- Treat this as a multiplier rather than a vulnerability in itself: it sets the ceiling on every other defect in the process, turning a path traversal that would have read one directory into one that reads the disk, and a crash into a host compromise. That is why it is worth fixing before the bug it will amplify is found.
- Where a resource's *own* permissions are too permissive rather than the process running with excess privilege, the finding is CWE-732; where privilege was legitimately needed for one operation and not dropped afterwards, CWE-272 - the remediation is the same, so treat the number as reporting preference rather than a triage question.
- Where a component only occasionally needs elevated access for one specific operation, prefer acquiring it narrowly and dropping it immediately after use (see the related least-privilege-violation pattern) rather than granting the privilege for the component's entire lifetime.
- Distinguish standing over-privilege (this weakness) from a resource's own permissions being too permissive; the two require different fixes even though both stem from missing least-privilege enforcement.
- Defence-in-depth: enforce scoping at the platform level (container user and capabilities, database account grants, cloud IAM policy) rather than relying on application logic alone.

## Remediation Steps

- Locate - Identify the configured identity and permission set of the process, service, container, or account under review, and compare it against what the component actually does.
- Trace data flow - Enumerate every operation the component performs over its lifetime and the privilege each one actually requires.
- Identify the unsafe pattern - Confirm the configured privilege set exceeds what any of the enumerated operations require, or that a broad shared account is in use.
- Replace with the safe pattern - Configure a dedicated identity scoped to exactly the required permission set, rather than reusing or retaining a broader one.
- Add secondary controls - Apply platform-level enforcement appropriate to the component type: non-root container users with minimal capabilities, per-service accounts, scoped database grants, or scoped cloud IAM policies.
- Test - Confirm the component still performs every operation it legitimately needs after the reduction, and confirm an operation outside the new minimum permission set is denied.
- Verify - Re-scan with the security or configuration tool that reported the finding to confirm it is resolved.
