# CWE-250: Execution with Unnecessary Privileges

## LLM Guidance

A standing condition: the component holds more privilege than its operations need, for its entire operational lifetime. Where privilege was legitimately acquired for one operation and not dropped afterwards, that is CWE-272, and the fix differs - a lower-privilege identity configured from startup here, a drop immediately after the operation there. Where a resource's own permissions are too permissive rather than the process's privilege, the finding is CWE-732.

## Key Principles

- Primary defence: determine the minimum privilege a component needs from its actual operations, and configure its identity to hold exactly that level from the start.
- Do not grant a broad privilege "temporarily" to unblock setup or development with a plan to narrow it later; the narrowing step is easy to skip and the broad grant tends to become permanent.
- Do not share one broad account or role across multiple components; a compromise of any one of them then grants every other component's access too.
- Treat this as a multiplier rather than a vulnerability in itself: it sets the ceiling on every other defect in the process, turning a path traversal that would have read one directory into one that reads the disk, and a crash into a host compromise. That is why it is worth fixing before the bug it will amplify is found.
- Where a component only occasionally needs elevated access for one specific operation, prefer acquiring it narrowly and dropping it immediately after use (see the related least-privilege-violation pattern) rather than granting the privilege for the component's entire lifetime.
- Defence-in-depth: enforce scoping at the platform level (container user and capabilities, database account grants, cloud IAM policy) rather than relying on application logic alone.

## Remediation Steps

- Locate - Identify the configured identity and permission set of the process, service, container, or account under review, and compare it against what the component actually does.
- Trace data flow - Enumerate every operation the component performs over its lifetime and the privilege each one actually requires.
- Identify the unsafe pattern - Confirm the configured privilege set exceeds what any of the enumerated operations require, or that a broad shared account is in use.
- Replace with the safe pattern - Configure a dedicated identity scoped to exactly the required permission set, rather than reusing or retaining a broader one.
- Add secondary controls - Apply platform-level enforcement appropriate to the component type: non-root container users with minimal capabilities, per-service accounts, scoped database grants, or scoped cloud IAM policies.
- Test - Confirm the component still performs every operation it legitimately needs after the reduction, and confirm an operation outside the new minimum permission set is denied.
- Verify - Re-scan with the security or configuration tool that reported the finding to confirm it is resolved.
