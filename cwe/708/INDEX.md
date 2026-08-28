# CWE-708: Incorrect Ownership Assignment

## LLM Guidance

Incorrect ownership assignment happens when a file, process, or other resource is assigned to a principal outside the application's intended control, letting that principal access it directly instead of through an access-controlled path. It commonly appears when ownership is set from an ambient default rather than an explicit intended owner, when an ownership change follows a symlink to an unintended target, or when a temporarily elevated owner is never restored. The fix is to assign ownership explicitly, verify the real target before changing it, and restore ownership as part of the same operation that granted it.

## Key Principles

- Assign ownership explicitly to a specific, intended principal rather than relying on the current process or invoking user as a default
- Resolve and verify the real target path before changing ownership; do not follow a symlink when the operation should apply to a specific file
- Restore ownership at the end of any session or privileged operation that temporarily changes it, as part of the same cleanup path, not a best-effort step
- Never derive an ownership decision from unverified caller-supplied identity data
- Verify ownership after assignment rather than assuming the operation succeeded
- Add periodic auditing of sensitive resource ownership against the expected principal as defence-in-depth
- Name the target by an open handle rather than by a path: a path is resolved afresh by every call that takes one, so a symlink dropped in between sends the ownership change somewhere else - and because the operation runs privileged, the attacker borrows that privilege to reassign a file they could not otherwise touch
- Implement the counterpart to any temporary grant: ownership handed to a user for the duration of a session must be taken back when it ends, or the permission outlives its justification and the previous user keeps access after the next one arrives
- Where the ownership decision trusts an unverified claim about who a resource belongs to, it is also CWE-345

## Remediation Steps

- Locate - Identify code that creates a resource or changes its ownership: installers, provisioning scripts, and session or privilege-management logic
- Trace data flow - Follow the path and identity values feeding the ownership-assignment call, and note whether the change happens at creation, during a session, or during cleanup
- Identify the unsafe pattern - Look for ownership set from an ambient default, ownership changes applied to a path without checking whether it is a symlink, or ownership never restored after a privileged session ends
- Replace with the safe pattern - Pin ownership explicitly to the intended principal, resolve the real path and refuse to follow symlinks, and restore the original owner as part of session teardown
- Add secondary controls - Read back the assigned owner to confirm it matches what was intended, and log ownership changes on sensitive resources
- Test - Point a symlink at a protected file and confirm the ownership change targets the symlink itself or is refused; complete a privileged session and confirm ownership reverts to the original owner afterward
