# CWE-243: Creation of Chroot Jail Without Changing Working Directory

## LLM Guidance

This weakness appears when code creates a chroot jail (remapping the process's filesystem root) but does not also change the process's current working directory into the new root immediately afterward. Because the working directory is left outside the jail, relative-path file access after the jail is created can still reach files anywhere the process's underlying privileges allow, making the jail cosmetic rather than a real containment boundary. The remediation is to treat jail creation and the directory change as one inseparable operation, followed immediately by dropping any elevated privilege the process no longer needs.

## Key Principles

- Primary defence: change the working directory into the new root immediately after creating the jail, with no file access performed in between.
- The jail alone is not a privilege boundary; a process that keeps elevated privileges after entering the jail can often re-invoke the jail-creation call on a subdirectory and walk back out.
- Drop elevated privileges immediately after the jail is established, as part of the same remediation, not as an optional follow-up.
- Do not treat the jail as sufficient isolation on its own; it only remaps a filesystem path and does not restrict process, network, or device visibility.
- Defence-in-depth: where the platform supports it, prefer a namespace- or container-based sandbox that provides real isolation instead of a syscall pair that must be sequenced correctly by hand every time.

## Remediation Steps

- Locate - Find every call that creates a chroot jail.
- Trace data flow - Identify every file operation the process performs after jail creation, since each one implicitly trusts that the working directory is already inside the jail.
- Identify the unsafe pattern - Confirm whether a working-directory change into the new root occurs immediately after jail creation, and whether elevated privileges are dropped afterward.
- Replace with the safe pattern - Sequence the code so the working-directory change happens immediately after jail creation, before any file access, followed immediately by dropping elevated privileges.
- Add secondary controls - Where available, prefer a namespace- or container-based isolation mechanism over a hand-sequenced chroot/working-directory pair.
- Test - Attempt to open a file outside the jail using a relative path immediately after setup and confirm it fails; confirm the process is not running with elevated privileges once setup completes; confirm the jail-creation call cannot be invoked a second time from inside the jailed process.
