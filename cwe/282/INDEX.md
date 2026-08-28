# CWE-282: Improper Ownership Management

## LLM Guidance

Improper ownership management occurs when files, directories, or resources are created with incorrect ownership, allowing unauthorized modification, privilege escalation, or data tampering by unintended users. Core fix: Set explicit ownership on all resources and verify it-never assume safe defaults.

## Key Principles

- Set explicit ownership on all created resources using chown/chgrp
- Use least-privilege ownership (service users, not root) for application files
- Verify ownership after creation in deployment scripts
- Never create world-writable files or directories
- Apply correct group ownership to enable proper access control
- Set ownership on an open descriptor: a path-based `chown` re-resolves the path and follows a symlink, so an attacker with write access to the directory can redirect it onto a file they do not own. Use `fchown` on a descriptor you opened yourself, or open with `O_NOFOLLOW` first - `lchown` changes the *link's* ownership rather than the target's, so it refuses redirection instead of performing the intended change
- Set the mode *after* the ownership: changing owner or group clears the setuid and setgid bits on an executable, including for root, so a `chown` run after the mode silently undoes a setuid binary
- Read the ownership back and compare it: some platforms report success on a partial change, so a call that did not raise is not proof it took effect
- Ownership and permission bits are two separate checks even when fixed in the same change - restrictive mode bits protect a file from other accounts only if the owner is also right
- Set ownership explicitly after any extract or install: `tar` run as root restores the ownership recorded in the archive by default, and rpm and dpkg apply the owner and group from package metadata, so the result is whatever the artifact says rather than what you chose
- Make it part of the repeatable deployment rather than a one-time manual fix, which is undone by the next redeploy, package upgrade, or directory recreation

## Remediation Steps

- Check file creation code for explicit ownership setting (chown commands)
- Review service files to find resources owned by root that should be service-owned
- Identify world-writable files (chmod 777) and restrict permissions
- Review sensitive configuration files for incorrect ownership
- Add chown commands immediately after file creation in deployment scripts
- Use install command with -o/-g flags instead of touch + chown
