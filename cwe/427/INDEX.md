# CWE-427: Uncontrolled Search Path Element

## LLM Guidance

CWE-427 occurs when a fixed, unmodified search path (unlike CWE-426, the path itself is not attacker-controlled) still contains one element that is writable by a lower-privileged or untrusted actor - most commonly the current working directory, a world-writable temp directory, or an application-local plugin folder that sits early in the default library/executable search order. An attacker who can place a malicious file at that one writable location (a same-named DLL, shared library, or executable) gets it loaded before the legitimate version further down the search path, without ever needing to modify PATH or any environment variable - the classic case is DLL side-loading via the current working directory. The fix is to remove writable-by-others locations from the search order or resolve to a specific, trusted, absolute path rather than relying on default search behavior.

## Key Principles

- Identify every directory in the default search order (current working directory, application directory, system directories, plugin/extension folders) and determine which are writable by users other than the application's own privileged owner
- Never rely on the current working directory being part of the search path; explicitly remove it or load by absolute path instead
- Load libraries and executables by their full, absolute, trusted path rather than depending on default loader search order, even when the path itself is not attacker-modifiable
- Apply least-writable-permissions to every directory that remains in the search order - a directory the application does not control should not be searched at all
- Verify the integrity (signature or checksum) of loaded components when loading by name is unavoidable
- Overwrite the search path rather than appending to it: appending inherits whatever elements were already there, which is the condition being fixed
- Do not expect a runtime property to move a loader's path - `System.setProperty("java.library.path", ...)` after startup changes the property and nothing else, since `System.loadLibrary` keeps the value captured at class-initialization time. Set `-Djava.library.path` at launch, or load by absolute path with `System.load`
- Set the environment for the subprocess rather than the parent, and prefer a clean environment over an inherited one
- The circulating names - DLL preloading, binary planting, insecure library loading, dependency confusion - are used for both this and CWE-426, so do not take a scanner's label as the answer

## Remediation Steps

- Identify the vulnerability - Review flaw details for where a library, plugin, or executable is loaded by name or relative reference rather than an absolute, fully-qualified path
- Enumerate the search order - Determine every directory the loader checks, in order, for the requested resource
- Check writability - For each directory in that order, determine whether an untrusted or lower-privileged actor can write to it (current working directory, temp folders, user-writable plugin directories)
- Remove or reorder unsafe locations - Where the platform supports it, remove the current working directory and other writable locations from the search order, or move trusted directories ahead of them
- Load by absolute path - Replace name-based loading with a fully-qualified path to the specific trusted file wherever possible
- Verify integrity - If dynamic lookup by name cannot be avoided, verify a signature or checksum before loading
- Test - Place a decoy file with the expected name in each writable location and confirm the application does not load it
