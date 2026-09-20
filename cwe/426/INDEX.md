# CWE-426: Untrusted Search Path

## LLM Guidance

The search path itself is attacker-influenced. Where the path is fixed and one element already in it is attacker-writable, that is CWE-427 - a distinction that decides the fix, since the names in circulation (DLL preloading, binary planting, dependency confusion) are used for both.

## Key Principles

- Always use absolute paths for executables and libraries
- Never rely on PATH, LD_LIBRARY_PATH, or similar environment variables
- Restrict search paths to trusted system directories only
- Verify integrity of loaded components when possible
- Remove current/relative directories from search order
- The test that separates this from CWE-427 is whether the attacker had to change the path: if they only had to write a file into a directory already on it, the finding belongs to CWE-427
- Resolve relative paths against a fixed base - the install directory or a configured root - never against the working directory, which is attacker-influenced, so joining a relative name to it produces an absolute path no more trustworthy than the name was

## Remediation Steps

- Review flaw details to identify where resources are loaded from untrusted paths
- Identify resource types being loaded - executables, libraries, DLLs, shared objects, or config files
- Check how resources are located - relative paths, PATH variable, LD_LIBRARY_PATH, or system search order
- Determine if attackers can control any directories in the search path
- Replace all relative paths with absolute paths (e.g., `/usr/local/bin/tool` instead of `tool`)
- Remove dependency on environment variables for critical resource loading
