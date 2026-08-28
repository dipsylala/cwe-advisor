# CWE-829: Inclusion of Functionality from Untrusted Control Sphere

## LLM Guidance

This vulnerability occurs when an application includes code, libraries, plugins, or configuration from a source it does not fully control - an unpinned CDN script, an unverified third-party package, a remotely fetched plugin, or a local include path that can resolve to an attacker-writable location. The defining risk is provenance, not the inclusion mechanism itself: even a static, hardcoded `<script src>` or `require()` call is vulnerable if what it loads can be swapped out by an attacker or a compromised upstream. This is distinct from CWE-94/CWE-95 (executing attacker-*supplied* code via `eval()`/`exec()` on tainted input) - CWE-829 is about functionality the application deliberately chooses to include, where the choice or verification of the source is the weakness. The core fix is verifying the integrity and origin of everything included, not removing dynamic execution (which may not even be present in a CWE-829 finding).

## Key Principles

- Identify every external source of included functionality: CDN scripts, third-party packages, plugins, remote configuration, dynamically resolved local includes
- Pin dependencies to exact, reviewed versions - never use floating or "latest" references for anything that gets executed
- Verify integrity at the point of inclusion: Subresource Integrity (SRI) hashes for CDN scripts, checksum/signature verification and lockfiles for packages, signed releases for plugins
- Restrict include/require/import paths so they cannot resolve to a user-controlled or externally-writable location
- Apply defence-in-depth by combining source verification, integrity checks, and a runtime restriction such as Content-Security-Policy
- Prefer the narrower entry where it fits: web functionality (a script, widget, or embedded content) is CWE-830, and PHP `include`/`require` of a remote path is CWE-98; this entry covers native libraries, package dependencies, dynamically loaded modules, and remote code reached through `eval`/`exec`
- Pin what is included by version *and* by digest, so a mutable tag or a re-published package version cannot change what runs
- Verify before executing against a key or hash you already hold, rather than against metadata the same source supplied (CWE-494)

## Remediation Steps

- Identify the vulnerability - find the specific include, import, script tag, or require call, and confirm exactly what source it resolves to (CDN URL, package registry, filesystem path, remote endpoint)
- Trace provenance - determine who controls that source, whether it is version-pinned, and whether an attacker or a compromised third party could alter what it serves
- Pin and verify - add SRI hashes to CDN scripts, lock package versions with checksums via a lockfile, and verify signatures for plugins or remote configuration where the ecosystem supports it
- Restrict resolution paths - ensure include/require/import paths cannot be influenced by user input or resolve outside a trusted directory
- Prefer static bundling over runtime fetching - where functionality can be bundled at build time instead of loaded dynamically, that removes this class of risk entirely
- Monitor for drift - alert when a pinned dependency's hash or version changes unexpectedly
