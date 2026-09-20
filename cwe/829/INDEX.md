# CWE-829: Inclusion of Functionality from Untrusted Control Sphere

## LLM Guidance

The defining risk is provenance, not the inclusion mechanism: a static, hardcoded `<script src>` or `require()` is in scope if what it loads can be swapped by an attacker or a compromised upstream. That separates it from CWE-94 and CWE-95, which cover executing attacker-*supplied* code - here the application deliberately chooses to include the functionality, and the weakness is in how the source is chosen or verified. Web functionality such as a script, widget, or embedded content is CWE-830, and PHP `include`/`require` of a remote path is CWE-98.

## Key Principles

- Identify every external source of included functionality: CDN scripts, third-party packages, plugins, remote configuration, dynamically resolved local includes
- Pin dependencies to exact, reviewed versions - never use floating or "latest" references for anything that gets executed
- Verify integrity at the point of inclusion: Subresource Integrity (SRI) hashes for CDN scripts, checksum/signature verification and lockfiles for packages, signed releases for plugins
- Restrict include/require/import paths so they cannot resolve to a user-controlled or externally-writable location
- Apply defence-in-depth by combining source verification, integrity checks, and a runtime restriction such as Content-Security-Policy
- Pin what is included by version *and* by digest, so a mutable tag or a re-published package version cannot change what runs
- Verify before executing against a key or hash you already hold, rather than against metadata the same source supplied (CWE-494)

## Remediation Steps

- Identify the vulnerability - find the specific include, import, script tag, or require call, and confirm exactly what source it resolves to (CDN URL, package registry, filesystem path, remote endpoint)
- Trace provenance - determine who controls that source, whether it is version-pinned, and whether an attacker or a compromised third party could alter what it serves
- Pin and verify - add SRI hashes to CDN scripts, lock package versions with checksums via a lockfile, and verify signatures for plugins or remote configuration where the ecosystem supports it
- Restrict resolution paths - ensure include/require/import paths cannot be influenced by user input or resolve outside a trusted directory
- Prefer static bundling over runtime fetching - where functionality can be bundled at build time instead of loaded dynamically, that removes this class of risk entirely
- Monitor for drift - alert when a pinned dependency's hash or version changes unexpectedly
