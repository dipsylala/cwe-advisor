# CWE-494: Download of Code Without Integrity Check

## LLM Guidance

This vulnerability occurs when applications download code or executables from external sources without verifying their integrity, allowing attackers to inject malicious code. Only download and install code with integrity verification (cryptographic signatures or hashes) from trusted sources over secure transport.

## Key Principles

- Verify integrity using pinned hashes, signed metadata, SRI, or package-manager signature/lockfile verification from a trusted source before executing downloaded code
- Download code only from trusted, authenticated sources over secure channels (HTTPS/TLS)
- Implement checksum verification for all packages, plugins, scripts, and executables
- Use package managers with built-in integrity checking and signed repositories
- Fail securely if integrity verification fails - never execute unverified code
- Verify against something the *download server does not control*: a signature made with a publisher key you already hold, or a hash pinned in your own source. A checksum served from the same host as the artifact proves only that the transfer completed
- TLS authenticates the channel, not the artifact - it says the bytes came from that host unmodified, which is a different claim from the bytes being the ones the publisher produced
- Verify before executing, and treat an unverifiable artifact as a failure rather than proceeding with a warning

## Remediation Steps

- Identify download operations - Review scan data_paths to find HTTP downloads, package installations, plugin loading, and script fetching
- Check for missing verification - Look for absent hash checks, signature validation, or checksum verification in download code
- Add integrity checks - Implement pinned hash verification (SHA-256+), signature verification, SRI, or trusted lockfile/package-manager verification before executing or importing downloaded code
- Use secure sources - Replace HTTP with HTTPS; use official package repositories with signature verification
- Validate before execution - Ensure downloaded files match expected hashes/signatures before `exec()`, `import`, or plugin load operations
- Handle failures securely - Reject and log downloads that fail integrity checks; do not fall back to unverified execution
