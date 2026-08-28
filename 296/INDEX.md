# CWE-296: Improper Following of a Certificate's Chain of Trust

## LLM Guidance

This weakness occurs when code validates parts of a certificate but does not properly build and verify the full chain up to a trusted root, accepts incomplete or self-signed chains, or trusts certificates outside the intended trust anchor set. The core fix is to rely on the platform or library's standard chain-validation path against an explicit, minimal trust store instead of custom chain-walking or trust logic, and to never disable chain validation for convenience.

## Key Principles

- Rely on the standard TLS/X.509 library's built-in chain validation rather than writing custom trust-chain logic
- Never disable certificate verification (permissive trust managers, "verify=false", accept-all callbacks), even temporarily for debugging
- Configure an explicit trust store containing only the intended root and intermediate CAs when the default OS-wide trust set is broader than required
- Validate the full chain to a trusted root, not just the leaf certificate or a single intermediate
- Combine chain validation with hostname verification and expiration checks; chain trust alone does not prove the certificate belongs to the expected host
- Use certificate or public key pinning for high-value connections as defence-in-depth, with a documented rotation plan
- Supplying a custom CA *replaces* the default trust store in most clients rather than adding to it, so internal services start working while every public host fails - and the usual response to that is to disable validation entirely. Include the platform defaults alongside your CA
- Validate the chain first and pin the verified leaf: a pin check that runs before validation compares the pinned hash against *some* certificate in the presented chain, so an attacker can attach the pinned CA or intermediate to a chain ending in a leaf of their own and the pin still matches

## Remediation Steps

- Locate - Find where TLS connections are established or certificates are manually parsed or verified (custom trust manager, HTTP client configuration, socket wrapper)
- Trace data flow - Follow the certificate and its chain from the peer handshake to the point where a trust decision is made
- Identify the unsafe pattern - Custom trust logic that returns without validating, missing chain construction, blanket CA acceptance, or caught and ignored chain-validation errors
- Replace with the safe pattern - Use the platform's default trust manager or validator backed by a defined trust store, or a maintained TLS library with full chain validation enabled
- Add secondary controls - Enforce hostname verification, require a minimum TLS version, and consider pinning for critical endpoints
- Test - Attempt a connection with a certificate signed by an untrusted CA and confirm rejection; connect with a valid chain and confirm success
