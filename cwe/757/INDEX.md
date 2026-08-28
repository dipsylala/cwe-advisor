# CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')

## LLM Guidance

CWE-757 occurs when a protocol's algorithm-negotiation process allows an attacker (often positioned as a man-in-the-middle) to steer the handshake toward a weaker algorithm or protocol version that both sides technically support, even though a stronger option was available - as in TLS cipher-suite downgrade, SSLv3 fallback (POODLE), or export-grade key-exchange forcing (FREAK, Logjam). Unlike simply using a weak algorithm outright (see CWE-327 for broken/risky algorithms or CWE-916 for weak password hashing), the flaw here is in the negotiation itself: the implementation accepts a weaker choice than it should have. The fix is to remove weak algorithms and protocol versions from the set the implementation will ever accept, not merely deprioritize them, and to reject any fallback or downgrade attempt.

## Key Principles

- Configure the server/client to only offer and accept strong, modern algorithms and protocol versions - remove weak options from the negotiable set entirely rather than ranking them last
- Disable protocol version fallback and insecure renegotiation (reject legacy protocol handshakes; disable fallback mechanisms that let a failed modern handshake retry at a lower version)
- Do not let the client unilaterally dictate the selected algorithm - the server must enforce its own minimum-strength policy regardless of what the client offers or requests
- Apply the same negotiation hardening to any protocol with algorithm agility, not just TLS - SSH key exchange, IPsec, and custom application-level negotiation handshakes are equally susceptible
- Monitor and log negotiation attempts that request deprecated algorithms or protocol versions, since repeated attempts can indicate an active downgrade attack
- Remove weak algorithms from the negotiable set rather than merely preferring strong ones: the server's own list decides the floor, so anything still listed has already been agreed to if asked, and an on-path attacker only has to rewrite the proposal so the weakest mutually supported option is the only one
- Verify the negotiation transcript so a rewritten offer is detected and the handshake aborted rather than silently downgraded
- Distinguish from CWE-327: a specific broken algorithm hardcoded with no negotiation involved belongs there, and downgrade, fallback, or negotiation behaviour belongs here

## Remediation Steps

- Identify the negotiation point - Locate where the protocol or library selects an algorithm or protocol version from a supported set (TLS cipher suite list, SSH key-exchange algorithm list, custom negotiation handshake)
- Audit the accepted set - List every algorithm and protocol version the implementation will currently accept, not just what it prefers
- Remove weak options entirely - Delete deprecated or broken algorithms and protocol versions from the accepted set rather than deprioritizing them
- Disable fallback mechanisms - Turn off downgrade/fallback support so a failed handshake at the target strength does not retry at a lower one
- Enforce server-side minimums - Configure the server to reject any negotiated result below its minimum acceptable strength, even if the client requested it
- Test downgrade resistance - Attempt a handshake offering only weak or deprecated options and confirm the connection is rejected rather than negotiated
- Monitor - Log and alert on negotiation attempts referencing deprecated algorithms or protocol versions
