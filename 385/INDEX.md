# CWE-385: Covert Timing Channel

## LLM Guidance

A covert timing channel is a deliberate, out-of-band communication path: two mutually distrusting or otherwise-isolated processes exchange information by having one modulate its use of a resource it shares with the other (CPU load, lock acquisition/release timing, cache occupancy, disk I/O pacing, induced faults) in an observable pattern, and the other decodes that pattern from the outside. This differs from CWE-208 (Observable Timing Discrepancy), where an attacker passively infers a secret from a single component's incidental response-time variation - CWE-385 requires an encoding sender and a decoding receiver cooperating across a boundary that is supposed to prevent them from communicating directly (a sandbox, a VM boundary, a mandatory access control policy, a multi-tenant host). The fix is architectural: eliminate or tightly control the shared, observable resource between the isolated principals rather than trying to patch the encoding pattern itself.

## Key Principles

- Identify which resources are shared between processes or principals that a security boundary (sandbox, VM, MAC policy, tenant isolation) is supposed to keep from communicating
- Prefer eliminating the shared resource entirely (dedicated cores, partitioned caches, separate physical hardware) over trying to rate-limit or obscure its use
- Where a shared resource cannot be eliminated, reduce its observability: quantize or add noise to timing/usage metrics exposed across the boundary, or restrict high-resolution timing measurement for the untrusted side
- Treat unusual, structured resource-usage patterns (rhythmic CPU spikes, patterned lock contention) as a potential exfiltration signal worth monitoring, not just noise
- Apply this at the architecture/isolation layer - this is not a code-level input-validation or output-encoding fix

## Remediation Steps

- Locate - Identify the isolation boundary in question (sandbox, container, VM, MAC/DAC policy, multi-tenant host) and the two principals it is meant to keep from communicating
- Identify the shared resource - Determine which resource (CPU scheduling, shared cache, shared lock, shared disk/network queue, power/thermal state) both principals can observe or influence
- Assess encoding capability - Confirm whether one principal can modulate its use of that resource in a way the other can measure and decode
- Remove or partition the resource - Where feasible, give each principal dedicated hardware or a partitioned resource (cache partitioning, core pinning, separate I/O queues) so there is nothing left to modulate
- Reduce observability - Where partitioning isn't feasible, quantize exposed timing/usage metrics, inject scheduling jitter at the boundary, or restrict high-resolution timers for the lower-trust principal
- Monitor - Add anomaly detection for structured, repeating resource-usage patterns that don't match normal workload behavior
- Test - Attempt to build a working covert channel between the two principals (send a known bit pattern via the suspected resource) and confirm it can no longer be decoded reliably
