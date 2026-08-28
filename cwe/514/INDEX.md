# CWE-514: Covert Channel

## LLM Guidance

A covert channel is any path a program uses to leak information through an unintended side effect, such as execution timing, resource consumption, or its effect on shared state, rather than through a sanctioned output. Most concrete findings resolve to one of two specific mechanisms, timing-based or storage-based, so identify which one applies before remediating: a timing leak (e.g., credential checks that return faster for one failure mode than another) needs constant-time handling, while a storage leak needs the shared resource written to independently of the secret.

## Key Principles

- Primary defence: make the observable side effect independent of the secret value it might otherwise reveal
- Identify the concrete mechanism first: timing, storage/shared state, or resource usage (for example, compression ratio revealing plaintext content)
- For timing-based leaks, use constant-time comparison and equalize code paths so duration does not depend on the secret
- For storage/shared-state leaks, write to the shared resource unconditionally rather than only on a specific outcome, so its state does not correlate with the secret
- Where the side effect cannot be fully equalized, restrict who can observe it: avoid exposing fine-grained timing or resource detail through debug endpoints, verbose logs, or detailed error responses to untrusted callers
- Defence-in-depth: rate-limit operations that would let an observer collect enough samples to exploit a residual channel statistically
- Identify the channel before remediating: a duration that varies with secret data is CWE-385, an effect on a shared resource another party can observe (a file's existence, a cache entry, a counter, an error log) is CWE-515, and only a channel that is genuinely neither belongs on this entry
- Resource consumption is a channel too - compression ratio revealing plaintext content is the CRIME/BREACH shape, and it is not fixed by anything that equalizes timing

## Remediation Steps

- Locate - Identify the operation that processes secret data (source) and every observable side effect it produces: response time, log entry, file or cache state, response size (sink)
- Trace data flow - Determine whether the side effect's value or timing varies depending on the secret
- Identify the unsafe pattern - A side effect that correlates with secret data and is observable by an unauthorized party
- Replace with the safe pattern - Equalize or eliminate the variation through constant-time operations, unconditional shared-state writes, or padded and normalized output
- Add secondary controls - Restrict exposure of fine-grained timing or resource metrics to untrusted callers and rate-limit the operation
- Test - Measure the side effect across many trials with different secret values and confirm it no longer correlates with the secret
