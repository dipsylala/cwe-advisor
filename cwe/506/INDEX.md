# CWE-506: Embedded Malicious Code

## LLM Guidance

Embedded malicious code includes backdoors, logic bombs, time bombs, and trojans intentionally placed in source code or dependencies. Compromised npm packages, malicious gems, and supply chain attacks inject code that steals credentials, creates backdoors, or triggers on specific conditions.

## Key Principles

- Enforce mandatory code review for all changes, especially from new contributors
- Implement dependency signing and provenance verification
- Scan for obfuscated code patterns (base64, eval/exec, encoded payloads)
- Monitor for unexpected behaviors like unauthorized network calls or file access
- Establish supply chain security controls for all third-party dependencies
- Treat the finding as a compromise of everything the code could reach, not just a defect to delete: pinning, signing and review controls prevent the next one and do not undo this one, so rotate the credentials and tokens that were in reach
- Remove the code or the compromised package version and rebuild from a source tree you have reviewed - do not patch the built artifact
- Obfuscation is itself the signal worth acting on, independent of what it turns out to do: base64 blobs, `eval`/`exec`, and encoded payloads in a dependency are grounds to stop and inspect
- Where the malicious behaviour waits for a date, event, or threshold before acting, the finding is CWE-511

## Remediation Steps

- Examine all dependencies - Review npm packages, pip packages, gems, JARs for suspicious activity
- Review recent code changes - Check commits for obfuscation, unexpected network calls, or process execution
- Search for red flags - `eval(base64.b64decode(...))`, `exec(__import__('base64').b64decode(...))`, hardcoded credentials
- Identify backdoors - Look for hidden authentication bypasses, unknown domain connections
- Remove malicious code - Delete compromised dependencies, revert suspicious commits, replace with verified versions
- Verify provenance - Use lock files, check package signatures, audit dependency chains
