# CWE-498: Cloneable Class Containing Sensitive Information

## LLM Guidance

This weakness occurs when a class holding credentials, keys, tokens, or a security context implements a language's duplication mechanism (a clone method, copy constructor, or equivalent), letting any code holding a reference produce an unauthorized, untracked copy that bypasses the constructor and whatever validation it normally enforces. The core fix is to remove the cloning mechanism from sensitive classes; if a copy is genuinely required, expose it as an explicit factory method that still goes through construction.

## Key Principles

- Primary defence: do not implement the language's clone/copy interface on any class that stores sensitive data
- Mark sensitive classes as non-subclassable so a subclass cannot add cloning support the base class deliberately omits
- Where a copy is genuinely needed, provide an explicit factory method that reconstructs through the constructor, not a generic clone hook
- If cloning cannot be avoided, gate it with an authorization check performed before the copy is produced, and deep-copy every mutable field rather than relying on default shallow-copy behavior
- Log any legitimate clone/copy operation the same way a new credential issuance would be logged
- Defence-in-depth: ensure every copy of sensitive data is tracked so it can be securely cleared from memory when no longer needed

## Remediation Steps

- Locate - Identify classes storing credentials, keys, tokens, or authorization context (source) and any cloning mechanism implemented on them (sink)
- Trace data flow - Determine which fields the clone/copy operation touches and whether it performs a shallow or deep copy
- Identify the unsafe pattern - A cloning interface implemented without an authorization check, or default shallow-copy behavior exposing shared mutable state
- Replace with the safe pattern - Remove the cloning interface and add a factory method that constructs through the class's normal validation path
- Add secondary controls - Authorization check and audit logging if cloning must remain supported for a specific workflow
- Test - Attempt to clone or copy the class from outside its intended path and confirm it is rejected, or properly authorized, deep-copied, and logged
