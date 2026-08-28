# CWE-1105: Insufficient Encapsulation of Machine-Dependent Functionality

## LLM Guidance

This weakness appears when code relies directly on machine-dependent characteristics, such as pointer width, byte order, memory alignment, or CPU-specific instruction sets, instead of isolating those assumptions behind a portable interface. The assumption holds on the development platform but breaks silently on a different architecture: a pointer truncates, a multi-byte value is misread, an unaligned access faults, or a missing CPU feature is used anyway. The remediation strategy is to make every machine-dependent assumption explicit, verified at runtime or by the type system, and centralized behind a single isolated interface rather than scattered through general logic.

## Key Principles

- Never assume a native integer type matches the platform's pointer width; use an explicit pointer-sized type instead
- Convert byte order explicitly at every serialization boundary (file, network, inter-process); never reinterpret a raw byte buffer as a multi-byte value directly
- Never access a multi-byte value through a pointer that is not guaranteed to be properly aligned for that type
- Detect CPU-specific instruction set availability at runtime rather than assuming it is present, and always provide a correct fallback
- Centralize all machine-dependent or platform-conditional code in one isolated, well-documented location instead of scattering assumptions through general application logic
- Treat an absent hardware feature or platform mismatch as a functionality or performance change, never a silent security downgrade
- MITRE marks this Prohibited for mapping - "primarily a quality issue with no direct security implications" - so file the consequence instead and use this entry as the remediation reference: a truncated pointer is CWE-197 (or the memory-safety CWE for what the truncated address reaches), a layout or byte-order assumption is CWE-188 or CWE-1102, and a hardware capability assumed rather than handled leaves a variable unassigned on the branch nobody wrote, which is CWE-457

## Remediation Steps

- Locate - Identify code that assumes a specific pointer width, byte order, memory alignment, or CPU instruction set is present
- Trace data flow - Follow the value through casts, serialization, deserialization, and any point where it crosses a platform or process boundary
- Identify the unsafe pattern - Look for narrow-integer pointer casts, raw buffer reinterpretation as a multi-byte type, unaligned pointer dereferences, or CPU feature use without a detection check
- Replace with the safe pattern - Use pointer-sized integer types, explicit byte-order conversion functions, alignment-safe copy-based access, and runtime feature detection with a correct fallback path
- Isolate machine-dependent code - Move platform- or architecture-specific branches into a single, centralized, clearly documented location
- Add secondary controls - Document the supported platforms and architectures, and add build-time or runtime assertions that fail loudly if an assumption does not hold
- Test - Verify behavior on a different word size and byte order than the primary development platform, and force the CPU-feature fallback path to confirm it is correct and does not weaken any security property
