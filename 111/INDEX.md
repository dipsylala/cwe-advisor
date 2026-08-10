# CWE-111: Direct Use of Unsafe JNI

## LLM Guidance

This weakness occurs when Java code calls native (JNI) functions and passes data across the managed/unmanaged boundary without validating it first, or when the native implementation itself uses JNI functions unsafely (unchecked lengths, missing null checks, unreleased references). Native code has none of Java's automatic memory safety, so any unvalidated data crossing the boundary can produce native-side memory corruption. The primary fix is to validate everything on the Java side before the native call and to use bounds-aware JNI accessor functions with proper error handling on the native side.

## Key Principles

- Validate all parameters (null, length, encoding, range) in Java before they cross into native code; do not rely on the native side to catch bad input
- Minimize the JNI surface: prefer pure Java or a managed native-interop layer over hand-written JNI wherever performance or platform needs allow
- In native code, use bounds-aware accessor functions and check every return value for null or error before use
- Always release every acquired JNI resource (strings, array elements, local references), including on error paths
- Treat data returned from native code as untrusted; validate it again in Java before use, especially if it flows into a further sink such as SQL or HTML output
- Apply defence-in-depth: fuzz native entry points and run memory sanitizers against them in testing

## Remediation Steps

- Locate - find the JNI boundary: the native method declaration in Java and its corresponding native implementation
- Trace data flow - follow parameters from their untrusted source through the Java call into the native function, and follow any values the native function returns back into Java
- Identify the unsafe pattern - missing length or null validation before the native call, or in native code: unchecked accessor return values, fixed-size buffers copied without a bounds check, or missing resource release
- Replace with the safe pattern - add explicit validation (null, length, encoding) in Java before the call, and in native code use length-aware accessor functions with buffers sized from actual validated data length
- Add secondary controls - check for pending exceptions after every JNI call, release all acquired references on every exit path including errors, and re-validate any data returned from native code before using it downstream
- Test - exercise the native boundary with oversized, null, and malformed input, and confirm with a memory sanitizer that no out-of-bounds access or leak occurs
