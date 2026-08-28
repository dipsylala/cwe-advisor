# CWE-111: Direct Use of Unsafe JNI

## LLM Guidance

This weakness occurs when Java code calls native (JNI) functions and passes data across the managed/unmanaged boundary without validating it first, or when the native implementation itself uses JNI functions unsafely (unchecked lengths, missing null checks, unreleased references). Native code has none of Java's automatic memory safety, so any unvalidated data crossing the boundary can produce native-side memory corruption. The primary fix is to validate everything on the Java side before the native call and to use bounds-aware JNI accessor functions with proper error handling on the native side.

## Key Principles

- Validate all parameters (null, length, encoding, range) in Java before they cross into native code; do not rely on the native side to catch bad input
- Express the bound in bytes on the side that owns the buffer: `String.length()` counts UTF-16 code units, so a 100-character check passes a 300-byte UTF-8 encoding, and a Java-side character check does not bound a native `char[]`
- Validate on both sides deliberately - in Java for the error message and the fast rejection, in native code for the safety property, since the native function owns the buffer and may be reachable from another caller or binding
- Throwing a Java exception from JNI does not unwind: execution continues to the next statement, so check for a pending exception (`ExceptionCheck`) after every JNI call and return immediately rather than continuing with a NULL result
- Minimize the JNI surface: prefer pure Java or a managed interop layer over hand-written JNI
- In native code, use bounds-aware accessor functions and check every return value for null or error before use
- Release every acquired JNI resource (strings, array elements, local references) on every path, including errors
- Treat data returned from native code as untrusted and validate it again in Java, especially where it flows into a further sink
- Apply defence-in-depth: fuzz native entry points and run memory sanitizers against them in testing
- Use `GetPrimitiveArrayCritical`/`GetStringCritical` only where profiling shows the copy matters: they return a direct pointer into the JVM heap and can suspend garbage collection, so calling almost any other JNI function or blocking between acquire and release can deadlock the VM
- Where the native layer exists only to reach a library, the Foreign Function & Memory API (final in Java 22) does the same work from Java with bounds-checked memory segments and no hand-written C - removing the boundary removes the weakness

## Remediation Steps

- Locate - find the JNI boundary: the native method declaration in Java and its corresponding native implementation
- Trace data flow - follow parameters from their untrusted source through the Java call into the native function, and follow any values the native function returns back into Java
- Identify the unsafe pattern - missing length or null validation before the native call, or in native code: unchecked accessor return values, fixed-size buffers copied without a bounds check, or missing resource release
- Replace with the safe pattern - add explicit validation (null, length, encoding) in Java before the call, and in native code use length-aware accessor functions with buffers sized from actual validated data length
- Add secondary controls - check for pending exceptions after every JNI call and release all acquired references on every exit path
- Test - build the native library with `-fsanitize=address` and run the JVM with `-Xcheck:jni`, which reports unreleased references, wrong reference types, and calls made while an exception is pending that the normal runtime accepts silently. Send input at, one byte over, and far over the byte limit *as non-ASCII*, send a string containing `U+0000`, force each error path, and assert native heap usage returns to baseline afterwards
