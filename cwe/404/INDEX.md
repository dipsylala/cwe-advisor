# CWE-404: Improper Resource Shutdown or Release

## LLM Guidance

This weakness occurs when a resource - file handle, socket, database connection, stream, or lock - is acquired but not properly released on all code paths, most often because cleanup is placed only on the success path or is skipped when an exception occurs. Unlike CWE-401, which centers on memory specifically, this covers any finite system resource whose exhaustion degrades or crashes the application. The primary fix is to use the language's automatic, deterministic resource-management construct so release is guaranteed on every exit path, including exceptions.

## Key Principles

- Use the language's automatic resource-management construct as the primary defence so release cannot be skipped by an early return or exception
- Where no such construct is available, place release logic in a guaranteed-execution block rather than after the code that uses the resource
- Release resources in reverse order of acquisition, and release derived or child resources before the parent they depend on
- Never let an exception raised during cleanup silently replace or hide the original exception; log it or attach it as a suppressed/chained exception instead
- Check for null or unset before releasing, and make cleanup idempotent so an already-released resource is not released again
- MITRE allows this ID with careful review, so use a child where one fits: memory specifically is CWE-401, a resource released but only partly is CWE-459, a release aimed at the wrong address is CWE-763, a certificate the issuer withdrew is CWE-299, and a file descriptor or handle is CWE-775
- Releasing a resource *twice* is the opposite defect and a different weakness (CWE-675), not a variant of this one
- Which children this class has depends on the CWE view, so a tool naming CWE-401 as a direct child is quoting the simplified-mapping view rather than being wrong

## Remediation Steps

- Locate - Identify where the resource is acquired and confirm whether release exists on all exit paths, including success, early return, and exception
- Trace control flow - Map every path out of the block that acquires the resource, including thrown exceptions and early returns
- Identify the unsafe pattern - Look for release calls placed only after the main logic, making them unreachable on exception, or release calls missing entirely
- Replace with the safe pattern - Wrap acquisition and use in the language's automatic resource-management construct so release is guaranteed
- Order multi-resource cleanup correctly - When multiple resources are involved, ensure release happens in reverse acquisition order
- Add secondary controls - Log cleanup failures without masking the original error, and monitor resource usage metrics for growth
- Test - Exercise both success and forced-exception paths and confirm the resource is released in each case; verify under sustained load that usage does not grow
