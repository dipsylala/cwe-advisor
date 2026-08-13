# LLM-Navigated Data Flow Trace

Fallback for SKILL.md Step 4 (Trace the Data Flow) when no SAST/DAST tool provides a call path or taint trace for the finding. Trace the flow yourself, using code navigation tooling (e.g. `find_all_references`, `go_to_definition`, symbol search) to speed up any of these steps where available, or reading the code directly otherwise:

1. **Start at the sink** - locate the exact operation the scanner flagged (e.g. SQL query, shell exec, file write). This is your fixed reference point.
2. **Trace backwards** - follow the data through function calls, assignments, and transformations back towards the entry point. Note every place the value passes through without validation or sanitisation - these are candidate fix points.
3. **Identify the source** - where does the untrusted input originally enter the application (HTTP request, file, environment variable, IPC, etc.)?
4. **Find the best fix point** - the first trust boundary the data crosses (e.g., HTTP handler, CLI parser, file reader) where input can be validated before reaching any sink. If no clear trust boundary exists, choose the earliest function in the call chain where the raw input is available in a form that can be validated.
5. **Forward pass for other sinks** - from that fix point, briefly check whether the same input flows to any other dangerous operations that would also need covering.
