# CWE-1426: Improper Validation of Generative AI Output - JavaScript

## LLM Guidance

In Node.js/TypeScript apps using `@anthropic-ai/sdk` (or OpenAI's, which follows the same pattern), the common mistake is treating a model's text response, a `tool_use` block's `input`, or a generated filename as trusted because the model produced it, then passing it to `eval()`, `child_process.exec()`, a template string used as HTML, or `fs.writeFile()` without the validation that path would require for user input. Constrain output shape with structured outputs (Zod schema) where possible, and validate tool-call arguments and generated paths exactly as you would a client-supplied request body.

## Key Principles

- Never pass a model's text response or `tool_use.input` value to `eval()`, `child_process.exec()`, a template-literal SQL query, or `dangerouslySetInnerHTML` without the same validation that path requires for user input - see this repo's code injection, command injection, SQL injection, and XSS guidance for the sink-specific fix
- Use `output_config.format` with `zodOutputFormat()` (or a raw JSON Schema) to constrain response shape instead of parsing free text - this narrows the injection surface for whatever consumes the output downstream
- Validate every field of `tool_use.input` against expected types and ranges before use - re-parse it through the same Zod schema (or equivalent) you would apply to an HTTP request body, don't assume the model's JSON already conforms
- Treat any filename or path present in model output or a tool result as attacker-controlled: reject the value if `path.basename(name) !== name` rather than silently rewriting it - `path.basename('../../etc/passwd')` returns `'passwd'` and writes successfully, which is a different file than the one requested, not a safe version of it
- A model claiming in its text output that it "verified" or "checked" something is not evidence of anything - perform independent verification for security-relevant claims
- Never authorize an action from a field inside `tool_use.input` (a user or resource ID the model echoed back) - it is model-influenced; authorize from the actual authenticated session only

## Taint Sinks

`eval()`, `child_process.exec()`/`execSync()`, unchecked `tool_use.input` passed to a handler, `fs.writeFile()` with a model-provided filename

## Remediation Steps

- Locate every point where a model's text response, a `tool_use.input` field, or a filename from a tool result reaches `eval`, `child_process.exec`/`execSync`, a SQL query, a filesystem call, or an HTML render
- For each sink, apply this repo's existing guidance for that sink type (code injection, command injection, SQL injection, path traversal, XSS), treating the model as the untrusted source
- Where free-form parsing extracts structured data, replace it with `client.messages.parse()` and `output_config.format` using `zodOutputFormat()` from `@anthropic-ai/sdk/helpers/zod`, reading the validated object from `response.parsed_output`
- Re-validate every `tool_use.input` field with the same Zod schema (or equivalent) used for the corresponding HTTP endpoint, before the tool handler acts on it
- Reject any model- or tool-produced filename where `path.basename(name) !== name`, or that resolves to `.` or `..`, rather than rewriting it to the basename and proceeding
- Test with a mocked or adversarial model response containing an out-of-schema value, a path-traversal filename (`../../etc/passwd`), or an injection payload in a text field, and confirm validation rejects it before the sink executes
