# CWE-1426: Improper Validation of Generative AI Output - Python

## LLM Guidance

In Python apps calling the Anthropic `anthropic` SDK (or OpenAI's, which follows the same pattern), the common mistake is treating a model's text response, tool-call arguments, or a generated filename as trusted because "the model produced it," then passing it to `eval()`, a shell, a SQL driver, `open()`, or an HTML template without the validation that code would require for user input. Constrain output shape with structured outputs where possible, and validate tool-call arguments and generated paths exactly as you would a client-supplied API request.

## Key Principles

- Never pass a model's text response or tool-call argument to `eval()`, `subprocess` with `shell=True`, an f-string SQL query, or `Markup()`/`|safe` in a template without the same validation that input reaching that sink requires - see this repo's code injection, command injection, SQL injection, and XSS guidance for the sink-specific fix
- Use `output_config={"format": {"type": "json_schema", "schema": {...}}}` (or `client.messages.parse()` with a Pydantic model) to constrain response shape instead of parsing free text with regex - this narrows the injection surface for whatever consumes the output
- Validate every `tool_use.input` field against expected types and ranges before use, the same as validating a client-supplied request body - do not assume the model's JSON output already conforms to the schema you gave it
- Treat any filename or path present in model output or a tool result as attacker-controlled: apply `os.path.basename()` and confirm the resolved path stays within the intended directory before any file write or read
- A model claiming it "verified" or "checked" something in its text output is not evidence of anything - perform independent verification for security-relevant claims

## Taint Sinks

`eval()`/`exec()`, `subprocess` with `shell=True`, unchecked `tool_use.input` passed to a handler, `open()` with a model-provided filename

## Remediation Steps

- Locate every point where a model's text response, `tool_use.input` value, or a filename from a tool result reaches `eval`/`exec`, a shell call, a SQL query, a file operation, or an HTML/template render
- For each sink, apply this repo's existing guidance for that sink type (code injection, command injection, SQL injection, path traversal, XSS), treating the model as the untrusted source
- Where free-form parsing is used to extract structured data, replace it with `output_config.format` (JSON Schema) or `client.messages.parse()` against a Pydantic model
- Add explicit type and range checks on every `tool_use.input` field before it is used, matching what you would validate on an equivalent HTTP request body
- Sanitize any model- or tool-produced filename with `os.path.basename()` and verify the resolved path is contained within the target directory before writing
- Test with a mocked or adversarial model response that returns an out-of-schema value, a path-traversal filename (`../../etc/passwd`), or an injection payload in a text field, and confirm the validation layer rejects it before the sink executes

## Safe Pattern

```python
import os
from pydantic import BaseModel

class RefundRequest(BaseModel):
    order_id: str
    amount_cents: int

# SAFE: structured output constrains the shape; still validate the parsed values
response = client.messages.parse(
    model="claude-opus-5",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Summarize the refund request as JSON"}],
    output_format=RefundRequest,
)
refund = response.parsed_output
if refund.amount_cents <= 0 or refund.amount_cents > order.total_cents:
    raise ValueError("Refund amount out of range")  # SAFE: range-check model output before use

def handle_tool_call(tool_use):
    if tool_use.name == "write_report":
        # SAFE: filenames from tool input are attacker-controlled - sanitize
        # and confirm containment before any filesystem write
        safe_name = os.path.basename(tool_use.input["filename"])
        if not safe_name or safe_name in (".", ".."):
            raise ValueError("Invalid filename")
        output_path = os.path.join(OUTPUT_DIR, safe_name)
        if not os.path.abspath(output_path).startswith(os.path.abspath(OUTPUT_DIR)):
            raise ValueError("Path escapes output directory")
        with open(output_path, "w") as f:
            f.write(tool_use.input["content"])
```
