# CWE-1426: Improper Validation of Generative AI Output - JavaScript

## LLM Guidance

In Node.js/TypeScript apps using `@anthropic-ai/sdk` (or OpenAI's, which follows the same pattern), the common mistake is treating a model's text response, a `tool_use` block's `input`, or a generated filename as trusted because the model produced it, then passing it to `eval()`, `child_process.exec()`, a template string used as HTML, or `fs.writeFile()` without the validation that path would require for user input. Constrain output shape with structured outputs (Zod schema) where possible, and validate tool-call arguments and generated paths exactly as you would a client-supplied request body.

## Key Principles

- Never pass a model's text response or `tool_use.input` value to `eval()`, `child_process.exec()`, a template-literal SQL query, or `dangerouslySetInnerHTML` without the same validation that path requires for user input - see this repo's code injection, command injection, SQL injection, and XSS guidance for the sink-specific fix
- Use `output_config.format` with `zodOutputFormat()` (or a raw JSON Schema) to constrain response shape instead of parsing free text - this narrows the injection surface for whatever consumes the output downstream
- Validate every field of `tool_use.input` against expected types and ranges before use - re-parse it through the same Zod schema (or equivalent) you would apply to an HTTP request body, don't assume the model's JSON already conforms
- Treat any filename or path present in model output or a tool result as attacker-controlled: apply `path.basename()` and confirm the resolved path is contained within the intended directory before any file write or read
- A model claiming in its text output that it "verified" or "checked" something is not evidence of anything - perform independent verification for security-relevant claims

## Remediation Steps

- Locate every point where a model's text response, a `tool_use.input` field, or a filename from a tool result reaches `eval`, `child_process.exec`/`execSync`, a SQL query, a filesystem call, or an HTML render
- For each sink, apply this repo's existing guidance for that sink type (code injection, command injection, SQL injection, path traversal, XSS), treating the model as the untrusted source
- Where free-form parsing extracts structured data, replace it with `output_config.format` using `zodOutputFormat()` from `@anthropic-ai/sdk/helpers/zod`
- Re-validate every `tool_use.input` field with the same Zod schema (or equivalent) used for the corresponding HTTP endpoint, before the tool handler acts on it
- Sanitize any model- or tool-produced filename with `path.basename()` and verify the resolved path stays within the target directory before writing
- Test with a mocked or adversarial model response containing an out-of-schema value, a path-traversal filename (`../../etc/passwd`), or an injection payload in a text field, and confirm validation rejects it before the sink executes

## Safe Pattern

```typescript
import path from "path";
import fs from "fs/promises";
import { z } from "zod";
import { zodOutputFormat } from "@anthropic-ai/sdk/helpers/zod";

const RefundRequest = z.object({
  orderId: z.string(),
  amountCents: z.number().int(),
});

// SAFE: structured output constrains the shape; still validate the parsed values
const response = await client.messages.parse({
  model: "claude-opus-5",
  max_tokens: 1024,
  messages: [{ role: "user", content: "Summarize the refund request as JSON" }],
  output_config: { format: zodOutputFormat(RefundRequest) },
});
const refund = response.parsed_output!;
if (refund.amountCents <= 0 || refund.amountCents > order.totalCents) {
  throw new Error("Refund amount out of range"); // SAFE: range-check model output before use
}

async function handleToolCall(toolUse: Anthropic.ToolUseBlock) {
  if (toolUse.name === "write_report") {
    const input = toolUse.input as { filename: string; content: string };
    // SAFE: filenames from tool input are attacker-controlled - sanitize and
    // confirm containment before any filesystem write
    const safeName = path.basename(input.filename);
    if (!safeName || safeName === "." || safeName === "..") {
      throw new Error("Invalid filename");
    }
    const outputPath = path.join(OUTPUT_DIR, safeName);
    if (!path.resolve(outputPath).startsWith(path.resolve(OUTPUT_DIR))) {
      throw new Error("Path escapes output directory");
    }
    await fs.writeFile(outputPath, input.content);
  }
}
```
