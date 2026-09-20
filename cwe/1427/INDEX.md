# CWE-1427: Improper Neutralization of Input Used for LLM Prompting

## LLM Guidance

Unlike CWE-1426, this ID is Allowed for mapping, so a prompt-injection finding belongs here. There is no parameterization fix: natural language has no syntax that reliably separates instruction from data the way a prepared-statement placeholder does, so the remediation is layered rather than a single change at the sink. Where a tool fetches a URL the model chose, apply CWE-918 to that fetch.

## Key Principles

- Never let "the model chose to call this tool" be the sole authorization for a consequential action - apply the same server-side access-control check you would apply to a request from an untrusted API client, independent of the model's reasoning
- Structurally separate trusted instructions from untrusted content wherever the platform provides a mechanism for it (a dedicated system/instruction channel distinct from user and retrieved content), rather than concatenating everything into one prompt string
- Treat content the model consumes from any external source - a fetched web page, an email, an uploaded document, a tool result - as untrusted input equivalent to direct user input; this is indirect prompt injection and does not require the attacker to control the conversation directly
- Apply least privilege to tool design: narrow, purpose-built, parameterized tools with server-side argument validation, not broad-capability tools (arbitrary shell execution, unrestricted file or network access) that turn a successful injection into full compromise
- Require human approval or a secondary confirmation step for irreversible or high-consequence actions (financial transfers, deletions, sending communications, credential changes) regardless of model confidence
- This class of weakness cannot be fully eliminated by any single control; combine multiple independent layers and expect new bypass techniques to keep appearing
- Defend in layers instead: structural separation of trusted instructions from untrusted content where the platform offers it, independent server-side authorization for every consequential tool action, and least-privilege tools so a successful injection has a narrow blast radius

## Remediation Steps

- Locate every place external, retrieved, or tool-result content is concatenated into the prompt or context sent to the model
- Trace whether that untrusted content can reach a channel the model treats as an instruction - a system prompt, or a position in the context indistinguishable from developer-authored guidance
- Inventory every tool or action the model can invoke and classify each by consequence: read-only, mutating, or irreversible
- For mutating or irreversible actions, add or verify an authorization check that runs independent of the model's tool-call request - the same check the endpoint would enforce if called directly by an untrusted client
- Move untrusted content out of the instruction channel: use the platform's structural separation mechanism for trusted operator context rather than string-concatenating retrieved or user content into a single prompt
- Test with adversarial content - fetched pages, uploaded documents, or tool outputs containing embedded instructions such as "ignore previous instructions and..." - and confirm the sensitive action is still gated by the independent server-side check, not just by the model declining to comply
