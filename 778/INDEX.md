# CWE-778: Insufficient Logging

## LLM Guidance

Insufficient logging occurs when a security-relevant event, such as an authentication attempt, authorization failure, privilege change, or sensitive data access, is not recorded, or is recorded without enough detail to reconstruct what happened. This blocks detection, incident response, and audit after the fact, since the information was never captured. The fix is to record both success and failure for every security-relevant event with consistent, structured context, and to treat a failed log write as an event worth surfacing rather than silently dropping.

## Key Principles

- Log both the success and failure outcome of every security-relevant operation, not failures alone
- Capture enough context per entry to answer who, what, when, where, and with what result, not just that an event occurred
- Use structured, machine-parseable log entries rather than free-text messages so they can be queried and correlated
- Never log secrets, full credentials, session tokens, or other sensitive values in plaintext
- Protect log integrity with restricted write and read permissions, and tamper-evident storage for high-value logs
- Treat a failure to write a security log as an operational event to alert on, not a task that can fail silently

## Remediation Steps

- Locate - Identify security-relevant operations that lack a log call: authentication, authorization decisions, privilege changes, sensitive data access, and administrative actions
- Trace data flow - Confirm whether each branch, both success and failure, of these operations reaches a logging call before returning
- Identify the unsafe pattern - Look for branches that return or continue without logging, log entries missing actor, outcome, or resource identifiers, or logging built from unstructured string concatenation
- Replace with the safe pattern - Add a structured log entry on every security-relevant branch, including timestamp, actor, action, result, source, and a correlation identifier
- Add secondary controls - Ship logs to durable, access-controlled storage and configure alerting on patterns such as repeated failures or unexpected privilege grants
- Test - Trigger each security-relevant code path for both success and failure and confirm a log entry with the required fields is produced; confirm logs are retained and queryable
