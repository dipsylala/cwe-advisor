# CWE-359: Exposure of Private Personal Information to an Unauthorized Actor

## LLM Guidance

Privacy violations occur when applications expose PII (names, SSN, medical data, financial info) through logs, error messages, APIs, URLs, or insufficient access controls, violating GDPR/CCPA/HIPAA and enabling identity theft, fraud, and legal liability. Core fix: minimize PII collection and enforce strict authorization with least disclosure principles.

## Key Principles

- Minimize PII collection and retention - only collect what's necessary
- Enforce authorization and least privilege for all PII access
- Control exposure channels: logs, errors, APIs, URLs, analytics, UI
- Delete PII promptly when no longer needed
- Question every PII field in forms and data models
- Hashing an identifier is pseudonymization, not anonymization: a hashed email, phone number, or SSN is recoverable by brute force (an SSN is a 10^9 keyspace, enumerable in seconds) and remains personal data under GDPR. Where analytics needs a per-user key, use a random, per-service, rotatable surrogate ID never derived from the PII
- Require step-up authentication before a bulk export or a full-record view, so a hijacked session alone is not enough
- Audit who accessed which personal data and when - the access log is part of the control here, not just of the investigation
- Use this entry when the exposed data is personally identifiable and regulatory exposure is the concern; CWE-200 covers sensitive-data exposure generally

## Remediation Steps

- Review flaw details to identify specific exposure location (file, line, code pattern)
- Identify exposed PII types - names, SSN, medical data, financial info, contact details
- Determine exposure channel - logs, error messages, APIs, URLs, database queries, analytics, UI
- Trace data flow from collection through storage to exposure point
- Implement data minimization - remove unnecessary PII fields from collection
- Add access controls - validate user authorization before returning PII in responses
