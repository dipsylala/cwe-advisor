# CWE-112: Missing XML Validation

## LLM Guidance

Missing XML validation occurs when applications parse XML without validating it against a defined schema (XSD, DTD, or RelaxNG), allowing malformed, malicious, or unexpected XML structures to be processed. This can lead to injection attacks, denial of service, or business logic bypasses. Never process untrusted XML without strict schema validation. This is distinct from CWE-611: disabling DTD and external-entity processing closes XXE, while schema validation is what closes this - a finding reported as "XXE" belongs to CWE-611, and one about structurally invalid, oversized, or unexpected XML being accepted belongs here. The two commonly appear together and both fixes are needed.

## Key Principles

- Always validate untrusted XML against a strict, application-defined schema before processing
- Reject any XML that does not conform exactly to the expected structure
- Use XSD types and constraints to enforce data validation at the schema level
- Limit element cardinality and data sizes to prevent denial of service attacks
- Employ allowlists for attribute values and element content where possible
- Validate against a schema the application ships, never one the document names: honouring `schemaLocation`/`noNamespaceSchemaLocation` from untrusted XML lets the sender choose the rules it will be judged by, and fetches a remote resource on the server's behalf
- Validation is not a substitute for the parser hardening - set `FEATURE_SECURE_PROCESSING`, disable DTDs and external entities, and cap document size and nesting depth as well

## Remediation Steps

- Define a comprehensive XSD that specifies all allowed elements, types, and requirements
- Set strict data type constraints using XSD types (string, int, date, etc.)
- Enforce length limits with `maxLength` attributes to prevent oversized payloads
- Define cardinality constraints using `minOccurs` and `maxOccurs` to limit element repetition
- Restrict attribute values with enumerations or regex patterns to allowlist valid inputs
- Configure your XML parser to validate against trusted local schemas, reject invalid documents before processing, disable external entity resolution, restrict external DTD/schema access, and apply document size/depth limits
