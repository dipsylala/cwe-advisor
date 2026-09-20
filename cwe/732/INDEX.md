# CWE-732: Incorrect Permission Assignment for Critical Resource

## LLM Guidance

A specific permission assignment set incorrectly in application logic - a bad `chmod` call, an ACL bug. The baseline a resource is *created* with is CWE-276, and the standing privilege of the process acting on resources rather than the resource's own bits is CWE-269, with CWE-250 for its over-privileged case.

## Key Principles

- Apply least privilege to all permission assignments and ACLs
- Use default-deny approach: start restrictive, grant only required access
- Minimize scope: limit who can read, write, or execute resources
- Validate permissions match resource sensitivity (config files, credentials, user data require stricter controls)
- Review and audit permissions regularly to prevent drift

## Remediation Steps

- Review flaw details to identify the specific resource (file, directory, service) with incorrect permissions
- Identify current permissions using `ls -l` (Unix), `Get-Acl` (Windows), or application-specific tools
- Determine resource sensitivity and required access patterns
- Assign minimum necessary permissions - grant only what's needed for legitimate operations
- Remove world-readable/writable permissions; use user/group-specific grants
- Validate changes with security tests - attempt unauthorized access to confirm restrictions work
