# CWE-639: Authorization Bypass Through User-Controlled Key

## LLM Guidance

A user-controlled identifier reaches the record with no ownership test. Flawed authorization logic generally is CWE-863, no check on the path at all is CWE-862, and the SQL primary-key manifestation is CWE-566.

## Key Principles

- Verify user authorization for every object access - never trust user-supplied identifiers
- Check both existence AND ownership before returning objects
- Use query filters or ACL lookups to enforce object-level permissions
- Return consistent error responses (403/404) that don't reveal whether objects exist
- Consider indirect references (UUIDs, session mappings) to prevent enumeration
- Derive the ownership check from the server-side session or token context, never from anything in the request that identified the object
- Test horizontal escalation across every verb: as user B, request user A's resource by id with `GET`, `PUT`, `DELETE`, and a create carrying another user's id in the body - each must be refused rather than returning the record

## Remediation Steps

- Identify all direct object references in API endpoints, queries, and file operations
- Add object-level authorization to every object retrieval (verify current user owns/can access the resource)
- Implement ownership verification in database queries - `WHERE id = ? AND user_id = ?`
- Test horizontal privilege escalation - attempt to access User A's resources as User B using modified IDs
- Replace sequential IDs with UUIDs or session-specific mappings to prevent ID guessing
- Validate authorization at the application layer, not just in the UI
