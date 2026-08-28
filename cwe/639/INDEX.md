# CWE-639: Authorization Bypass Through User-Controlled Key

## LLM Guidance

Insecure Direct Object Reference (IDOR) occurs when applications expose direct references to internal objects (database keys, filenames, paths) and fail to verify user authorization. Attackers modify object references (e.g., changing `id=123` to `id=124`) to access unauthorized data. This broken access control vulnerability stems from trusting user-supplied object identifiers.

## Key Principles

- Verify user authorization for every object access - never trust user-supplied identifiers
- Check both existence AND ownership before returning objects
- Use query filters or ACL lookups to enforce object-level permissions
- Return consistent error responses (403/404) that don't reveal whether objects exist
- Consider indirect references (UUIDs, session mappings) to prevent enumeration
- Derive the ownership check from the server-side session or token context, never from anything in the request that identified the object
- Test horizontal escalation across every verb: as user B, request user A's resource by id with `GET`, `PUT`, `DELETE`, and a create carrying another user's id in the body - each must be refused rather than returning the record
- Distinguish the neighbours: flawed authorization logic generally is CWE-863, no check on the path at all is CWE-862, and the SQL primary-key manifestation is CWE-566

## Remediation Steps

- Identify all direct object references in API endpoints, queries, and file operations
- Add object-level authorization to every object retrieval (verify current user owns/can access the resource)
- Implement ownership verification in database queries - `WHERE id = ? AND user_id = ?`
- Test horizontal privilege escalation - attempt to access User A's resources as User B using modified IDs
- Replace sequential IDs with UUIDs or session-specific mappings to prevent ID guessing
- Validate authorization at the application layer, not just in the UI
