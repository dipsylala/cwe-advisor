# CWE-384: Session Fixation

## LLM Guidance

Session Fixation occurs when an application allows an attacker to set or reuse a session identifier for another user, enabling the attacker to hijack the victim's session after authentication. The core fix is to regenerate session identifiers whenever authentication or privilege level changes, ensuring that pre-authentication sessions never remain valid post-authentication.

## Key Principles

- Regenerate session IDs immediately after authentication or privilege escalation
- Never accept session identifiers from URL parameters or untrusted sources
- Invalidate old session identifiers to prevent reuse
- Use framework-native session regeneration functions (session.regenerate(), session_regenerate_id())
- Bind sessions to additional user context for defence-in-depth
- Invalidate the old identifier rather than merely replacing it: PHP's `session_regenerate_id()` defaults to `delete_old_session = false`, which writes the session's current contents back to the old id - regenerate *after* writing the authenticated state and that pre-login id stays a fully authenticated session until it expires. Passing `true` destroys it regardless of ordering
- Check what the framework's regeneration does with existing session data: Django's `cycle_key()` keeps it (and `django.contrib.auth.login()` calls it, so a finding usually means a login path that writes the session directly), while Express's `req.session.regenerate(callback)` starts an empty session, so anything worth keeping must be written *inside* the callback
- Regenerate on any privilege change, not only at login
- Keep the two session timers separate: an idle timeout that resets on activity and an absolute timeout that does not, after which the user re-authenticates regardless
- `SameSite=Strict` is not simply the stronger choice - it also withholds the cookie from inbound links, SSO redirects and OAuth callbacks, which lands the user signed out with no error anywhere

## Remediation Steps

- Review authentication flows (login handlers, OAuth callbacks, SSO) to identify where session IDs are not regenerated
- Call session.regenerate() or framework equivalent immediately after successful authentication
- Invalidate the previous session ID to prevent attackers from reusing it
- Reject session IDs passed via URL parameters or query strings
- Verify session ID changes before and after login during testing
- Bind sessions to additional context (IP address, user agent) as a secondary control
