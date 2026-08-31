# CWE-613: Insufficient Session Expiration

## LLM Guidance

Insufficient session expiration means a session or token stays valid far longer than the access it grants requires, or has no expiration at all - so a stolen cookie, a leaked token, or an account whose privileges just changed keeps working long after it should have stopped. A traditional server-side session needs an explicit idle and absolute timeout on the session store. A stateless token such as a JWT is the harder case: once issued, it stays valid until its own `exp` claim expires regardless of anything the server does afterward, since there is no session store to update. The fix has two independent halves - set the expiration deliberately, short enough that a leak isn't a long-term compromise, and build a revocation path for anything that must be invalidated before its natural expiry, since time alone cannot do that for a token already issued.

## Key Principles

- Set both an idle and an absolute timeout on server-side sessions. Sliding renewal alone lets a session that stays continuously active - including one an attacker is actively using - outlive discovery indefinitely; the absolute cap is what bounds that
- Treat a token's `exp` claim as its entire lifetime commitment: nothing server-side can shorten it once issued, so choose the value deliberately rather than defaulting to whatever a copied example used - often a year, or no expiration at all
- Revocation before expiry needs its own mechanism for a stateless token: a denylist keyed by the token's own identifier (its `jti` claim), not the raw token or a hash of it, or a short-lived access token paired with a separately revocable refresh token
- Size the timeout to the risk, not to one number for everything - shorter for a high-value action, longer for low-risk browsing - and set an absolute cap sized to how long a legitimate session should ever actually need to last
- A password change, role change, or explicit logout must invalidate the specific session or token already issued, not just stop new ones from being trusted the same way - check that the fix revokes the one already in the attacker's hand
- Distinguish the neighboring failure: reusing the *same* session identifier across a trust-level change (a login that never rotates it) is session fixation (CWE-384), not this weakness - this one is about a session or token that started legitimately but remains usable, or reusable, longer than it should

## Remediation Steps

- Locate every place a session or token's lifetime is set, or left at a library or framework default - session-store configuration, a cookie's `Max-Age`/`Expires`, and any `exp` claim assignment
- Trace what the session or token actually authorizes, since the acceptable lifetime depends on what is at stake
- Identify the unsafe pattern - no expiration set at all, a lifetime inherited from an example far longer than needed, or a token with no path to revoke it before `exp`
- Replace with an explicit, deliberately-chosen idle and absolute timeout for sessions, and a short `exp` for tokens
- Add the denylist or refresh-token mechanism where pre-expiry revocation is required, and wire logout, privilege change, and breach response to actually use it
- Test - confirm a session outlives neither its idle nor absolute timeout, that a revoked token is rejected on the very next request rather than only on the next issuance, and that a logged-out session's identifier no longer authorizes anything
