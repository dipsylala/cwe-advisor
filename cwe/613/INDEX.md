# CWE-613: Insufficient Session Expiration

## LLM Guidance

A server-side session can be expired by the store; a stateless token cannot - once issued it stays valid until its own `exp` claim says so, whatever the server does afterward. Expiration and revocation are therefore two separate pieces of work rather than one. Reusing the *same* session identifier across a trust-level change is session fixation, CWE-384, not this weakness: this entry is a session or token that started legitimately and stays usable longer than it should.

## Key Principles

- Set both an idle and an absolute timeout on server-side sessions. Sliding renewal alone lets a session that stays continuously active - including one an attacker is actively using - outlive discovery indefinitely; the absolute cap is what bounds that
- Treat a token's `exp` claim as its entire lifetime commitment: nothing server-side can shorten it once issued, so choose the value deliberately rather than defaulting to whatever a copied example used - often a year, or no expiration at all
- Revocation before expiry needs its own mechanism for a stateless token: a denylist keyed by the token's own identifier (its `jti` claim), not the raw token or a hash of it, or a short-lived access token paired with a separately revocable refresh token
- Size the timeout to the risk, not to one number for everything - shorter for a high-value action, longer for low-risk browsing - and set an absolute cap sized to how long a legitimate session should ever actually need to last
- A password change, role change, or explicit logout must invalidate the specific session or token already issued, not just stop new ones from being trusted the same way - check that the fix revokes the one already in the attacker's hand

## Remediation Steps

- Locate every place a session or token's lifetime is set, or left at a library or framework default - session-store configuration, a cookie's `Max-Age`/`Expires`, and any `exp` claim assignment
- Trace what the session or token actually authorizes, since the acceptable lifetime depends on what is at stake
- Identify the unsafe pattern - no expiration set at all, a lifetime inherited from an example far longer than needed, or a token with no path to revoke it before `exp`
- Replace with an explicit, deliberately-chosen idle and absolute timeout for sessions, and a short `exp` for tokens
- Add the denylist or refresh-token mechanism where pre-expiry revocation is required, and wire logout, privilege change, and breach response to actually use it
- Test - confirm a session outlives neither its idle nor absolute timeout, that a revoked token is rejected on the very next request rather than only on the next issuance, and that a logged-out session's identifier no longer authorizes anything
