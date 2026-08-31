# CWE-613: Insufficient Session Expiration - PHP

## LLM Guidance

PHP's own session timeout, `session.gc_maxlifetime` (default 1440 seconds, 24 minutes), is not a hard per-session cutoff - it is the age threshold garbage collection uses, and GC itself only runs probabilistically per request by default, so a session can outlive the configured value by a wide margin under low traffic. Laravel's own `config/session.php` `lifetime` (120 minutes by default) is the more reliable idle timeout for a Laravel app. A hand-issued JWT via `firebase/php-jwt` has no equivalent default at all: `exp` is just another array key the caller adds to the payload, and Sanctum's personal-access tokens never expire unless the `expiration` config is set - both need a value chosen deliberately, not left to a framework default that isn't one.

## Key Principles

- `session.gc_maxlifetime` (default 1440 seconds) is not a hard expiry - php.net's own documentation frames it as the age garbage collection uses, and GC runs probabilistically per `session.gc_probability`/`gc_divisor` by default, so a low-traffic app can retain sessions well past the configured value. In production, set `gc_probability` to `0` and trigger `session_gc()` on a schedule instead of relying on the per-request chance
- `session.cookie_lifetime` (default `0`, meaning until the browser closes) is a separate setting from `gc_maxlifetime` - one governs the cookie's own lifetime, the other governs when the server-side data becomes eligible for cleanup. Setting one without the other leaves a real gap
- Laravel's `config/session.php` `lifetime` (120 minutes by default) is the idle timeout that actually matters for a Laravel app - `expire_on_close` (default `false`) is the separate absolute-vs-persistent toggle
- `firebase/php-jwt` has no builder and no enforced maximum lifetime - `exp` is a plain array key the caller adds to the payload passed to `JWT::encode()`, so a token minted without one never expires; `JWT::decode()` does validate `exp` where present and throws `Firebase\JWT\ExpiredException`, with a configurable `JWT::$leeway` for clock skew that should stay a few minutes at most, not larger
- Sanctum's personal-access tokens never expire by default - Laravel's own documentation states this explicitly - and are only invalidated by deleting the token row (`$user->tokens()->where('id', $tokenId)->delete()`). Set the `expiration` config (minutes) deliberately if tokens should expire at all, and schedule `sanctum:prune-expired` to clean up the resulting rows
- Neither `firebase/php-jwt` nor Sanctum's default mode gives pre-expiry revocation beyond row deletion - for a hand-issued JWT that must be invalidated before `exp`, add a `jti`-keyed denylist checked at decode time

## Taint Sinks

`JWT::encode()` with a payload array missing `exp`, `JWT::$leeway` set larger than a few minutes, Laravel `config/session.php` `lifetime` left at an excessive value, Sanctum `'expiration' => null` where tokens should expire, a personal-access token with no `sanctum:prune-expired` schedule

## Remediation Steps

- Locate - find `JWT::encode()` calls and their payload construction, `config/session.php` and `config/sanctum.php`, and native `session.gc_maxlifetime`/`session.cookie_lifetime` settings
- Trace what the session or token authorizes, to size the lifetime to the risk
- Identify the unsafe pattern - a JWT payload with no `exp` key, a `gc_maxlifetime` relied on as if it were a hard cutoff, or Sanctum's `expiration` left unset for tokens that should expire
- Replace with an explicit `exp` in the JWT payload and a deliberately-chosen Sanctum `expiration`/session `lifetime`
- Bind, encode, validate, or authorize - for pre-expiry revocation, delete the specific token row (Sanctum) or check a `jti`-keyed denylist (hand-issued JWT) before trusting it
- Harden configuration - set `gc_probability` to `0` and trigger `session_gc()` on a schedule rather than the per-request default, and schedule `sanctum:prune-expired`
- Test - confirm a token or session issued before the fix is rejected once its new, shorter lifetime passes, and that a deleted token row or denylisted `jti` is rejected on the very next request
