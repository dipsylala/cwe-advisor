# CWE-522: Insufficiently Protected Credentials - JavaScript

## LLM Guidance

Insufficiently protected credentials in Node appear as plaintext storage, a fast digest used as a password hash, or a secret that reaches logs and client bundles. Separate the two cases before fixing either: a user password is hashed with an adaptive algorithm and never read back, while a credential the application presents to another system is loaded at runtime. Name the package when prescribing a fix - `bcrypt` and `bcryptjs` expose the same `hash()`/`compare()` shape and differ in ways that matter.

## Key Principles

- `bcrypt` (kelektiv) is a native addon built through `node-gyp` with best-effort prebuilds; `bcryptjs` is pure JavaScript with zero dependencies and no build step, at roughly 30% slower hashing by its own README - which lowers the rounds you can afford in the same time budget. Choose deliberately rather than by whichever name came to mind
- Floor `bcrypt` at **5.0.0**: earlier versions carry a wrap-around bug (CVE-2020-7689) and, in the README's words, "will truncate passwords >= 255 characters leading to severely weakened passwords" and mishandle NUL bytes so "all subsequent characters being dropped". The same README asks for **6.0.0** on Node 18+
- Both implementations use only the first **72 bytes** - bytes, not characters, so a UTF-8 string with emoji reaches the limit sooner. Neither checks it for you: `bcryptjs` documents the check as the caller's job and provides `bcrypt.truncates(password)` for exactly this, which is the cheapest guard to add
- Node hashes passwords itself now: `crypto.scrypt` since v10.5.0 and `crypto.argon2`/`argon2Sync` since **v24.7.0**. They return a raw derived key rather than a PHC string, with no verify and no rehash-needed check, so they are a dependency-free option that costs you the encode/verify plumbing - `node-argon2`'s own README lists exactly those gaps. Node's default scrypt `cost` is 16384
- Compare digests and tokens with `crypto.timingSafeEqual`, which the docs describe as constant-time and suitable "for comparing HMAC digests or secret values like authentication cookies". It throws when the two inputs differ in byte length, so hash both sides to a fixed width before comparing rather than passing raw secrets
- Node does not normalise Unicode before key derivation: its own docs warn that a passphrase in composed versus decomposed form yields a different derived key and suggest `String.prototype.normalize()` on user input before it reaches `scrypt`, `argon2` or `pbkdf2`
- The cookie attributes protect narrower things than their names suggest. `httpOnly` blocks `document.cookie` but the cookie is still attached to `fetch()` and `XMLHttpRequest` requests, so it is not an XSS fix. `Secure` is ignored on localhost and does not stop a `document.cookie` read when `httpOnly` is absent. `SameSite` defaults to `Lax` in only *some* browsers, with a two-minute exemption for `POST`
- Node loads `.env` natively - `node --env-file=.env`, non-experimental since 22.21.0 and 24.10.0 - so `dotenv` is a choice rather than a requirement on a current runtime

## Taint Sinks

`crypto.createHash('md5'|'sha1'|'sha256')` used as a password hash, a secret compared with `===` rather than `crypto.timingSafeEqual`, hardcoded secrets in source, `console.log()` of credentials, a committed `.env`, a secret behind a `VITE_` or `NEXT_PUBLIC_` prefix

## Remediation Steps

- Separate the two cases - Hash what only needs recognising; load what must be presented elsewhere
- Replace the digest - Move to `bcrypt`/`bcryptjs` at a work factor the verification server can afford, or to `argon2`, and re-hash on successful login when the configured cost has moved
- Guard the length - Reject or pre-hash inputs over 72 bytes, using `bcrypt.truncates()` where the library offers it, so a long passphrase is not silently reduced to its first 72 bytes
- Fix the comparison - Replace `===` on tokens and HMACs with `crypto.timingSafeEqual` on equal-length buffers
- Externalise the rest - Read secrets from `process.env` fed by `--env-file` or the platform, and confirm nothing crossed into a client bundle
- Untrack, do not just ignore - Adding `.env` to `.gitignore` leaves an already-tracked file tracked; `git rm --cached .env` is what removes it
- Scan with the right tool for the job - `git-secrets` describes itself as preventing commits rather than searching history; TruffleHog, now at `trufflesecurity/trufflehog`, is the history scanner and verifies findings against the live API
