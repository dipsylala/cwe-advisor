# CWE-501: Trust Boundary Violation - Go

## LLM Guidance

Go has no session in the standard library, so the trusted store is whatever the application chose:
`gorilla/sessions`, a JWT, or - most often for request-scoped data - `context.Context`. The reported
line is a write of request data into one of those, after which downstream handlers read it and act on
it because it arrived through the trusted channel rather than the request. Validate and authorize at
the write, and establish which store is in use before reasoning about what a bad write exposes.

## Key Principles

- Establish the store first. `sessions.NewCookieStore` serialises the session into the client cookie,
  so a bad write there is disclosure as well as escalation; `NewFilesystemStore` and the database-
  backed stores keep it server-side. `securecookie` authenticates with the first key and only
  encrypts when a second is supplied, so a cookie store created with one key is readable by the user
- A `securecookie` value being valid proves this server wrote it, not that the value was ever checked.
  The same holds for a verified JWT - `token.Valid` says the signature matches, and says nothing about
  whether the claim was validated when it was issued
- `context.WithValue` is the request-scoped trusted store, and middleware is where request data most
  often enters it. Validate before attaching, and name the key so a reader can tell a checked value
  from a copied one
- Use an unexported, non-string key type for context values - `type ctxKey struct{}` or a defined
  unexported type. A plain string key can be written by any package in the process, including a
  dependency, so the store is not actually private to the code that trusts it
- Do not carry an authorization decision in the context. Carry the identity, and re-derive the
  decision where it is enforced; a `context.Context` marked "isAdmin" is believed by every handler
  that receives it
- Rotate the session identifier on any trust-level change. With `gorilla/sessions` that means calling
  `session.Options.MaxAge = -1` and saving to drop the old session, then creating a fresh one - simply
  overwriting values keeps the identifier an attacker may already know
- Store a resolved identifier and load the authority on use: a user id in the session, the role from
  the database, rather than a role string the authorization middleware will believe
- Decoding a session or token into a struct with `encoding/gob` or `encoding/json` is where an
  attacker-influenced graph re-enters typed code, so the field set of that struct is part of the trust
  boundary - a struct shared with the persistence layer accepts fields the client should never set

## Taint Sinks

`session.Values[...] =` (gorilla/sessions), `sessions.NewCookieStore`, `context.WithValue`,
`jwt.NewWithClaims` with request-derived claims, `r.WithContext` in middleware, a struct field set
from `r.FormValue`/`r.Header.Get` then stored

## Remediation Steps

- Locate - find writes into `session.Values`, `context.WithValue` calls in middleware, and JWT claim
  construction whose value derives from `r.FormValue`, `r.PostForm`, a header, a cookie, or a decoded
  body
- Establish the store - cookie-backed or server-side, and whether `securecookie` was given an
  encryption key - since that decides whether the write also discloses the value
- Trace data flow - follow the key to the handlers that read it, and mark those making an
  authorization decision
- Identify the unsafe pattern - a raw request value in the session or context, an authorization
  decision carried rather than re-derived, or a string-typed context key
- Replace the unsafe pattern - validate and authorize immediately before the write, store a
  server-resolved identifier, and change context keys to an unexported type
- Bind, encode, validate, or authorize - build JWT claims from the user record loaded during
  authentication, never from the request body that triggered the login
- Harden configuration - supply both keys to `securecookie` where the store is cookie-backed, and drop
  and recreate the session on a trust-level change
- Test - submit an extra role or ownership field and confirm it reaches neither the session nor a
  claim, and decode a cookie-backed session to confirm nothing sensitive is legible
