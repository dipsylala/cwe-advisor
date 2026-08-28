# CWE-501: Trust Boundary Violation - PHP

## LLM Guidance

The reported line is `$_SESSION['role'] = $_POST['role']` or an equivalent write of request data into
the session. `$_SESSION` is server-side by default, so the immediate risk is privilege rather than
disclosure - later code reads the key and acts on it because it came from the session. Two PHP-specific
things decide whether a fix holds: `session.use_strict_mode` is **off by default**, so the session the
value lands in may be one the attacker chose; and Laravel's `cookie` session driver moves the whole
store to the client.

## Key Principles

- Set `session.use_strict_mode = 1`. It is off by default, and while off PHP will adopt any session id
  the client presents rather than only ids it generated - so an attacker who can set a cookie fixes
  the session your validated value is then written into. This is the setting that makes the rest of
  the fix meaningful
- Call `session_regenerate_id(true)` on any trust-level change - login, privilege elevation,
  impersonation. The `true` argument deletes the old session file; without it the previous identifier
  remains valid and still resolves to a session
- Validate and authorize at the write, not at the readers. Every reader is entitled to skip the check,
  and a `$_SESSION` key is readable from anywhere in the request
- Store a resolved identifier and load the authority on use: a user id in the session, the role from
  the database, rather than a role string an authorization check will believe
- In Laravel, `SESSION_DRIVER=cookie` serialises the whole session into the client cookie. Encryption
  under `APP_KEY` means the user cannot read or forge it, not that the value was checked, so establish
  the driver before reasoning about exposure. That driver also has its own history: paired with any
  place the app encrypts user input and returns the result, it reached RCE (GHSA-qm5c-m76r-2hfr, fixed
  in 6.18.31 and 7.22.4)
- Rotating `APP_KEY` logs out every session on *any* driver, since Laravel encrypts the session cookie
  itself - list the outgoing key in `APP_PREVIOUS_KEYS` to rotate without the mass logout
- Laravel's `session()->regenerate()` is the framework equivalent of the id rotation above, and
  `Auth::login()` performs it; a hand-rolled elevation does not
- `session.use_only_cookies` is likewise off by default in the raw configuration, which allows a
  session id from a query string - a trivially shareable and log-visible credential. Set it on
- `$_SESSION` values are serialised by the session handler and unserialised on read, so an
  attacker-influenced object graph stored there is a deserialization concern (CWE-502) reached through
  this weakness, particularly with a custom session handler backed by a shared store
- `extract($_POST)` and `$$variable` writes are the same weakness against the local scope: they let a
  request name the variable it overwrites, including one a later check reads

## Taint Sinks

`$_SESSION[...] =`, `session_start()` with an id from input, `extract()`, `$$variable` assignment,
`session()->put()` / `session([...])` (Laravel), `Auth::login()` with a request-built user, a request
value written into a container binding or config at runtime

## Remediation Steps

- Locate - find `$_SESSION` assignments and `session()->put()` calls whose value comes from `$_POST`,
  `$_GET`, `$_COOKIE`, a header, or a decoded request body
- Establish the store - `$_SESSION` server-side, or Laravel's configured `SESSION_DRIVER`, since the
  `cookie` driver puts the data on the client
- Trace data flow - follow the key to its readers and mark those making a security decision
- Identify the unsafe pattern - a raw request value written into the session, a role cached rather
  than resolved, or an `extract()` letting the request choose variable names
- Replace the unsafe pattern - validate and authorize immediately before the write, and store a
  server-resolved identifier with the authority loaded on use
- Harden configuration - set `session.use_strict_mode = 1` and `session.use_only_cookies = 1`, and
  call `session_regenerate_id(true)` on every trust-level change
- Test - submit a modified role parameter and confirm it never reaches the session; present a
  self-chosen session id cookie and confirm the server issues a new one rather than adopting it
