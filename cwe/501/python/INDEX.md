# CWE-501: Trust Boundary Violation - Python

## LLM Guidance

The reported line is `session['role'] = request.form['role']` or the Django equivalent
`request.session['x'] = request.POST['x']`. The session is the trusted store: later code reads it and
acts on it because it came from the session rather than the request. Where the two frameworks differ
sharply is *where the session lives* - Flask's default session is a signed cookie held by the client,
Django's default is server-side - and that changes what a bad write exposes as well as what it lets
through.

## Key Principles

- Flask's default session is a **client-side signed cookie**. The framework's own documentation is
  explicit that the user can read the contents but not modify them without the secret key. So a
  secret written into `session` is disclosed even though it cannot be tampered with, and "it's signed"
  answers a different question from "is this value trustworthy" - the signature proves the server
  wrote it, not that anyone checked it
- The cookie is also size-limited. Values that silently fail to persist across requests are usually a
  session cookie that outgrew the browser's limit, which is a correctness failure that can leave a
  security flag unset rather than false
- Django's session is server-side by default (database or cache backend), so the same write is a
  privilege problem rather than a disclosure one - unless `SESSION_ENGINE` is set to
  `django.contrib.sessions.backends.signed_cookies`, which moves it client-side with Flask's
  properties. Check the setting before reasoning about exposure
- Validate and authorize at the write, not at the readers. Store a resolved identifier - a user id, a
  primary key - and load the role or permission from the database on use, rather than caching the
  submitted value where an authorization check will believe it
- Rotate the session identifier on any trust-level change: Django's `login()` calls
  `request.session.cycle_key()` for you, but a hand-rolled elevation, an impersonation feature, or a
  step-up authentication flow must call it explicitly
- Never write into `request.user`, or attach an attribute to it, from request data. It is the object
  every permission class and template consults, so a value placed there is trusted everywhere
  afterwards
- A middleware that copies request data onto `request` for later components is the same weakness at
  request scope: name such attributes so the boundary is visible, and validate before attaching
- Flask's `g` is per-request and fine for a validated value, but it inherits the same rule - a later
  reader cannot tell whether what it finds there was checked

## Taint Sinks

`flask.session[...]` assignment, `session.update()`, `request.session[...]` assignment,
`request.session.update()`, `django.contrib.auth.login()` with a hand-built user, attributes attached
to `request` or `request.user` in middleware, `flask.g` attributes set from request data

## Remediation Steps

- Locate - find assignments into `session` or `request.session` whose value comes from `request.form`,
  `request.args`, `request.POST`, `request.GET`, a JSON body, or a header
- Establish where the session lives - Flask's cookie by default, Django's configured `SESSION_ENGINE`
  - since that decides whether the write also discloses the value to the user
- Trace data flow - follow the key to its readers and mark those making a security decision
- Identify the unsafe pattern - a raw request value stored in the session, a role or permission cached
  rather than resolved, or an attribute attached to `request.user`
- Replace the unsafe pattern - validate and authorize immediately before the write, and store a
  server-resolved identifier, loading the authority from the database on use
- Harden configuration - call `cycle_key()` on any trust-level change outside Django's own `login()`,
  and move anything sensitive out of a cookie-backed session
- Test - submit a modified role or ownership parameter and confirm it never reaches the session;
  decode the Flask session cookie in a browser and confirm nothing sensitive is legible in it
