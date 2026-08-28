# CWE-501: Trust Boundary Violation - Java

## LLM Guidance

The reported line is almost always `session.setAttribute(name, request.getParameter(...))` or an
equivalent write into `HttpSession` from request data. The session is the trusted store: later code
reads an attribute and acts on it precisely because it came from the session rather than the request,
so the write is the only place a check can go. Validate and authorize at the write, and prefer keeping
a server-derived value - an id resolved to an entity, a role loaded from the database - over storing
the submitted value at all.

## Key Principles

- Validate and authorize at the `setAttribute` call, not at the readers. Every reader is entitled to
  skip the check by design, and there is usually more than one
- Store the resolved value rather than the submitted one: put a user id in the session and load the
  role from the database on use, rather than putting a role string from the request into the session
  where an authorization check will later read it
- Spring MVC's `@SessionAttributes` is the case with no visible write. A `@ModelAttribute` populated
  by data binding from request parameters is copied into the session by the framework, so request data
  reaches the trusted store without any `setAttribute` in the source - grep for the annotation as well
  as for the call
- Never derive a `GrantedAuthority` or anything reaching `SecurityContextHolder` from request data.
  Spring Security's context is the most trusted store in the application, and a role placed there is
  believed by every `@PreAuthorize` afterwards
- Call `request.changeSessionId()` (Servlet 3.1+) when the trust level changes - at login, on
  privilege elevation, on impersonation - so a session fixed before the change does not carry the new
  authority. Spring Security does this for its own login flow, not for a hand-rolled one
- In a replicated or persisted session, attributes are serialized and deserialized by the container.
  An attacker-influenced object graph stored in the session therefore becomes a deserialization sink
  on the receiving node, which is CWE-502 reached through this weakness
- Distinguish the neighbours the root names: security state kept where the client controls it is
  CWE-642, and the same shape at startup is CWE-454
- Keep a naming convention that makes the boundary visible - a prefix for attributes derived from
  request data, or separate maps for validated and unvalidated values - so a reviewer can see which is
  which without tracing every write

## Taint Sinks

`HttpSession.setAttribute()`, `HttpSession.putValue()`, `@SessionAttributes` on a controller,
`ServletContext.setAttribute()`, `SecurityContextHolder.getContext().setAuthentication()`,
`request.setAttribute()` forwarded across a trust boundary

## Remediation Steps

- Locate - find `setAttribute` calls whose value derives from `getParameter`, `getHeader`, `getCookies`
  or a request body, and any controller carrying `@SessionAttributes`
- Trace data flow - follow the attribute forward to its readers and identify which of them make a
  security decision on it; that set is what the fix has to protect
- Identify the unsafe pattern - a raw request value written into the session, an authority derived
  from input, or a model attribute promoted into the session by the framework
- Replace the unsafe pattern - validate and authorize immediately before the write, and store a
  server-resolved value (an id, an enum, an entity reference) rather than the submitted string
- Bind, encode, validate, or authorize - where a role or permission is involved, resolve it from the
  authenticated principal and the database at the point of the write, never from the request
- Harden configuration - call `changeSessionId()` on any trust-level change, and confirm session
  attributes are serializable types you control if the container replicates sessions
- Test - submit a modified role or ownership parameter, confirm it never reaches the session, and
  verify a session established before a privilege change does not carry the new authority afterwards
