# CWE-306: Missing Authentication for Critical Function - PHP

## LLM Guidance

PHP has a structural exposure the frameworks do not remove: any `.php` file under the document root is reachable by URL on its own, whether or not the application's front controller routes to it. A framework finding is usually a route registered outside an `auth` middleware group or a Symfony path matching no `access_control` rule; a legacy finding is often a script that was never meant to be an endpoint at all. Fix by requiring authentication at the route group or firewall, and by keeping anything that is not a deliberate entry point outside the web root.

## Key Principles

- Only the front controller belongs under the document root. Any other `.php` file there - an admin utility, a migration script, a leftover diagnostic - is an endpoint that the router never sees, so it needs its own check or it needs to move out of the web root
- A file included for its side effects still executes when requested directly; where it cannot be relocated, guard it by requiring a constant the including file defines and exiting when it is absent
- In Laravel, `routes/web.php` and `routes/api.php` receive different middleware groups: the `api` group has no session, so the session-based `auth` middleware never authenticates anyone there. Use `auth:sanctum` (or the relevant guard) on API routes and confirm which guard the route group actually resolves
- Prefer applying `auth` to a `Route::middleware([...])->group(...)` block over per-route middleware, so a route added inside the block inherits it and one added outside is visible as such
- Symfony's `access_control` in `security.yaml` is evaluated top-down and the first matching rule wins; a path matching no rule carries no requirement at all. End the list with a catch-all requiring `IS_AUTHENTICATED_FULLY` and mark public paths explicitly with `PUBLIC_ACCESS`
- A firewall with `security: false` disables authentication for everything it matches, including paths a later firewall was meant to protect - firewalls are matched in order, like access control rules
- In WordPress and plugin code, a handler registered on `wp_ajax_nopriv_{action}` is deliberately reachable without a login; registering the same callback on both `wp_ajax_` and `wp_ajax_nopriv_` makes a privileged action public, and REST routes need a real `permission_callback` rather than one returning true

## Taint Sinks

Routes outside an `auth` middleware group, `routes/api.php` routes using session `auth` rather than `auth:sanctum`, Symfony paths matching no `access_control` rule, `security: false` on a firewall, any directly reachable `.php` file under the document root, `wp_ajax_nopriv_*` handlers, `permission_callback` returning true

## Remediation Steps

- Locate - Enumerate the framework's routes and, separately, every `.php` file under the document root, since the second list is not derivable from the first
- Diff against coverage - For Laravel, determine which middleware group each route file and group applies; for Symfony, read `access_control` top-down and identify paths matching no rule
- Confirm identity is never established - A route that authenticates but omits a policy or ownership check is CWE-862 rather than this entry
- Apply the fix - Wrap protected routes in a middleware group with the correct guard, and add a catch-all `access_control` rule requiring an authenticated user
- Relocate stray scripts - Move non-front-controller `.php` files outside the document root, or guard them with a defined-constant check that exits on direct request
- Correct the guard on API routes - Replace session `auth` with the token guard the API actually uses, and confirm an unauthenticated request is rejected rather than silently treated as a guest
- Test directly against the endpoint - Request each route and each stray script by URL with no session or token, and confirm a 401 or redirect rather than a 200
