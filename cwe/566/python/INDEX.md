# CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key - Python

## LLM Guidance

CWE-566 here is the SQL-primary-key case: a user-controlled ID (URL parameter, form field) is the lookup value in a Django ORM, SQLAlchemy or Flask-SQLAlchemy query, and the query returns or modifies the matching row without an ownership filter in the query itself. The fix belongs in the query - filter by both the primary key and the authenticated user's ID in the same call, not in a separate ownership check after the row has been fetched. Django and SQLAlchemy take different forms; write the one that matches the code in front of you.

## Key Principles

- Django's `get_object_or_404()` accepts lookup parameters "in the format accepted by `get()` and `filter()`", so the entire fix is one extra argument: `get_object_or_404(Document, pk=pk, user=request.user)`. The same holds for `Model.objects.get()` and `.filter()`
- SQLAlchemy's form is `filter_by(id=doc_id, user_id=current_user.id)`. On Flask-SQLAlchemy, `one_or_404()` asserts exactly one row where `first_or_404()` returns the first of possibly many
- `Query.get()` is deprecated as of SQLAlchemy 2.0 with `Session.get()` as its replacement, and Flask-SQLAlchemy documents `Model.query` as the legacy interface, preferring `db.session.execute(db.select(...))` with the `db.first_or_404`/`db.one_or_404` helpers added in 3.0. Both legacy forms still work, so the finding is the missing predicate rather than the API - but write the fix in the style the file already uses
- `Session.get()` looks in the identity map first and queries the database only for what is not present, so an object already loaded in that session comes back with no query for a predicate to apply to. A lookup by primary key is the wrong place to enforce ownership even where it looks like a query
- Enforce the rule once rather than at every call site: SQLAlchemy's `with_loader_criteria()` adds criteria for an entity globally - "as it appears in the SELECT query as well as within any subqueries, join conditions, and relationship loads" - and the documented way to apply it to every statement is a `do_orm_execute` event listener that adds the option to each SELECT
- On Django REST Framework, scope the data in `get_queryset()` against `self.request.user`. DRF's own form is a method override, because a `queryset` class attribute is evaluated once at class definition and has no request in scope. That also covers the list endpoint, which has no object-level hook to fire
- Carry the same filter into the write paths. `Model.objects.filter(...).update()` and `.delete()` execute as a single SQL statement, return the number of rows matched or deleted, do not call `save()`, and send no `pre_save`/`post_save` or `pre_delete`/`post_delete` signals - so no downstream hook can re-check ownership for them
- Where the identifier is guessable, answer 404 for both the missing and the not-owned row. Keep 403 for a gate that does not itself depend on the record existing - Django raises `PermissionDenied` for exactly that case - since RFC 9110 makes the 404 substitution a choice available to a server unwilling to state the reason, not a rule

## Taint Sinks

`Model.query.get()`, `Session.get()`, `db.session.get()`, `.filter_by(id=...)`, `.filter(pk=...)`, `get_object_or_404()`, `Model.objects.get()`, `.update()`, `.delete()` - each keyed on a user-supplied primary key with no owner column in the same call

## Remediation Steps

- Trace data flow - find where a user-controlled ID reaches a database query as the primary-key lookup value
- Locate every call keyed on that identifier alone, on the read path and on the update and delete paths that reach the same row
- Add the ownership filter to the call itself - `get_object_or_404(Document, pk=pk, user=request.user)` on Django, `Document.query.filter_by(id=doc_id, user_id=current_user.id).one_or_404()` on Flask-SQLAlchemy - rather than a check performed after retrieval
- On DRF, override `get_queryset()` to filter by `self.request.user`, so list, retrieve, update and destroy are scoped by one edit
- Where the rule is application-wide and the call sites are many, add a `with_loader_criteria()` option from a `do_orm_execute` listener instead of repeating the predicate
- Handle missing resources uniformly - return 404 for both the non-existent and the unowned key
- Test privilege escalation - request another user's known primary key while authenticated as a different account, on every verb that reaches the row
