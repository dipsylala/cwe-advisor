# CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key - Python

## LLM Guidance

CWE-566 here is the SQL-primary-key case: a user-controlled ID (URL parameter, form field) is used as the lookup value in a Django ORM / SQLAlchemy / Flask query, and the query returns or modifies the matching row without an ownership filter in the query itself. The fix belongs in the query - filter by both the primary key and the authenticated user's ID in the same call - not in a separate ownership check performed after the row has already been fetched.

## Key Principles

- Never trust a user-controlled primary key value as sufficient proof of authorization
- Filter the query itself by both the primary key and the authenticated user's ID (`filter_by(id=doc_id, user_id=current_user.id)`) - do not fetch by ID alone and compare ownership afterward in application code
- Use framework-level authorization decorators for defense-in-depth, but do not rely on them as the only protection
- Apply the same composite filter to every query path that reads, updates, or deletes the resource by ID
- Return 404 instead of 403 - Avoid leaking resource existence information

## Taint Sinks

`Model.query.get()`, `.filter_by(id=doc_id)`, `get_object_or_404()` without a `user_id` filter

## Remediation Steps

- Trace data flow - Find where a user-controlled ID reaches a database query as the primary-key lookup value
- Locate the query construction - Identify `.get()`, `.filter_by(id=...)`, or `get_object_or_404()` calls that use only the primary key
- Add the ownership filter to the query itself - `Document.query.filter_by(id=doc_id, user_id=current_user.id).first_or_404()` - not a separate check performed after retrieval
- Apply the same composite filter to every verb that touches the resource - GET, PUT, PATCH, DELETE
- Handle missing resources uniformly - Return 404 for both non-existent and unauthorized resources
- Test privilege escalation - Request another user's known primary key while authenticated as a different account

## Safe Pattern

```python
from flask import abort
from flask_login import current_user

@app.route('/documents/<int:doc_id>')
@login_required
def get_document(doc_id):
    # Query with BOTH resource ID and user ID
    document = Document.query.filter_by(
        id=doc_id,
        user_id=current_user.id
    ).first_or_404()
    
    return jsonify(document.to_dict())
```
