# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - Python

## LLM Guidance

Mass assignment vulnerabilities occur when user input is directly mapped to object attributes without validation, allowing attackers to modify unintended fields like `is_admin` or `role`. In Django/DRF this happens through `fields = "__all__"`, `setattr()` loops, or `request.data` unpacking; in FastAPI it happens through a Pydantic input model that declares a sensitive field directly - Pydantic's default (v1 and v2 alike) already silently ignores undeclared fields, so the risk is a field the schema actually declares, or a model that explicitly opts into `extra="allow"`. Always use explicit allowlists to control which attributes can be modified.

## Key Principles

- Use explicit field allowlists in forms/serializers; never use `fields = "__all__"`
- Validate and filter input before assigning to model attributes
- Mark sensitive fields as `read_only` in serializers (`read_only_fields` in `Meta`, or `read_only=True` per field) - this protects the serializer's own deserialization path (a name in `Meta.fields` is excluded from writes), but does nothing for a raw `setattr()` loop or a bare `Model(**data)` constructor call bypassing the serializer entirely, since it's serializer-generation metadata, not an assignment guard on the model itself. A DRF `ModelSerializer` treats a model field with `editable=False` as read-only automatically, but only through that same auto-generated serializer path - it has the identical limitation
- Use separate serializers/forms for create vs update operations with different field sets
- Prefer a plain `serializers.Serializer` (not `ModelSerializer`) or an explicit `PrimaryKeyRelatedField` when a view needs full control over which fields are writable, rather than relying on a model-derived serializer's defaults
- In FastAPI, `model_config = ConfigDict(extra="forbid")` (Pydantic v2) rejects an undeclared field outright, but it does not protect a field that *is* declared on the input model - `is_admin: bool = False` on a `UserUpdate` schema is still caller-controlled regardless of the `extra` setting; the sensitive field has to be absent from the input model entirely, or split into a separate admin-only schema
- An allowlist protects which fields can be set, not whose record is being updated - `setattr()`-ing only permitted fields onto a row selected by a caller-supplied `user_id`/`owner_id` still lets one user modify another's data; check ownership (or use `request.user` as the target) separately from field filtering

## Taint Sinks

`setattr()` in a loop over request data, `fields = "__all__"` in a ModelSerializer/ModelForm, `**request.data` unpacked into a model constructor, a Pydantic input model with `extra="allow"` or a sensitive field declared directly, `**model.dict()`/`**model.model_dump()` unpacked into an ORM constructor

## Remediation Steps

- Replace `fields = "__all__"` with explicit field lists - `fields = ['name', 'email', 'description']`
- Set `read_only_fields = ['is_admin', 'created_by', 'role']` for protected attributes on a `ModelSerializer` - for a `setattr()` loop or a bare `Model(**data)` constructor call, filter the keys explicitly instead, since no model-level flag protects those paths
- Avoid `for k,v in request.data.items() - setattr(obj, k, v)` patterns
- Create separate `CreateSerializer` and `UpdateSerializer` classes limiting exposed fields
- For FastAPI, define a separate Pydantic model per operation (a `UserUpdate` without `is_admin`, distinct from an internal `UserAdmin` schema) rather than relying on `extra="forbid"` alone to filter a single shared model
- Validate input with `clean()` methods before mass operations; note that a raw `setattr()` allowlist bypasses model/field validators entirely - pair it with `full_clean(exclude=...)` or route through a serializer instead
- Audit every serializer/schema class touching the model, not just the one in the finding - DRF/Pydantic protection is per-class, so a sibling admin or bulk-update view on the same model needs the same check
