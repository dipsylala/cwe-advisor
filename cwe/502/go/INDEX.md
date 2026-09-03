# CWE-502: Deserialization of Untrusted Data - Go

## LLM Guidance

Go's type system limits classic gadget-chain remote code execution, but `encoding/gob` and `net/rpc` will happily instantiate and populate any registered struct field-including privileged ones like `IsAdmin` or `Balance`-from untrusted input, and YAML libraries can cause resource-exhaustion or unexpected-type issues. The primary fix is the destination type, not the wire format: decode into a narrow, explicitly-typed request struct that carries only client-settable fields (never the persistence struct, never `interface{}`/`map[string]interface{}`), then resolve privileged values server-side. `gob` decodes only the fields present in the destination type and ignores the rest, so pointing the existing `Decode(&dto)` at a narrower struct closes the privileged-field vector without changing what producers send. Switch gob to JSON only when every producer changes in the same fix - a decoder-only format swap breaks every existing message and must be called out as a breaking change, not folded into the security fix. For JSON, add `decoder.DisallowUnknownFields()` and explicit field validation.

## Key Principles

- Do not expose `net/rpc` on attacker-reachable input, and keep `interface{}`-typed fields out of any struct that `gob` decodes from untrusted data - an interface field is where a `gob.Register`ed type gets instantiated from the payload. A concrete, narrow destination struct has no such field to abuse, so the gob call itself does not have to go
- Decode untrusted JSON into a purpose-built request DTO containing only client-settable fields, not the domain/persistence struct that also carries privileged fields like `IsAdmin` or `Role`
- Use `json.NewDecoder(r.Body).DisallowUnknownFields()` to reject unexpected fields instead of `encoding/json`'s default silent-ignore behavior
- Avoid unmarshaling untrusted data into `interface{}` or `map[string]interface{}` with unchecked type assertions (`data["x"].(string)`); these panic on type mismatch and provide no schema enforcement
- If using `gopkg.in/yaml.v2` or `v3`, treat "no code execution" as separate from "no need to validate"-apply the same field-level validation as JSON, and never build an `interface{}` field expansion from untrusted YAML tags
- Determine privileged fields (admin status, balance, role) from server-side authorization/database lookups, never from deserialized client data
- `gopkg.in/yaml.v3` does not construct arbitrary types the way Python's loader does, so the risk here is shape rather than execution: decode into a concrete struct rather than `map[string]interface{}`, and bound the input, since deeply nested or alias-heavy YAML is a resource-exhaustion vector

## Taint Sinks

`gob.NewDecoder().Decode()`, `net/rpc` handlers, `json.Unmarshal()`/`Decode()` into `interface{}` or `map[string]interface{}`, `yaml.Unmarshal()`

## Remediation Steps

- Locate - Find `gob.Decode`, `net/rpc` handlers, `json.Unmarshal`/`json.NewDecoder(...).Decode`, and `yaml.Unmarshal` calls that read from `r.Body`, request parameters, or other untrusted sources
- Trace data flow - Follow the decoded struct or map into business logic; flag any privileged field (`IsAdmin`, `Role`, `Balance`, `Price`) that originates from the decoded value rather than a server-side lookup
- Replace the unsafe pattern - Point the existing decoder at a scoped request struct (for `gob`, the same `Decode(&dto)` call with a narrower type); convert `interface{}`/`map[string]interface{}` decoding to a typed struct with explicit tags. Change the format (gob to JSON) only when the producers are in the same change, and state it in the write-up as a breaking change rather than part of the fix
- Bind, encode, validate, or authorize - Call `decoder.DisallowUnknownFields()`, then a `Validate()` method checking length/range/format on every field before use; resolve authorization fields via `checkAdminPermissions(ctx)` or a DB lookup, not the request struct
- Break taint after allowlist validation - Construct the persistence/domain object explicitly from validated request fields plus server-computed authorization values, rather than reusing the decoded struct directly
- Harden configuration - Wrap request bodies in `http.MaxBytesReader(w, r.Body, limit)` before decoding to prevent oversized-payload resource exhaustion
- Test - Send payloads with extra fields (expect rejection), boundary/invalid types (expect validation error, not panic), and attempts to set privileged fields (expect no effect on authorization)
