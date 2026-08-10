# CWE-502: Deserialization of Untrusted Data - Go

## LLM Guidance

Go's type system limits classic gadget-chain remote code execution, but `encoding/gob` and `net/rpc` will happily instantiate and populate any registered struct field-including privileged ones like `IsAdmin` or `Balance`-from untrusted input, and YAML libraries can cause resource-exhaustion or unexpected-type issues. The primary fix is to avoid `encoding/gob`/`net/rpc` on untrusted data entirely, and when using `encoding/json`, decode into a narrow, explicitly-typed request struct (never the same struct used for persistence, and never `interface{}`/`map[string]interface{}`) with `decoder.DisallowUnknownFields()`, followed by explicit field validation and server-side authorization.

## Key Principles

- Never call `gob.NewDecoder(...).Decode(...)` or expose `net/rpc` endpoints on attacker-reachable input; these formats instantiate and populate arbitrary registered struct fields with no integrity check
- Decode untrusted JSON into a purpose-built request DTO containing only client-settable fields, not the domain/persistence struct that also carries privileged fields like `IsAdmin` or `Role`
- Use `json.NewDecoder(r.Body).DisallowUnknownFields()` to reject unexpected fields instead of `encoding/json`'s default silent-ignore behavior
- Avoid unmarshaling untrusted data into `interface{}` or `map[string]interface{}` with unchecked type assertions (`data["x"].(string)`); these panic on type mismatch and provide no schema enforcement
- If using `gopkg.in/yaml.v2` or `v3`, treat "no code execution" as separate from "no need to validate"-apply the same field-level validation as JSON, and never build an `interface{}` field expansion from untrusted YAML tags
- Determine privileged fields (admin status, balance, role) from server-side authorization/database lookups, never from deserialized client data

## Remediation Steps

- Locate - Find `gob.Decode`, `net/rpc` handlers, `json.Unmarshal`/`json.NewDecoder(...).Decode`, and `yaml.Unmarshal` calls that read from `r.Body`, request parameters, or other untrusted sources
- Trace data flow - Follow the decoded struct or map into business logic; flag any privileged field (`IsAdmin`, `Role`, `Balance`, `Price`) that originates from the decoded value rather than a server-side lookup
- Replace the unsafe pattern - Convert `gob`/`net/rpc` untrusted-input paths to `encoding/json` with a scoped request struct; convert `interface{}`/`map[string]interface{}` decoding to a typed struct with explicit `json` tags
- Bind, encode, validate, or authorize - Call `decoder.DisallowUnknownFields()`, then a `Validate()` method checking length/range/format on every field before use; resolve authorization fields via `checkAdminPermissions(ctx)` or a DB lookup, not the request struct
- Break taint after allowlist validation - Construct the persistence/domain object explicitly from validated request fields plus server-computed authorization values, rather than reusing the decoded struct directly
- Harden configuration - Wrap request bodies in `http.MaxBytesReader(w, r.Body, limit)` before decoding to prevent oversized-payload resource exhaustion
- Test - Send payloads with extra fields (expect rejection), boundary/invalid types (expect validation error, not panic), and attempts to set privileged fields (expect no effect on authorization)

## Safe Pattern

```go
// SAFE: typed request struct, unknown-field rejection, server-side authorization
package main

import (
    "context"
    "encoding/json"
    "errors"
    "net/http"
)

type CreateUserRequest struct {
    Username string `json:"username"`
    Email    string `json:"email"`
}

func (r *CreateUserRequest) Validate() error {
    if len(r.Username) < 3 || len(r.Username) > 32 {
        return errors.New("invalid username length")
    }
    return nil
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

    var req CreateUserRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields() // SAFE: reject unexpected fields, e.g. "isAdmin"
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := req.Validate(); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // SAFE: privilege determined server-side, never from the decoded request
    isAdmin := checkAdminPermissions(r.Context())
    _ = isAdmin
}

func checkAdminPermissions(ctx context.Context) bool { return false }
```
