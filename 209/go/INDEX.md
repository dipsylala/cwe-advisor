# CWE-209: Generation of Error Message Containing Sensitive Information - Go

## LLM Guidance

Go error handling by convention returns `error` values that callers often serialize directly into HTTP responses with `http.Error(w, err.Error(), status)` or by JSON-encoding the error, leaking database driver messages, file paths, and panic details. Unrecovered panics in HTTP handlers can also surface stack traces if middleware or a debug handler echoes them back to the client. The fix separates the internal `error` (logged) from a fixed, generic user-facing message, and wraps handlers with panic recovery.

## Key Principles

- Never call `http.Error(w, err.Error(), ...)` or encode a raw `error` into a JSON response; return a fixed generic message instead
- Log detailed errors server-side with `log/slog` (or an equivalent structured logger) including request context, never the raw error text sent to clients
- Recover from panics in HTTP handlers with middleware using `defer`/`recover()` so an unhandled panic never reaches the client as a stack trace
- `fmt.Errorf("...: %w", err)` preserves `errors.Is`/`errors.As` chains but does not sanitize the message - the wrapped error still carries the original text
- Use custom error types (or error codes) carrying both a safe public message and an internal detail field, so handlers only ever surface the safe field
- Gate verbose error output behind an explicit development-only flag that defaults to off, never one inferred from an ambient value

## Remediation Steps

- Locate - search for `http.Error(w, err.Error()`, `fmt.Sprintf("%v", err)` written to a response, `json.NewEncoder(w).Encode(err)`, and handlers lacking panic recovery
- Trace data flow - follow the `error` value from its source (database driver, file I/O, third-party client) to where it is written to the `http.ResponseWriter` or response body
- Replace the unsafe pattern - stop passing `err` or `err.Error()` to the client; introduce a constant or mapped generic message per error class
- Log, then respond - call `logger.Error(...)` with the full error and request context, then send the client only the generic message and status code
- Harden configuration - add global panic-recovery middleware around all handlers and ensure any debug/verbose mode defaults to off and is not client-controllable
- Test - trigger database, filesystem, and type-assertion failures in tests and assert the HTTP response body contains no file paths, SQL text, or stack frames

## Safe Pattern

```go
// SAFE: log full error server-side, return generic message to client
import "log/slog"

func getUserProfile(w http.ResponseWriter, r *http.Request) {
    user, err := db.QueryUser(r.URL.Query().Get("user_id"))
    if err != nil {
        slog.Error("query user failed", "error", err, "path", r.URL.Path)
        http.Error(w, "unable to retrieve user profile", http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(user)
}

// SAFE: recover from panics before a stack trace can reach the client
func recoverMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if rec := recover(); rec != nil {
                slog.Error("panic recovered", "panic", rec, "path", r.URL.Path)
                http.Error(w, "internal server error", http.StatusInternalServerError)
            }
        }()
        next.ServeHTTP(w, r)
    })
}
```
