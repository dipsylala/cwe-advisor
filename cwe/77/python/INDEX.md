# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') - Python

## LLM Guidance

In Python, CWE-77 commonly appears where an application talks to a Redis (or similar) server by hand-building the wire protocol command instead of using redis-py's parameterized API. This is distinct from CWE-78 (`subprocess`/`os.system` OS execution), covered separately. The primary defence is to use redis-py's client methods, which pass each argument to the server as a separately framed value so embedded delimiters cannot be read as a new command.

## Key Principles

- **Primary defence:** use `redis.Redis` client methods (`.set()`, `.hset()`, etc.) or `.execute_command(*args)` with each value as its own argument, never a concatenated command string
- Never hand-build a raw Redis command by opening a `socket` and writing text like `f"SET {key} {value}\r\n"`; the plain-text inline protocol reads an embedded CRLF as the end of one command and the start of another
- redis-py's client encodes each argument as a RESP bulk string with an explicit length prefix, so a value containing CRLF, spaces, or command names cannot split into a separate command when passed through `execute_command` or a typed method
- Apply the same rule to other protocol clients (Memcached via `pymemcache`, SMTP via `smtplib`): prefer the maintained client's structured send/command methods over building the wire text by hand
- Validate and bound key/value length and character set as defence-in-depth, even though the client library already prevents delimiter injection
- Connect with least-privilege Redis ACL credentials (read-only where possible) so an injected command has limited effect if this control is ever bypassed

## Taint Sinks

`socket.send()`/`sendall()` with hand-built inline-protocol commands (e.g. Redis f-string `f"SET {key}..."`)

## Remediation Steps

- Locate - find code that opens a raw `socket` connection to a Redis/Memcached port, or that builds a command string via f-strings/`%`/`.format()` before sending it
- Trace data flow - confirm which parts of the built command string originate from untrusted input (keys, values, identifiers)
- Replace with the safe pattern - swap the raw socket/string-building code for `redis.Redis` (redis-py) and its typed methods or `execute_command(*args)`
- Bind arguments - pass each untrusted value as its own argument rather than folding it into a pre-built string
- Add validation - constrain key/value length and character set as defence-in-depth
- Harden configuration - use a dedicated, least-privilege Redis ACL user for the application connection
- Test - send values containing `\r\n`, spaces, and Redis command names (for example `\r\nFLUSHALL\r\n`) and confirm they are stored as literal data rather than executed as separate commands
