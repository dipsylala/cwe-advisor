# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') - Python

## LLM Guidance

In Python, CWE-77 commonly appears where an application talks to a Redis (or similar) server by hand-building the wire protocol command instead of using redis-py's parameterized API. This is distinct from CWE-78 (`subprocess`/`os.system` OS execution), covered separately. The primary defence is to use redis-py's client methods, which pass each argument to the server as a separately framed value so embedded delimiters cannot be read as a new command.

## Key Principles

- **Primary defence:** use `redis.Redis` client methods (`.set()`, `.hset()`, etc.) or `.execute_command(*args)` with each value as its own argument, never a concatenated command string
- Never hand-build a raw Redis command by opening a `socket` and writing text like `f"SET {key} {value}\r\n"`; the plain-text inline protocol reads an embedded newline as the end of one command and the start of another
- redis-py encodes each argument as a RESP bulk string with an explicit length prefix, so a value containing CRLF, spaces, or command names cannot split into a separate command when passed as an *argument*
- The first argument is the exception, and the guidance depends on it: `pack_command` whitespace-splits `args[0]` before framing, so that Redis receives `execute_command("CONFIG GET", k)` as two tokens. An untrusted value there does not create a second command, but it does change the array's arity - keep untrusted data out of the command-name position entirely rather than relying on the framing
- Apply the same rule to other protocol clients, but check what actually protects each one. `pymemcache` is not protected by framing: its key sits on a CRLF-terminated command line, and `check_key_helper` raises `MemcacheIllegalInputError` for whitespace, NUL, non-ASCII, and keys over 250 bytes
- `smtplib` rejects CR and LF in a command, but only from `putcmd`, and only since 3.6.15/3.7.12/3.8.12/3.9.7/3.10. That covers envelope addresses passed to `sendmail()`; it does not cover message headers, which reach the server through `data()` and are the caller's responsibility
- Validate and bound key/value length and character set as defence-in-depth, even though the client library already prevents delimiter injection
- Redis ACL users need Redis 6.0; read-only key permissions (`%R~`) need 7.0. Note the bound an ACL does not give you: key patterns restrict only commands that name keys, so a user scoped to `~app:*` can still run `FLUSHALL`. Excluding those takes an explicit `-flushall -flushdb -swapdb`

## Taint Sinks

`socket.send()`/`sendall()` with hand-built inline-protocol commands (e.g. Redis f-string `f"SET {key}..."`), `smtplib.SMTP.docmd()`

## Remediation Steps

- Locate - find code that opens a raw `socket` connection to a Redis/Memcached port, or that builds a command string via f-strings/`%`/`.format()` before sending it
- Trace data flow - confirm which parts of the built command string originate from untrusted input (keys, values, identifiers)
- Replace with the safe pattern - swap the raw socket/string-building code for `redis.Redis` (redis-py) and its typed methods or `execute_command(*args)`
- Bind arguments - pass each untrusted value as its own argument rather than folding it into a pre-built string, and keep the command name a literal
- Add validation - constrain key/value length and character set as defence-in-depth
- Harden configuration - use a dedicated Redis ACL user for the application connection, excluding the keyspace-wide commands by name rather than relying on the key pattern to cover them
- Test - send values containing `\r\n`, spaces, and Redis command names (for example `\r\nFLUSHALL\r\n`) and confirm they are stored as literal data rather than executed as separate commands. Test the *argument* position: the same payload in the command-name position is not stored at all, so a test there passes without exercising the fix
