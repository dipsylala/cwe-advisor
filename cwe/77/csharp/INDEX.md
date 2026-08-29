# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') - C#

## LLM Guidance

In .NET, CWE-77 commonly appears where an application talks to a non-OS command interpreter, most often Redis or a similar key-value store, by hand-building the wire protocol command instead of using the client library's parameterized API. This is distinct from CWE-78 (`Process.Start`/OS shell execution), covered separately. The primary defence is to use the client library's typed or parameterized command methods, which frame each argument so embedded delimiters cannot be read as a new command.

## Key Principles

- **Primary defence:** use StackExchange.Redis's typed methods (`IDatabase.StringSet`, `HashSet`, etc.) or `IDatabase.Execute(command, args)` with arguments passed as separate array elements, never concatenated into one string
- Never hand-build a raw Redis command string (inline-protocol style, e.g. `"SET " + key + " " + value + "\r\n"`) over a raw `Socket`/`NetworkStream`; the plain-text inline protocol treats an embedded newline as the end of one command and the start of another
- RESP, the protocol StackExchange.Redis uses, encodes each argument with an explicit length prefix, so a value containing CRLF or spaces cannot split into an extra command when passed through the client's parameterized API
- Keep the untrusted value in `args`; the `command` argument is not a safe position. StackExchange.Redis rejects only a *space* in a command name (`RedisCommandException`, from 3.0.17) - CRLF and tab pass through, are sent as one unknown token, and the server answers `-ERR unknown command`
- Memcached is not the same shape, so the reasoning does not carry across: only its data block is length-delimited, while the key sits on a space-delimited, CRLF-terminated command line. Safety there comes from the client rejecting the byte, not from framing - EnyimMemcachedCore's default `DefaultKeyTransformer` throws `ArgumentException` for 0x00-0x20 and space, and is replaceable via `options.KeyTransformer`
- Validate and bound the size/character set of values used as keys or command arguments as defence-in-depth, even though the client library already prevents delimiter injection
- Redis ACL users need Redis 6.0; read-only key permissions (`%R~`) need 7.0. Note the bound an ACL does not give you: key patterns restrict only commands that name keys, so a user scoped to `~app:*` can still run `FLUSHALL`. Excluding those takes an explicit `-flushall -flushdb -swapdb`

## Taint Sinks

`NetworkStream.Write()`/`Socket.Send()` with hand-built inline-protocol commands (e.g. Redis `"SET " + key`)

## Remediation Steps

- Locate - find code that opens a raw `Socket`/`TcpClient`/`NetworkStream` to a Redis, Memcached, or similar protocol port, or that builds a command string via `string.Concat`/interpolation before writing it to the connection
- Trace data flow - confirm which parts of the built command string originate from untrusted input (keys, values, user-supplied identifiers)
- Replace with the safe pattern - swap the raw socket/string-building code for StackExchange.Redis (or the equivalent maintained client) and its typed or `Execute(command, args)` API
- Bind arguments - pass each untrusted value as its own element in the `args` array rather than folding it into a pre-built string
- Add validation - constrain key/value length and character set as defence-in-depth
- Harden configuration - use a dedicated Redis ACL user for the application connection, excluding the keyspace-wide commands by name rather than relying on the key pattern to cover them
- Test - send values containing `\r\n`, spaces, and Redis command names (for example `\r\nFLUSHALL\r\n`) and confirm they are stored as literal data rather than executed as separate commands. Test the *argument* position: the same payload in the command-name position is not stored at all, so a test there passes without exercising the fix
