# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') - C#

## LLM Guidance

In .NET, CWE-77 commonly appears where an application talks to a non-OS command interpreter, most often Redis or a similar key-value store, by hand-building the wire protocol command instead of using the client library's parameterized API. This is distinct from CWE-78 (`Process.Start`/OS shell execution), covered separately. The primary defence is to use the client library's typed or parameterized command methods, which frame each argument so embedded delimiters cannot be read as a new command.

## Key Principles

- **Primary defence:** use StackExchange.Redis's typed methods (`IDatabase.StringSet`, `HashSet`, etc.) or `IDatabase.Execute(command, args)` with arguments passed as separate array elements, never concatenated into one string
- Never hand-build a raw Redis command string (inline-protocol style, e.g. `"SET " + key + " " + value + "\r\n"`) over a raw `Socket`/`NetworkStream`; the plain-text inline protocol treats an embedded CRLF as the end of one command and the start of another
- RESP, the protocol StackExchange.Redis uses, encodes each argument with an explicit length prefix, so a value containing CRLF or spaces cannot split into an extra command when passed through the client's parameterized API
- Apply the same rule to other protocol clients (Memcached, mail/FTP libraries): prefer the maintained client library's structured API over building commands from string concatenation
- Validate and bound the size/character set of values used as keys or command arguments as defence-in-depth, even though the client library already prevents delimiter injection
- Connect with least-privilege data-store credentials (read-only where possible) so an injected command has limited effect if this control is ever bypassed

## Taint Sinks

`NetworkStream.Write()`/`Socket.Send()` with hand-built inline-protocol commands (e.g. Redis `"SET " + key`)

## Remediation Steps

- Locate - find code that opens a raw `Socket`/`TcpClient`/`NetworkStream` to a Redis, Memcached, or similar protocol port, or that builds a command string via `string.Concat`/interpolation before writing it to the connection
- Trace data flow - confirm which parts of the built command string originate from untrusted input (keys, values, user-supplied identifiers)
- Replace with the safe pattern - swap the raw socket/string-building code for StackExchange.Redis (or the equivalent maintained client) and its typed or `Execute(command, args)` API
- Bind arguments - pass each untrusted value as its own element in the `args` array rather than folding it into a pre-built string
- Add validation - constrain key/value length and character set as defence-in-depth
- Harden configuration - use a dedicated, least-privilege Redis user/ACL for the application connection where the deployment supports it
- Test - send values containing `\r\n`, spaces, and Redis command names (for example `\r\nFLUSHALL\r\n`) and confirm they are stored as literal data rather than executed as separate commands

## Safe Pattern

```csharp
using StackExchange.Redis;

// SAFE: arguments passed separately - RESP framing prevents delimiter injection
var redis = ConnectionMultiplexer.Connect("localhost");
IDatabase db = redis.GetDatabase();

string key = "session:" + sessionId;   // sessionId still validated upstream
string value = userSuppliedValue;      // may contain \r\n, spaces, etc.

db.StringSet(key, value);

// Equivalent for commands without a typed method:
db.Execute("SET", key, value);
```
