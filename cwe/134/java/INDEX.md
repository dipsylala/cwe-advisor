# CWE-134: Use of Externally-Controlled Format String - Java

## LLM Guidance

`String.format()`, `Formatter` and `PrintStream.printf()` take a format string of conversion specifiers, and `java.text.MessageFormat` takes a pattern (`{0}`, `{1,number,integer}`) carrying the same risk. Java's specifiers cannot read or write arbitrary memory - `%n` emits the platform line separator rather than a write primitive, and a mismatched specifier throws a catchable exception. The realistic impact is denial of service through an unhandled `IllegalFormatException`, plus information disclosure via positional specifiers: `%3$s` prints the third argument whatever the application's own template showed. Keep the format a compile-time literal and pass user data as arguments.

## Key Principles

- The format string is a literal; user data goes in the argument list (`String.format("%s", userInput)`)
- Positional specifiers are the disclosure route - where a call site passes several arguments, an attacker-written template can print one the intended template never showed
- A specifier that does not match the arguments throws `MissingFormatArgumentException`/`IllegalFormatConversionException`; unhandled, that is a request or thread failure, so this is a denial-of-service finding even where nothing leaks
- Use the logging framework's own placeholders - SLF4J `logger.info("user {} did {}", user, action)` - rather than pre-formatting the message; the `{}` form is substituted, never interpreted as a format
- `MessageFormat` patterns are equally unsafe from input, and its quoting rules (a single `'` escapes) make user text behave unexpectedly even without an attacker
- Where a format must vary, select it from a fixed `Map` or enum of literals by key and reject unknown keys
- Guard width specifiers (`%2000000000s`) in any path where a user fragment reaches a format, which is a memory-exhaustion vector rather than a disclosure one - wrapping the call in `catch (IllegalFormatException)` does not cover this: the huge width throws `OutOfMemoryError`, which is an `Error`, not an `IllegalFormatException`
- `java.util.logging`'s no-parameter `log()` overload never interprets its message as a format at all; only the parameterized overload turns it into a live `MessageFormat` pattern - a scanner treating every `Logger.log()` call the same way misses which overload the finding actually names. A malformed pattern on that path is swallowed silently, with no exception and no log line, so a test that only checks "does it throw" can pass against data loss it never notices
- Static analysis rules for non-constant format strings are cheap to enable and catch the whole class

## Taint Sinks

`String.format()`, `String.formatted()`, `PrintStream.printf()`/`format()`, `Formatter.format()`, `MessageFormat.format()`, `Logger` calls whose message is a concatenated user string

## Remediation Steps

- Locate - find formatting calls whose first argument is a variable rather than a literal, and logging calls that concatenate user data into the message
- Trace data flow - determine whether that variable can carry request parameters, headers, file content, or database values
- Identify the unsafe pattern - a non-literal format or pattern, or a message built with `+` before being handed to a logger
- Replace with the safe pattern - a literal format with the value as an argument, or SLF4J placeholders
- Bind, encode, validate, or authorize - where the template must vary, resolve it from an application-defined map of literals
- Harden configuration - enable a static-analysis rule for non-constant format strings, and ensure the framework's exception handler does not render stack traces to clients
- Test - submit `%s`, `%d`, `%3$s`, and `%2000000000s` through every path that formats or logs user text and confirm they are printed literally rather than interpreted or throwing
