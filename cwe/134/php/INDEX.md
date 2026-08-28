# CWE-134: Use of Externally-Controlled Format String - PHP

## LLM Guidance

`printf()`, `sprintf()` and `vsprintf()` take a format string of conversion specifiers. PHP does not implement C's `%n`, so this cannot become a memory-corruption primitive. The realistic impact is denial of service and error-driven disclosure: since PHP 8.0 a format requiring more arguments than were supplied throws `ArgumentCountError` and an unknown specifier throws `ValueError`, and a single `%2000000000s` exhausts `memory_limit` and kills the worker with a fatal error. Keep the format a literal written by the application and put user data in the argument list.

## Key Principles

- `printf("%s", $user_input)` rather than `printf($user_input)` - the format position is never user-controlled
- The width specifier is the harder-hitting route: `%2000000000s` is a fatal memory-limit error rather than a catchable exception, so it takes the worker down regardless of exception handling
- Since PHP 8.0 a mismatched argument count throws `ArgumentCountError` and an unknown specifier throws `ValueError`; unhandled, those become a 500 and, depending on `display_errors`, a stack trace disclosing file paths
- Ensure `display_errors` is off in production so an uncaught formatting error does not render internal detail to the client
- Where a format must genuinely vary, index a fixed application-defined array of literals by key and reject an unknown key - never accept the format itself
- `vsprintf()` with a user-controlled array is the same weakness with the arguments supplied indirectly; validate the count and types before the call
- `number_format()`, `date()` and `str_pad()` are safer choices where the goal is presentation rather than templating
- Static analysis for a non-literal first argument to the `printf` family catches the whole class cheaply

## Taint Sinks

`printf()`, `sprintf()`, `vsprintf()`, `vprintf()`, `fprintf()`, `sscanf()` format argument, `error_log()` with a pre-formatted user string

## Remediation Steps

- Locate - find `printf`-family calls whose format argument is a variable rather than a literal
- Trace data flow - determine whether that variable can carry `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`, database, or file content
- Identify the unsafe pattern - a non-literal format, or a format built by concatenation with user data
- Replace with the safe pattern - a literal format with `%s` and the value passed as an argument
- Bind, encode, validate, or authorize - where the format varies, resolve it through an allowlist array keyed by an application-defined name
- Harden configuration - turn off `display_errors` in production, set a sane `memory_limit`, and add a static-analysis rule for non-literal formats
- Test - submit `%s`, `%d`, `%x`, and `%2000000000s` through every path that formats user text and confirm they are printed literally rather than interpreted, and that no stack trace reaches the client
