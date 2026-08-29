# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') - PHP

## LLM Guidance

In PHP, CWE-77 commonly appears in applications that implement their own command interpreter - an admin console, chat-bot command syntax, or macro/scripting mini-language - where user input selects or builds a command that a bespoke parser then executes via dynamic dispatch (`call_user_func`, variable functions, or a lookup by string). This is distinct from CWE-78 (`shell_exec`/`exec`/`proc_open` OS execution), covered separately. The primary defence is to allowlist known command verbs and parse arguments with a structured parser instead of routing raw input into dynamic dispatch.

## Key Principles

- **Primary defence:** map each recognised command verb to a specific, hardcoded handler via an explicit allowlist array, never via `call_user_func($userInput)` or variable-function/variable-variable dispatch on untrusted input
- Never let untrusted input choose which function, method or class is invoked directly; only the allowlist lookup result should reach the dispatch call
- The dangerous form is the *call*, not the name lookup: `$$cmd` alone resolves a variable, and it is `$$cmd()` that invokes. Search for the invocation forms, since a value can reach dispatch through several of them - `$obj->$method()`, `Foo::$method()`, `new $class`, and a string callback handed to `array_map`/`usort`
- A callable string is not limited to a plain function name: the manual documents `"Class::method"`, `[$obj, 'method']` and `[Foo::class, 'method']` as callables, so a verb reaching dispatch unfiltered can select a static or instance method anywhere in the codebase
- Parse arguments with a structured approach (a defined grammar, or `explode()`/regex against an expected shape) rather than passing the raw remainder of the input string into the handler. `explode()` is a split, not a validator - it returns a one-element array when the separator is absent and empty strings for leading or trailing separators, so index into it only after checking the count
- Anchor the verb pattern with `\A` and `\z`, or add the `D` modifier. In PCRE `$` also matches immediately before a trailing newline, so `/^[a-z]+$/` accepts `status\n`
- Reject any input that does not match a known command verb exactly; do not attempt partial matches or fallthrough execution
- Do not reach for `function_exists()`/`is_callable()` as the control - neither is documented as one, and `is_callable()` returns true for any method name on an object implementing `__call()`, including methods that do not exist
- Apply defence-in-depth: run the interpreter's handlers with the minimum permissions they need, and log unrecognised or rejected commands
- Keep this bespoke-interpreter case separate from OS command execution (CWE-78), argument/flag injection into an external process (CWE-88), and code evaluation such as `eval()` (CWE-94/CWE-95); no shell or external process is involved here

## Taint Sinks

`call_user_func()`, `call_user_func_array()`, `$cmd()`, `$$cmd()`, `$obj->$method()`, `new $class`

## Remediation Steps

- Locate - find custom command-parsing code (an admin console, chat command handler, macro interpreter) that takes user input and dispatches it to a function or action
- Trace data flow - identify how the command verb and its arguments are extracted from the untrusted input and where dispatch occurs
- Identify the unsafe pattern - dynamic dispatch on a value derived from user input, in any of the invocation forms above
- Replace with the safe pattern - look up the verb in a fixed allowlist array mapping known strings to specific handler functions
- Break taint after allowlist validation - pass the allowlist-selected handler reference to the dispatch call, not the original input string
- Parse arguments structurally - validate each argument's type/format before passing it to the handler
- Test - submit unknown verbs, verbs with unexpected casing or trailing whitespace and newlines, and attempts to reference internal function or class names directly (including `Class::method` form), and confirm only allowlisted handlers ever execute
