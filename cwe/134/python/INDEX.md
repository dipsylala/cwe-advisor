# CWE-134: Use of Externally-Controlled Format String - Python

## LLM Guidance

Python has no `%n` write primitive, so a user-controlled format string cannot corrupt memory. The risk is information disclosure: `str.format()` allows attribute access and item lookup inside placeholders, so if untrusted input becomes the *template* passed to `.format(**data)` or `.format(obj)`, an attacker can walk from a harmless-looking object into its internals - `{0.__class__.__init__.__globals__}` reaches module globals including settings and secrets. The fix is that the template is always written by the application; untrusted input is only ever a substitution value.

## Key Principles

- Never pass untrusted input as the template to `.format()`, `%`, `Formatter().format()`, or `Template.substitute()`
- The attribute chain is what the disclosure runs on: `{0.__class__}` traverses attributes, while `[...]` calls `__getitem__`, so `{user[__init__]}` raises `TypeError` on a non-subscriptable object. Assume the dotted form is reachable. The `{0.__class__.__init__.__globals__}` chain only works when the object's class defines its own `__init__` - a plain data holder using the inherited `object.__init__` breaks the chain with `AttributeError`, which is a property of the test object, not proof the finding is safe
- The well-known `{o.__class__.__mro__[1].__subclasses__()}` sandbox-escape payload does *not* work here: the format mini-language has no call syntax, so the parentheses are read as a literal part of the attribute name and it raises `AttributeError` regardless of whether the code is vulnerable - testing with it proves nothing either way
- Prefer f-strings for application-authored templates: an f-string is parsed from source at compile time, so it cannot be constructed from a runtime string without `eval()`, which would be a more severe finding (CWE-95)
- The legacy `%` operator is weaker but still lets an attacker probe mapping keys with `%(key)s` when both the format and the data dict are reachable
- Pass the *value* rather than the object where a template must be applied to data: `template.format(user.name)` exposes a string; `template.format(user)` exposes everything reachable from `user` - removing specific sensitive names from the substitution context closes that one path but not the underlying issue, since any object still reachable from an attacker-controlled template is a potential gadget
- Use logging's own parameterization - `logger.info("user %s", name)` - so the module does the substitution lazily and a malformed user string cannot become a template
- Where a template genuinely varies, select it from a fixed dictionary of literals by key, and consider `string.Template` with `safe_substitute()`, whose syntax has no attribute access at all
- Guard against `{:>1000000000}`-style width abuse in any path where a user-supplied fragment reaches formatting, which is a memory-exhaustion vector rather than a disclosure one

## Taint Sinks

`str.format()`, `str.format_map()`, `"%" % value` with a tainted format, `string.Formatter().format()`, `string.Template().substitute()`, `logging` calls whose message argument is user data

## Remediation Steps

- Locate - find `.format()`/`%`/`Formatter` calls whose template argument is a variable
- Trace data flow - determine whether the template can carry request, database, or file content, and which objects are passed as substitution arguments
- Identify the unsafe pattern - a user-supplied template, or a template applied to a rich object rather than to plain values
- Replace with the safe pattern - an f-string or a literal template, with the untrusted value as an argument
- Bind, encode, validate, or authorize - where templates must vary, look them up from an application-defined dictionary by key and reject unknown keys
- Harden configuration - use `logger.info("...%s", value)` parameterization rather than pre-formatted messages, and pass plain values rather than model objects into any template
- Test - submit `{0.__class__.__init__.__globals__}`, `{config[SECRET_KEY]}`, and `{:>1000000000}` through every path that formats user text and confirm they are rendered literally or rejected. For the `%`-operator path, probe with a key that actually exists in the substitution dict - `%(__class__)s` against an ordinary dict raises `KeyError` whether or not the code is vulnerable, so that test passes either way and proves nothing
