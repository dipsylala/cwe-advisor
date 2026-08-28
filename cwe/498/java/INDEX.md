# CWE-498: Cloneable Class Containing Sensitive Information - Java

## LLM Guidance

`Cloneable` plus `Object.clone()` creates a duplication path that bypasses the constructor entirely, so no validation, authorization, or auditing written there runs on the copy. For a class holding credentials, keys, tokens, or a security context, any code with a reference can produce an untracked copy - and the default shallow copy means the clone shares the original's backing arrays. Do not implement `Cloneable` on such a class: make it `final`, provide no `clone()`, and let the inherited `Object.clone()` throw `CloneNotSupportedException`.

## Key Principles

- Make the class `final` so a subclass cannot add the `Cloneable` support the base class deliberately omits
- Omit `clone()` entirely rather than overriding it to throw - a class that is not `Cloneable` already fails, and adding the method invites someone to implement it later
- Provide a static factory method where copying is genuinely needed, so every instance still goes through the constructor and its checks
- Make the fields `final` and defensively copy mutable ones (`Arrays.copyOf`) in the constructor, so the caller's array cannot be mutated to change the stored credential afterwards
- Prefer `char[]` over `String` for a password and clear it with `Arrays.fill(password, '\0')` when done - a `String` cannot be erased and stays in the heap until collected
- Close the other bypass routes as well: mark the class non-serializable (or give it `writeObject`/`readObject` that throw), since serialization is the same constructor-bypassing copy
- Do not add a copy constructor that skips validation - the point is that every path to an instance runs the same checks
- Where a defensive copy of a returned array is needed, return `Arrays.copyOf(...)` from the accessor rather than the field itself

## Taint Sinks

`implements Cloneable` on a credential/key holder, `Object.clone()`, `super.clone()` returning a shallow copy of an array field, a getter returning a mutable array field directly, `Serializable` on the same class

## Remediation Steps

- Locate - find classes implementing `Cloneable` or overriding `clone()` that hold credentials, keys, tokens, or session state
- Trace data flow - determine who can obtain a reference to the instance and therefore call `clone()`, and which fields are shared by a shallow copy
- Identify the unsafe pattern - `Cloneable` on a sensitive class, a shallow `clone()`, or an accessor handing out the backing array
- Replace with the safe pattern - `final class`, no `clone()`, `final` fields, defensive copies in the constructor and in accessors, and a factory method where copying is required
- Bind, encode, validate, or authorize - keep the constructor's validation as the single gate, and add an explicit `clear()` for secret material
- Harden configuration - block the serialization bypass too, and consider a deserialization filter for the process
- Test - assert `clone()` throws `CloneNotSupportedException`, that mutating the array passed to the constructor does not change the stored value, and that an accessor's returned array can be mutated without effect
