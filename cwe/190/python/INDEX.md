# CWE-190: Integer Overflow or Wraparound - Python

## LLM Guidance

Python's built-in `int` is arbitrary precision, so the classic wrap-to-a-small-or-negative-value failure does not occur in pure Python arithmetic. That does not make the finding a false positive: an attacker-controlled value used to size a `bytearray`, a list, or a loop count is a resource-exhaustion denial of service, and any value that crosses an FFI boundary into a fixed-width C type (NumPy, `ctypes`, a C extension) reintroduces the classic overflow on the C side. The fix is an explicit application-level bound on inputs and on the computed total, plus an explicit range check before any FFI call.

## Key Principles

- "Cannot overflow" is not "is safe": validate both the operands and the computed total against practical limits the process can actually allocate
- Bound the result as well as the inputs - two individually reasonable values can multiply into an allocation that exhausts memory
- Check explicitly against the target width before crossing into NumPy or `ctypes`: a value above `2**31 - 1` assigned into an `int32` array wraps there, and NumPy will not raise for a Python `int` that fits in `int64` but not in the array's dtype
- NumPy's own integer arrays wrap on overflow (with a `RuntimeWarning` at most); use `dtype=object`, a wider dtype, or explicit checks where the operands are attacker-influenced
- `struct.pack` raises for an out-of-range value, so prefer it over a manual cast when serialising to a fixed-width field
- Watch loop counts and slice sizes as well as allocations: `range(n)` with a large `n` is a denial of service without allocating anything
- Where a value is read from a wire format as a fixed-width field, validate it against the domain's limits after unpacking, not before
- `sys.maxsize` is the maximum container size, not the maximum `int`; do not use it as an arithmetic bound

## Taint Sinks

`bytearray(n)`/`bytes(n)`, `[0] * n`, `range(n)`, `numpy.zeros(n)`/`numpy.empty(n)`, `ctypes` integer arguments, `struct.pack()`, a computed size passed to a C extension

## Remediation Steps

- Locate - find arithmetic on request-derived values that reaches an allocation, a loop bound, a slice size, or an FFI call
- Trace data flow - determine the reachable operand ranges and whether the result crosses into a fixed-width representation
- Identify the unsafe pattern - an unbounded product used as a size, or a Python `int` handed to NumPy/`ctypes` without a width check
- Replace with the safe pattern - validate each operand, compute the total, then validate the total against an application limit before allocating
- Bind, encode, validate, or authorize - clamp or reject at the boundary; do not rely on the allocation failing, since a large-but-possible allocation succeeds and starves the process
- Harden configuration - set process memory limits where the platform allows, and configure NumPy error handling (`np.seterr`) so overflow is not silently ignored
- Test - submit operands whose product exceeds the application limit, a value just above `2**31 - 1` on any FFI path, and a very large `range` bound; assert each is rejected rather than attempted
