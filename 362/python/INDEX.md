# CWE-362: Race Condition - Python

## LLM Guidance

The GIL prevents two threads from executing Python bytecode simultaneously, but it does not make compound operations atomic: `counter += 1`, a dict/list mutation split across multiple statements, or a check-then-act sequence can still be interrupted between bytecode instructions and interleaved with another thread. The primary fix for threads is `threading.Lock`/`threading.RLock` around the full read-modify-write sequence. `asyncio` code has a different but equally real hazard: coroutines never run truly in parallel, but any `await` is a point where another task can run and mutate shared state before the current coroutine resumes, so an unguarded read-await-write across a scheduling point is a race even in single-threaded asyncio; use `asyncio.Lock` there. For multiple OS processes (`multiprocessing`, separate workers), the GIL does not apply at all and shared state needs `multiprocessing.Lock`/`Value`/`Manager`, or should be pushed to the database.

## Key Principles

- Use `threading.Lock`/`with lock:` around the full read-modify-write sequence for state shared between threads; do not assume the GIL makes `+=` or dict/list mutation atomic
- Use `asyncio.Lock`/`async with lock:` around any critical section that contains an `await`, since another task can run and mutate shared state during the suspension
- For multiple processes, use `multiprocessing.Lock`, `multiprocessing.Value`/`Array` with a lock, or a `Manager` proxy; in-process `threading.Lock` does not protect state across process boundaries
- Replace plain `dict`/`list` shared across threads with `queue.Queue` for producer/consumer patterns, and still guard compound check-then-act sequences explicitly
- For database-backed shared state, use a transaction with `SELECT ... FOR UPDATE` or an atomic `UPDATE ... SET balance = balance - %s WHERE id = %s AND balance >= %s` rather than a Python-level lock
- Keep locked/async-locked sections minimal but complete: acquire before the first read of shared state and release only after the final write

## Taint Sinks

`counter += 1` on shared state, `dict`/`list` mutation across threads without `Lock`, coroutine mutating shared state across an `await` without `asyncio.Lock`

## Remediation Steps

- Locate - Find module-level variables, instance attributes, or shared dict/list objects read and written by more than one thread, task, or process
- Trace data flow - Identify where a value is read, a decision made, and the value written back, including any `await` between the read and the write
- Identify the unsafe pattern - An unsynchronized read-modify-write, a compound operation assumed atomic because of the GIL, or a coroutine mutating shared state across an `await`
- Replace with the safe pattern - Wrap the critical section in `threading.Lock`, `asyncio.Lock`, or `multiprocessing.Lock` matching the concurrency model in use
- Bind, encode, validate, or authorize - For database-backed shared state, move the read-then-write into a single transaction using `SELECT ... FOR UPDATE` or a conditional atomic `UPDATE`
- Harden configuration - Ensure the same lock instance protects the resource consistently across all call sites, including exception paths (use `try`/`finally` or the context manager form)
- Test - Drive concurrent threads or tasks against the same resource and confirm the final value is always correct with no lost updates

## Safe Pattern

```python
# SAFE: threading.Lock protects the read-modify-write sequence across threads
import threading

class Counter:
    def __init__(self):
        self._lock = threading.Lock()
        self._value = 0

    def increment(self):
        with self._lock:
            self._value += 1

# SAFE: asyncio.Lock prevents another task from interleaving across an await point
import asyncio

class AsyncAccount:
    def __init__(self, balance):
        self._lock = asyncio.Lock()
        self._balance = balance

    async def withdraw(self, amount):
        async with self._lock:
            if self._balance < amount:
                raise ValueError("insufficient funds")
            self._balance -= amount
```
