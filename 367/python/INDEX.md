# CWE-367: Time-of-check Time-of-use Race Condition - Python

## LLM Guidance

The GIL protects the interpreter's own structures, not your read-modify-write sequence: a thread switch can occur between any two bytecodes, so `if balance >= amount:` followed by `balance -= amount` has the same gap it would have in C. The detail that decides the fix is deployment shape - most Python web applications run several worker processes (Gunicorn, uWSGI, Celery), so a `threading.Lock` protects one worker and nothing else. A fix that passes in a single-process test and fails in production is the characteristic failure here.

## Key Principles

- Push the invariant into the database: make the condition part of the write (`UPDATE ... WHERE balance >= :amount`) so it is evaluated under the row lock the write already takes, and check `rowcount` to learn the outcome
- A `threading.Lock` guards one process; with multiple workers use a database transaction, `SELECT ... FOR UPDATE`, or a distributed lock with an expiry - and prefer the database constraint over the lock
- Express the rule as a database constraint (`CHECK (balance >= 0)`, a unique index) where possible, so no code path can violate it regardless of ordering
- For filesystem work, open once and act on the file object rather than checking a path and then opening it: `os.path.exists()` followed by `open()` resolves the path twice
- Create exclusively with `open(path, 'x')` or `os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)`, and use `tempfile.NamedTemporaryFile`/`mkstemp` rather than composing a name yourself
- Prefer `try`/`except` over a pre-check (`try: open(...) except FileNotFoundError:`) - the exception reports the state at the moment of the operation, which a prior check cannot
- `itertools.count()`, `dict.setdefault()` and similar are not a substitute for a transaction; atomicity of a single bytecode does not extend to a sequence
- Where async code is involved, `await` is a yield point: state read before an `await` may be stale after it, so re-read inside the same transaction

## Taint Sinks

`os.path.exists()`/`os.access()` followed by `open()`, a read-then-write on a shared object or ORM instance, `Model.objects.get()` followed by `save()`, `tempfile.mktemp()`, a balance/quota check followed by a separate update

## Remediation Steps

- Locate - find a check and the operation it guards, separated by any statement, on state shared between requests or processes
- Trace data flow - determine what else can modify that state concurrently, and whether the deployment runs more than one worker process
- Identify the unsafe pattern - a Python-level check guarding a database write, a lock that only spans one process, or a path checked then opened
- Replace with the safe pattern - a single conditional `UPDATE` (or `select_for_update()` inside a transaction) whose result tells you whether it applied
- Bind, encode, validate, or authorize - add the corresponding database constraint so the invariant holds even if a new code path forgets the check
- Harden configuration - for filesystem operations use exclusive creation flags and `tempfile`, and avoid world-writable directories
- Test - run concurrent requests from several processes, not threads, and assert the invariant holds; a threaded test passes against a broken fix
