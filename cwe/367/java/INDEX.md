# CWE-367: Time-of-check Time-of-use Race Condition - Java

## LLM Guidance

In a Java web application the two ends of this weakness are usually an authorization check and the operation it guards, separated by enough work that another request can change the state the check relied on. Every request runs on its own thread against shared state - a session object, a cached user, a database row - so "checked a moment ago" is not the same claim as "true now". The same pattern appears in file handling, where `Files.exists()` followed by `Files.newOutputStream()` resolves the path twice.

## Key Principles

- Perform the check and the action in one transaction, and read the state that the check depends on *inside* that transaction rather than from a cache or session attribute
- Hold the row: a `@Lock(LockModeType.PESSIMISTIC_WRITE)` repository method (`SELECT ... FOR UPDATE`) makes a concurrent revocation either land before the read or wait until after the commit
- Where pessimistic locking is too coarse, use optimistic locking with `@Version`: Spring Data does not surface the raw `jakarta.persistence.OptimisticLockException` from a version conflict - it translates it into `org.springframework.dao.OptimisticLockingFailureException` (typically the subclass `ObjectOptimisticLockingFailureException`) before your code sees it, and the check only runs if the write actually happens inside the transaction, so call `saveAndFlush`, not `save`
- Prefer a conditional update whose row count reports the outcome (`UPDATE ... WHERE version = :v`) over a read, a decision, and a separate write
- A `synchronized` block or a `ReentrantLock` guards one JVM only - useless across instances behind a load balancer, and misleading in a test that runs one node
- For filesystem work, resolve once: use `Files.newByteChannel` with `StandardOpenOption.CREATE_NEW` (which fails if the file exists) and `LinkOption.NOFOLLOW_LINKS` rather than checking `Files.exists()` first
- Use `Files.createTempFile` rather than composing a name and creating it separately
- Re-read the authorization subject rather than trusting a `SecurityContext` snapshot for a long-running operation; a role revoked mid-request is exactly the case this CWE covers

## Taint Sinks

`Files.exists()` followed by an open, `File.canWrite()`/`canRead()` followed by an operation, a repository read followed by a separate `save()`, a `SecurityContextHolder` role check separated from the guarded action, `File.createTempFile` misuse

## Remediation Steps

- Locate - find a check and the operation it authorizes, separated by other statements, service calls, or a transaction boundary
- Trace data flow - determine what the check reads (session, cache, database) and what else can change it concurrently
- Identify the unsafe pattern - the check reading from a source the action does not lock, or a check performed outside the transaction that acts
- Replace with the safe pattern - move both into one `@Transactional` method and read the state with a pessimistic-write lock
- Bind, encode, validate, or authorize - express the invariant as a database constraint or a conditional update so it holds even for a code path that forgets the check
- Harden configuration - for files, use `CREATE_NEW` and `NOFOLLOW_LINKS` and keep the directory unwritable by other users
- Test - drive the operation concurrently from several threads *and* several instances, and assert the invariant holds; a single-JVM test passes against a `synchronized`-only fix that fails in production
