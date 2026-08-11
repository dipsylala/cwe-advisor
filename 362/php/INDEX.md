# CWE-362: Race Condition - PHP

## LLM Guidance

PHP's typical process-per-request model means requests do not share in-memory state directly, so races appear at the shared resources requests do have in common: database rows, files, sessions, and shared caches (APCu, Redis, Memcached). The primary fix is to push the read-modify-write into a single atomic operation at that shared resource: a database transaction with `SELECT ... FOR UPDATE` (via PDO) or a conditional atomic `UPDATE`, `flock()` for shared files, or `apcu_inc()`/`apcu_cas()` for an in-memory counter shared across PHP-FPM workers on the same host. PHP's default session handler (`files`) already serializes concurrent requests for the same session ID by locking the session file for the request's duration; do not defeat this by calling `session_write_close()` early unless the remaining code no longer touches session data.

## Key Principles

- For database-backed shared state, wrap the read and the write in a single PDO transaction using `SELECT ... FOR UPDATE`, or use a conditional atomic `UPDATE ... WHERE balance >= :amount` and check the affected row count
- For shared files, use `flock($handle, LOCK_EX)` around the entire read-modify-write sequence, and release with `LOCK_UN` only after the write is flushed
- For a counter or flag shared across PHP-FPM workers on one host, use `apcu_inc()`/`apcu_dec()` (atomic) or `apcu_cas()` (compare-and-swap) instead of a separate `apcu_fetch()` followed by `apcu_store()`
- Do not disable or bypass the default session file lock (avoid early `session_write_close()`) when later code in the same request still reads or writes `$_SESSION`
- For state shared across multiple servers, use a datastore-level lock (database row lock, Redis `SET key value NX EX ttl`) rather than a host-local mechanism like `flock()` or APCu
- Never assume "PHP is single-threaded" removes the race; concurrent requests are still concurrent processes acting on the same external resource

## Remediation Steps

- Locate - Find database rows, files, session keys, or cache keys read and written by more than one concurrent request
- Trace data flow - Identify where a value is fetched, a decision made, and the value written back, and what other requests can reach the same resource in that interval
- Identify the unsafe pattern - A separate `SELECT` followed by `UPDATE` with no lock, a `apcu_fetch()`/`apcu_store()` pair, or a file read-modify-write without `flock()`
- Replace with the safe pattern - Use `SELECT ... FOR UPDATE` inside a PDO transaction, `apcu_inc()`/`apcu_cas()`, or `flock(LOCK_EX)` around the full sequence
- Bind, encode, validate, or authorize - Check the affected row count or `apcu_cas()` return value and reject/retry on conflict rather than assuming the write succeeded
- Harden configuration - Ensure the transaction isolation level and lock scope are consistent everywhere the resource is touched, including error and rollback paths
- Test - Fire concurrent requests (parallel HTTP clients or a load-testing tool) against the same resource and confirm the final state is always correct with no lost updates

## Safe Pattern

```php
// SAFE: SELECT ... FOR UPDATE inside a transaction serializes the read-modify-write on the row
function withdraw(PDO $pdo, int $accountId, int $amount): void
{
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT balance FROM accounts WHERE id = :id FOR UPDATE');
        $stmt->execute(['id' => $accountId]);
        $balance = $stmt->fetchColumn();

        if ($balance < $amount) {
            throw new RuntimeException('insufficient funds');
        }

        $update = $pdo->prepare('UPDATE accounts SET balance = balance - :amount WHERE id = :id');
        $update->execute(['amount' => $amount, 'id' => $accountId]);
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}

// SAFE: apcu_inc() is an atomic increment shared across PHP-FPM workers
apcu_inc('request_count');
```
