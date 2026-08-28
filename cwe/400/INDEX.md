# CWE-400: Uncontrolled Resource Consumption

## LLM Guidance

This weakness is a missing limit: a request, message, or file causes the application to allocate
memory, open handles, spawn work, or spend CPU in proportion to something the attacker controls,
until the service degrades or fails. The distinctive property is that each request is individually
legitimate - there is no malformed input to reject - so the fix is a bound applied where the resource
is acquired, not validation. Where the finding names a specific mechanism, prefer that entry:
catastrophic regular-expression backtracking is CWE-1333, and unbounded recursion is CWE-674.

## Key Principles

- Name the resource before proposing a fix - memory, CPU, file descriptors, sockets, threads,
  database connections, disk, or an external API quota. A cap on the wrong one leaves the finding open
- Bound the input where it is read, not after it is materialised: a size check that runs once the
  whole body is in memory has already paid the cost it was meant to prevent
- Set a timeout on every outbound call - HTTP client, database query, DNS lookup, lock acquisition. A
  connection with no read timeout holds its worker until the peer releases it, which turns one slow
  dependency into an outage for the whole pool
- Bound the result as well as the request: a query with a legitimate filter can still return millions
  of rows, so paginate in the query rather than slicing the list after loading it
- Look for multiplicative work - a per-item operation over an attacker-sized collection, a nested loop
  over two request-supplied lists, a GraphQL query whose nesting expands the result. Bound the count,
  not only each item's size
- Decompression and parsing amplify: a small archive, XML document, or image can expand by orders of
  magnitude, so limit decompressed size and nesting depth rather than input size
- Prefer a bounded queue with a rejection policy over an unbounded one, which does not prevent
  exhaustion but defers it into memory and turns a fast failure into a slow one
- Rate limiting complements a cap rather than replacing it - it bounds how often a request arrives,
  not how much one permitted request costs. Likewise authentication changes who can trigger the
  finding, so a multi-tenant service still needs per-tenant limits

## Remediation Steps

- Locate - identify the operation whose cost scales with attacker-controlled input, and which resource
  it consumes
- Trace the scaling factor - determine what the attacker controls: payload size, item count, nesting
  depth, page size, or concurrency
- Establish the current limit - check whether the framework already imposes a default cap, since many
  findings are a default raised or disabled rather than a limit never set
- Apply the bound at acquisition - cap the request body, result set, queue depth, thread and
  connection pools, decompressed size, and nesting depth at the point the resource is taken
- Add timeouts - connect, read, and total-operation timeouts on every dependency, plus a maximum
  request-handling duration
- Handle the limit as a normal outcome - return a clear rejection status, release everything acquired
  on every path including errors, and log enough to distinguish a limit breach from a fault
- Test - submit input at and beyond each limit, confirm rejection rather than degradation, and verify
  other requests are still served while the limit is exercised
