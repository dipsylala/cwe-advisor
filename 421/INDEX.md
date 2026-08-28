# CWE-421: Race Condition During Access to Alternate Channel

## LLM Guidance

This weakness occurs when a program opens a secondary communication channel - a data port, named pipe, callback URL, or rendezvous socket - intended for one specific authorized peer, but accepts whichever connection arrives first without verifying identity, letting an attacker race the legitimate peer and hijack the channel. It is a specific case of the broader race-condition weakness, applied to channel or session setup rather than shared in-memory state. The fix is to bind the channel to the requesting session with an unpredictable, verifiable credential and reject any connection that cannot present it.

## Key Principles

- Never treat "first to connect" as implicit authentication; require the connecting peer to present a credential proving it is the party the channel was opened for
- Generate a unique, cryptographically unpredictable token or channel identifier per session or request, and require it before granting access on the alternate channel
- Verify the peer's identity using OS-level primitives where available (peer credentials on a socket, process identity on a named pipe) in addition to any application-level token
- Create the channel with restrictive access already in place at creation time rather than opening it broadly and restricting permissions afterward, which leaves a window of exposure
- Minimize the race window with a short timeout so the channel does not remain open indefinitely waiting for the legitimate peer
- Never treat "whoever connects first" as authentication - bind the channel to the identity of the session that requested it and reject a peer that does not match
- On Windows, `FILE_FLAG_FIRST_PIPE_INSTANCE` answers only "was I first", and it does so even against a squatter that did not pass the flag: a create that passes it fails with `ERROR_ACCESS_DENIED` when the name already exists, which is broader than the documented both-callers case and is what makes it useful for detection
- This is CWE-362 applied to channel setup; asynchronous signal delivery interrupting shared state is CWE-364 and unrelated

## Remediation Steps

- Locate - Identify where a secondary channel (port, pipe, socket, callback) is opened for a specific session or client
- Trace data flow - Follow how the channel is exposed, what identifies the expected peer, and how the first connection is handled
- Identify the unsafe pattern - Look for channels accepted without any peer verification, fixed or predictable ports or names, or no timeout on the open window
- Replace with the safe pattern - Bind the channel to an unpredictable, session-specific token or identifier and require it on connection
- Verify peer identity - Add OS-level peer verification where the platform provides it, as a layer independent of the application token
- Add secondary controls - Apply a short timeout on the open channel and log rejected or unexpected connection attempts
- Test - Attempt to connect to the channel before the legitimate peer and attempt to guess or brute-force the identifier, confirming both are rejected and the timeout is enforced
