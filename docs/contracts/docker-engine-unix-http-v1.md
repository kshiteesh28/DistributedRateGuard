# Docker Engine Unix HTTP Transport Contract (Proposal)

**Status:** Selected internal component contract; implementation and verification are tracked separately. No Docker deployment, process-fencing or release guarantee is claimed.

## Boundary and API

`IUnixHttpTransport::RoundTrip` in `src/supervisor/unix_http_transport.h` carries only GET or POST, an origin-form target, an absolute `CLOCK_MONOTONIC` deadline (`platform::MonoNanos`), and a cancellation flag. Requests have no caller-controlled headers or body. The controller constructs and validates the Docker API-version-qualified target; the transport never chooses or upgrades an API version. The response exposes the final status and bounded decoded body. Transport failures contain a bounded reason and `request_possibly_sent`; that flag is false until a first request byte is written and true thereafter. Failure reasons include invalid target/deadline, unconfigured socket, unsupported platform, peer mismatch, overload, cancellation, deadline expiry, clock failure, socket/protocol error, response limit, and allocation failure. Any failure after dispatch is uncertain to its caller. HTTP error statuses remain responses. There are no automatic retries or redirects.

## Local socket and trust boundary

The concrete Linux transport uses only a configured pathname AF_UNIX stream socket. The factory validates the canonical socket path and expected socket metadata, then captures device/inode/owner identity. Each exchange rechecks that identity, creates a fresh `SOCK_NONBLOCK | SOCK_CLOEXEC` descriptor, and verifies peer credentials with `SO_PEERCRED`. Both expected peer UID and socket owner UID default to root (0); nonzero overrides exist only for internal tests, and the production controller must keep both at 0. TCP, abstract sockets, proxy variables, Docker context/config directories, redirects, TLS, and caller-supplied endpoint selection are excluded. Socket ownership/path validation and privileged host configuration remain operator assumptions; peer UID verification does not authenticate a particular daemon binary.

## Request validation and resource bounds

Reject targets over 2,048 bytes; require a leading `/` and visible ASCII bytes only (`0x21–0x7e`), excluding `#`, CR, LF, and NUL. Requests are GET or POST with an empty body and generated fixed headers; total encoded request is at most 4 KiB. Allow at most four in-flight exchanges; do not queue, and fail fast as `Overloaded` when full. No mutex is held during socket operations.

Proposed parser caps: 8 KiB total response headers, at most 64 header fields, 512 KiB total response wire bytes, 256 KiB decoded body, at most 4,096 chunks, and at most 128 bytes per chunk-size line. Wire accumulation stops before exceeding its cap; the bounded parser checks header/count/chunk/body caps before returning a decoded response. Allocation failure is a bounded transport error. No raw request, response, socket path, or daemon error text is logged by this component.

## HTTP framing

Parse strict HTTP/1.0 or HTTP/1.1 status and header lines with CRLF. Reject informational responses, malformed status/header syntax, duplicate Content-Length, Transfer-Encoding combined with Content-Length, unsupported transfer/content codings, invalid chunk framing, chunk extensions, nonempty trailers, and bytes beyond the framed response. Support exactly one `chunked` transfer coding, a single valid Content-Length, or close-delimited bodies completed by EOF. For this Docker transport profile, 204 and 304 must have no transfer coding and may omit Content-Length or use Content-Length: 0 only; any body bytes are rejected. This is narrower than all general HTTP 304 metadata use. A framed response must also satisfy the connection-close exchange contract; failure to observe EOF before the deadline is an error. The transport rechecks cancellation and the injected clock/deadline after parsing and before reporting success. Never reinterpret malformed or truncated framing as a successful empty response.

These deliberately narrow framing rules follow HTTP/1.1 message framing and parsing in [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html). This component implements only HTTP framing and local socket transport; it does not interpret paths, response bodies/status meaning, container state, or lifecycle operations.

## Deadlines, cancellation, and uncertainty

Use the injected trusted monotonic clock and absolute deadlines for connect, writes, reads, and waits. Recompute remaining time after EINTR, EAGAIN/EWOULDBLOCK, and each readiness notification; do not restart the timeout. Cancellation is checked at each wait and I/O boundary. Cancellation or timeout after any request byte was written reports `request_possibly_sent=true`; callers must treat a stop outcome as unknown and inspect/reconcile rather than retry automatically. The transport rejects deadlines already expired or more than 30 seconds ahead, using the injected `IClock`. Higher layers may choose shorter budgets; this hard cap is an implementation bound, not a product latency guarantee.

Linux AF_UNIX provides local process communication and peer credentials; `poll` readiness waits are bounded by a timeout and can be interrupted, so callers must recompute their deadline after interruptions. See Linux man-pages for [`connect(2)`](https://man7.org/linux/man-pages/man2/connect.2.html), [`unix(7)`](https://man7.org/linux/man-pages/man7/unix.7.html), and [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html). A nonblocking Unix socket `connect` that returns `EAGAIN` is a safe transport failure here; only `EINPROGRESS` proceeds to readiness polling and `SO_ERROR` validation. The transport is Linux-only; other platforms return an explicit unsupported result.

## Error and response ownership

Stable failure reasons are `InvalidTarget`, `InvalidDeadline`, `NotConfigured`, `UnsupportedPlatform`, `PeerCredentialMismatch`, `Overloaded`, `Cancelled`, `DeadlineExpired`, `ClockFailure`, `SocketFailure`, `ProtocolError`, `ResponseTooLarge`, and `AllocationFailure`. No raw errno strings or daemon response text are emitted as telemetry. Callers own interpretation of Docker status/body and operation state; transport success alone does not prove a container stopped, exited, or was fenced.

## Required verification before implementation acceptance

Use a fake Unix HTTP peer and injected clock/cancellation seam to verify exact request bytes; HTTP status and all three framing modes; 204/304; every byte/count bound; malformed and ambiguous framing; extra bytes; EOF truncation; cancellation/deadline at connect/write/read; EINTR/EAGAIN deadline preservation; peer UID mismatch; concurrency cap; and both `request_possibly_sent` states. Add a Linux integration probe for real `SO_PEERCRED` behavior. These checks are acceptance work, not completed evidence.
