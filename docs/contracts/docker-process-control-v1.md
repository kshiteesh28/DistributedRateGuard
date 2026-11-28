# Docker inspect/stop component v1

**Status:** Selected component contract; component source and native qualification accepted; full lifecycle integration remains open. Sources: PRD 8 / SRD 5, HLD 5 A-03 and LLD lifecycle requirements. This is an internal control boundary, not an epoch capability.

## Ownership and trust

IRecoveryProcessController accepts an exact registered pending or observed container target. Structural validation is not authorization: the future supervisor must obtain targets from complete, trusted inventory while holding runtime ownership. No public caller selects arbitrary Docker paths.

The controller owns its transport/probe; their borrowed IClock must outlive every call. Configuration is immutable. Calls have local state and explicit cancellation/deadlines; no controller lock spans I/O. Existing EpochGate's IProcessController remains a separate interface requiring future composition.

Native composition fixes the local socket owner/peer UID to 0 and proc root to /proc. A trusted deployment profile supplies the observer PID-namespace identity. Equality with /proc/1 alone does not establish host placement. Docker Desktop, proxies, remote daemons and unqualified PID/proc lookup contexts cannot support native cessation evidence.

## API and bounded parsing

A selected numeric API version is explicit, at least 1.42, and inside the observed daemon MinAPIVersion..ApiVersion range. Factory qualification has one five-second monotonic budget. There is no negotiated production default. The signal override first appears in [Docker API 1.42](https://docs.docker.com/reference/api/engine/version-history/#v142-api-changes); actual target compatibility must still be qualified.

Inspect uses GET /v<version>/containers/<full64-lowercase-ID>/json. Stop uses POST to that exact container's /stop?signal=SIGTERM&t=1 with empty body. Never use a name, ID prefix, CLI process, environment-selected daemon, redirect or automatic retry.

Before DOM allocation, a bounded SAX pass rejects duplicate keys and excessive nesting/nodes/decoded strings/object fields. Limits: 256 KiB body, depth 16, 4,096 nodes, 256 fields per object and 16,384 bytes per decoded string. Required values have exact types. Invalid/missing/mismatched data cannot become positive exit evidence.

All eight immutable labels must equal trusted target values: io.rateguard.domain, epoch, authority, policy, role, slot, participant and incarnation. Canonical hex, role text and decimal slot match the bootstrap model. Unknown/reused target identities fail before POST.

## Inspect and stop outcomes

MatchedExited requires exact CID/labels, RestartPolicy=no, State.Status=exited, Running=false, Restarting=false and Pid=0. An observed target also requires the recorded-process probe to report RecordedProcessAbsent. A pending target can yield only RuntimeOnlyPendingTarget scope. Zombies, PID reuse, probe failures, 404/removal, created/dead/paused/restarting states and incomplete observations never satisfy observed cessation.

Running identity is point-in-time data. A logically bound CID can still be drained when its restart policy or OS identity is wrong; those failures prevent positive exit classification but do not protect a known container from stop. Stop's 204/304 results are ACKs only. After every stop result, the future supervisor must inspect/reconcile; an ACK does not close an epoch.

Inspect/stop default budgets are 5/15 seconds; maximum 30 seconds. Initial invalid deadlines differ from in-flight expiry. Recheck clock health, cancellation and deadline after I/O, parsing and probe work before positive completion. Every post-dispatch failure preserves stop uncertainty; a transport failure before POST is not a possibly-sent stop. Operation IDs are echoed control identifiers, not a durable replay journal.

## Recorded-process evidence

The native probe checks qualified observer/proc lookup context, boot identity, PID/start ticks and common time provenance with bounded no-follow procfs reads. Only exact kernel namespace links are followed. A live target's start identity and time namespace must match; changed/unreadable data stays Unknown.

A missing proc directory alone is insufficient because [procfs can hide live processes](https://www.kernel.org/doc/html/latest/filesystems/proc.html). Corroborate ENOENT with read-only syscall(SYS_pidfd_open,pid,0): only ESRCH may proceed to the same-boot/observer/clock rechecks. A returned descriptor is closed and leaves absence uncorroborated; every other error is Unknown. This sends no signal, performs no wait and needs no handle captured while the process was alive. [Linux pidfd_open semantics](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).

Do not attach a fresh target time-namespace observation after death. MatchedZombie is diagnostic and does not satisfy the controller's conservative exit rule. All evidence is point-in-time: external restart and in-flight old starts must be excluded by the future durable supervisor protocol.

## Acceptance and remaining integration

Require independent fake-driven CID/label/JSON/deadline/uncertainty tests, portable stat/pidfd classification tests, real Linux child-process fixtures and an actual local rootful Docker qualification. The latter records observed API/image/clock/profile and running/stop/exited transitions on one owned constrained synthetic container. It does not establish full deployment, positive fencing of every old participant, quota safety or release metrics.

Durable recovery operations, orphan reconciliation, an old-start barrier, authenticated bootstrap/activation, witness integration and verified successor authorization remain separate. No scan, ACK, process observation or successful fixture grants serving authority.
