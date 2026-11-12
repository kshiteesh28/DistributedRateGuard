# Implementation stories

**Date:** 2026-11-12 · **Status:** Planned; no implementation or acceptance results claimed.

Machine-readable handoff: [context blocks](context-blocks.json). Follow dependency IDs rather than numeric order. Release labels indicate the deliverable; independent oracle work precedes dependent correctness checks even when delivered with release B.

## RG-001

**Freeze wire contracts and build manifest** · Release A · Planned

Dependencies: none.

Freeze numbered v1 fields, enums, cost/operation binding, typed errors, and a C++20 target build lock before compiling services. Select compiler, CMake, library, model-tool, and Linux image versions by successfully configuring and building on the actual target environment; record exact versions and image digest rather than guessing or claiming an unbuilt lock is validated. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `proto/rateguard/v1/admission.proto`, `proto/rateguard/v1/authority.proto`, `CMakeLists.txt`, `build-lock.json`.

Classes: AdmissionService, AuthorityService.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-005, PRD-021, FR-005, FR-020.

Acceptance criteria (not run):

- **RG-001-AC01** — Golden protobuf/encoding fixtures reject unspecified enums, invalid widths and malformed payloads without quota mutation. Evidence: AT-04, AT-06.
- **RG-001-AC02** — Build manifest records exact tool/compiler/library versions and reproducible build commands; no runtime metric is claimed. Evidence: AT-13, AT-20.
- **RG-001-AC03** — Raw transport failure after dispatch carries Possible commitment; automatic strict retry/hedging is disabled. Evidence: AT-07.

## RG-002

**Implement immutable policy and checked arithmetic** · Release A · Planned

Dependencies: RG-001.

Preload finite immutable policy and integer state. Never insert unknown tenants. Use checked 128-bit refill and independent golden calculations. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `src/policy/policy_snapshot.h`, `src/policy/policy_loader.h`, `src/policy/canonical_codec.h`, `src/authority/bucket_math.h`.

Classes: PolicySnapshot, PolicyLoader, CanonicalPolicyCodec, BucketMath.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-001, PRD-002, PRD-003, FR-001, FR-002, FR-003.

Acceptance criteria (not run):

- **RG-002-AC01** — Canonical byte fixtures produce identical digests regardless of input map order; duplicate IDs and invalid policy bounds reject. Evidence: AT-01, AT-04.
- **RG-002-AC02** — At available=c*S admit; at c*S-1 limit. Maximum bounds, saturation, fractions and overflow fixtures agree with independent arithmetic. Evidence: AT-02, AT-03.
- **RG-002-AC03** — LIMITED advances refill accounting without cost debit; reject-all and double-debit mutations are detected. Evidence: AT-21.

## RG-003

**Implement shared clock provenance and commit timing** · Release A · Planned

Dependencies: RG-001.

Clock identity binds boot ID, time namespace and CLOCK_MONOTONIC. Client time and wall-clock TLS validity never create refill. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `src/platform/clock.h`, `src/platform/clock_linux.h`.

Classes: IClock, LinuxMonotonicClock.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-002, PRD-024, FR-001, FR-017.

Acceptance criteria (not run):

- **RG-003-AC01** — Wrong namespace/boot/clock ID prevents readiness; backwards time or syscall failure stops transitions. Evidence: AT-01, AT-17.
- **RG-003-AC02** — Clock samples and ordered state transitions have an auditable linearization mapping; late responses cannot move timestamps. Evidence: AT-02, AT-07.
- **RG-003-AC03** — Unknown provenance yields UNKNOWN safety evidence rather than PASS. Evidence: AT-17.

## RG-004

**Implement mTLS identity and operation authorization** · Release A · Planned

Dependencies: RG-001, RG-002.

Validate role/SAN/EKU/expiry every RPC including reused channels. Bind peer to tenant/operation and derive cost from policy. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `src/security/peer_authenticator.h`, `src/security/authorization.h`.

Classes: PeerAuthenticator, AuthorizationResolver.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-008, PRD-024, FR-003.

Acceptance criteria (not run):

- **RG-004-AC01** — Wrong principal/role/SAN/EKU and spoofed overrides reject without quota allocation. Evidence: AT-04.
- **RG-004-AC02** — Expired certificate on an existing connection is rejected; fenced new epoch is required for trust rotation. Evidence: AT-04, AT-14.
- **RG-004-AC03** — No private keys, full credentials or raw sensitive payloads appear in event/export fixtures. Evidence: AT-10, AT-13.

## RG-005

**Implement bounded events and incomplete-history accounting** · Release A · Planned

Dependencies: RG-001.

Reserve slots before commit. Published checksummed records and producer seals distinguish complete evidence from crash gaps. Run-wide cap is 1 GiB. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `src/events/event_recorder.h`, `src/events/history_exporter.h`.

Classes: EventRecorder, HistoryExporter.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-009, PRD-015, FR-009, FR-010.

Acceptance criteria (not run):

- **RG-005-AC01** — Reserved but unpublished slots, gaps, checksum loss and missing producer seals mark a run incomplete/UNKNOWN. Evidence: AT-10, AT-11.
- **RG-005-AC02** — Cap exhaustion stops correctness traffic; no event is silently dropped and no debit is refunded. Evidence: AT-11.
- **RG-005-AC03** — Owner-stage counters reconcile; metric labels are bounded and local synthetic export cleanup follows seven-day policy. Evidence: AT-10, AT-13.

## RG-006

**Implement supervisor lifecycle and positive fencing** · Release A · Planned

Dependencies: RG-002, RG-003, RG-004, RG-005.

Use ACTIVE/DRAINING/CLOSED; preserve exact process/container inventory. Supervisor failure never adopts a running old epoch. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `src/supervisor/epoch_gate.h`, `src/supervisor/manifest_store.h`, `src/supervisor/process_controller.h`, `src/supervisor/epoch_supervisor.h`, `src/supervisor/docker_process_controller.h`.

Classes: EpochGate, ManifestStore, IProcessController, EpochSupervisor, DockerProcessController.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-007, PRD-024, PRD-025, FR-001, FR-007, FR-008, FR-022.

Acceptance criteria (not run):

- **RG-006-AC01** — Isolated confirmed-credit process blocks fresh epoch activation until positive exact-identity exit evidence exists. Evidence: AT-09, AT-28.
- **RG-006-AC02** — Partial manifest write, lost inventory, PID reuse and supervisor crash cannot silently reset state. Evidence: AT-08, AT-09.
- **RG-006-AC03** — Host reboot and trust rotation follow fenced new-epoch procedure; all lifecycle fixtures distinguish DRAINING from CLOSED. Evidence: AT-14, AT-28.

## RG-007

**Implement independently validated witness transactions** · Release A · Planned

Dependencies: RG-002, RG-003, RG-005, RG-006.

Independent expected-state recomputation, exact transaction IDs and pre-reserved bounded journal slots. Flush before ack; lost acknowledgment repeats exact transaction only. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `src/authority/witness_port.h`, `src/supervisor/witness_state.h`, `src/supervisor/journal_writer.h`, `src/authority/local_witness_client.h`, `src/supervisor/witness_server.h`.

Classes: IStateWitness, WitnessStateMachine, JournalWriter, LocalStateWitnessClient, WitnessServer.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-007, PRD-015, PRD-024, FR-008, FR-010.

Acceptance criteria (not run):

- **RG-007-AC01** — Single-record deletion/rollback and invalid candidate transitions are rejected by an independently held witness image. Evidence: AT-09.
- **RG-007-AC02** — Duplicate transaction/ack loss cannot append a second debit; successor is blocked until exact acknowledgment. Evidence: AT-09, AT-15.
- **RG-007-AC03** — Disk full, fsync failure, witness death and 2 GiB cap produce DRAINING and uncertainty without rollback-and-resume. Evidence: AT-09, AT-11.

## RG-011

**Build the independent oracle (A acceptance prerequisite; replay CLI in B)** · Release B deliverable · Planned

Dependencies: RG-002, RG-005.

Before RG-008 strict acceptance, implement the minimal independent serial oracle and strict golden fixtures needed for AT-01–03/21. This test-support subset is a Release A prerequisite and is not the user-facing replay deliverable. Complete deterministic offered-trace parsing, policy comparison, first-divergence reporting, and replay CLI in Release B. Full traces include order, initial state and immutable policy hashes. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `tools/replay/reference_model.h`, `tools/replay/main.cpp`.

Classes: ReplayModel.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-006, FR-011, FR-012.

Acceptance criteria (not run):

- **RG-011-AC01** — Before RG-008 acceptance, strict golden fixtures cover equal-time order, weighted costs, partial refill and admission boundaries; Release B replay fixtures additionally cover first divergence and changed decisions. Evidence: AT-01–03/12.
- **RG-011-AC02** — Missing/invalid rows fail the whole comparison; identical input yields identical complete outputs and hashes. Evidence: AT-12.
- **RG-011-AC03** — The oracle does not import production BucketMath or AuthorityEngine logic. Evidence: AT-20, AT-21.

## RG-008

**Implement strict authority and admission service** · Release A · Planned

Dependencies: RG-001, RG-003, RG-004, RG-005, RG-007, RG-011.

Per-tenant reservation spans witness work without mutex held over RPC/I/O. Commit under lock, respond after durable witness ack. Invalid/expired precommit calls never debit. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `src/authority/tenant_ledger.h`, `src/authority/tenant_reservation.h`, `src/authority/authority_engine.h`, `src/authority/authority_service.h`, `src/admission/admission_service.h`, `src/admission/grpc_authority_client.h`.

Classes: TenantLedger, TenantReservation, AuthorityEngine, AuthorityService, AdmissionService, GrpcAuthorityClient.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-001, PRD-002, PRD-003, PRD-005, FR-002, FR-005, FR-006.

Acceptance criteria (not run):

- **RG-008-AC01** — One and three replicas match independent serial/concurrent model and preserve quota bounds across at least one million attempts. Evidence: AT-01, AT-02, AT-03.
- **RG-008-AC02** — Deadline/lost-response races preserve Possible commitment, no refunds and explicit outcomes. Evidence: AT-06, AT-07.
- **RG-008-AC03** — Mutation fixtures detect double-spend and reject-all; malformed/missing state fails closed. Evidence: AT-09, AT-21.

## RG-009

**Implement trusted adapter forwarding gate** · Release A · Planned

Dependencies: RG-004, RG-006, RG-008.

One Pending→ForwardStarted CAS; timely ALLOW and locally ACTIVE epoch required. No automatic backend retries or pending replay after adapter crash. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `adapter/forward_attempt.h`, `adapter/sample_adapter.h`.

Classes: ForwardAttempt, SampleAdapter.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-004, PRD-005, FR-004, FR-006.

Acceptance criteria (not run):

- **RG-009-AC01** — Late ALLOW, LIMITED and raw transport errors never forward. Evidence: AT-06, AT-07.
- **RG-009-AC02** — Duplicate callback and shutdown races produce at most one backend invocation per attempt. Evidence: AT-07.
- **RG-009-AC03** — Backend failure never refunds quota; committed/forwarded/completed events remain distinct. Evidence: AT-07, AT-10.

## RG-010

**Implement fixed-Q grants and replica credit state** · Release C · Planned

Dependencies: RG-006, RG-007, RG-008, RG-009, RG-011.

At most one confirmed batch/in-flight grant. GRANTED allocates; only local spend yields ALLOW. Coordinator identity/fingerprint persists until known result. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `src/credits/tenant_credits.h`, `src/credits/credit_manager.h`, `src/admission/authority_client.h`.

Classes: ReplicaTenantCredits, CreditManager, IAuthorityClient.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-016, PRD-017, PRD-018, PRD-019, FR-014, FR-015, FR-016, FR-017, FR-018.

Acceptance criteria (not run):

- **RG-010-AC01** — Duplicate LIMITED after refill returns the old result; stale/skipped/changed fingerprints reject; unknown result blocks next sequence. Evidence: AT-15.
- **RG-010-AC02** — Partial grant c-1/c/Q boundaries, remainder retirement, one-time activation and expired initiating caller match the contract. Evidence: AT-15, AT-16.
- **RG-010-AC03** — Crash/partition/sequence exhaustion never refunds or reuses slots; conservation and per-epoch B+rΔt+NQ hold in complete histories. Evidence: AT-17, AT-18, AT-28.

## RG-012

**Implement frozen workloads and comparative reports** · Release B · Planned

Dependencies: RG-005, RG-009, RG-011.

Deterministic PRD-026 routing and separate skew trace; open-loop scheduling, no retries, five 60-second runs after 30-second warmup. Credit-mode gate requires RG-010. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `tools/loadgen/trace_generator.h`, `tools/loadgen/runner.h`, `tools/report/main.cpp`.

Classes: TraceGenerator, BenchmarkRunner.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-010, PRD-011, PRD-012, PRD-020, PRD-022, PRD-026, FR-013, FR-019, FR-023, NFR-002, NFR-003, NFR-004, NFR-005, NFR-006, NFR-007, NFR-009.

Acceptance criteria (not run):

- **RG-012-AC01** — For N>1, uniform and block-skew routing schedules differ; each has its own named manifest/hash. Exact N=1/3/8 counts/cost mix and warmup indexing pass schedule checks. Evidence: AT-25, AT-29.
- **RG-012-AC02** — Each run applies ≥99.5% delivery, nearest-rank p99≤5 ms at 5,000/s over all delivered attempts (include errors; caller-cancellation time is a failure sample; no-response timeouts use the caller-deadline duration), ≥99% timely ALLOW/LIMITED and noisy-tenant ≥99% ALLOW without excluding failures. Evidence: AT-22, AT-23, AT-27.
- **RG-012-AC03** — Credit comparison preserves ≥95% admitted cost with ≥50% fewer authority operations; retries/witness overhead are disclosed and two clean reproductions recalculate gates. Evidence: AT-13, AT-19, AT-24.

## RG-013

**Implement bounded formal model and history checker** · Release C · Planned

Dependencies: RG-005, RG-010, RG-011.

Independent bounded model and implementation histories; efficient prefix-min interval scan cross-checked against exhaustive small histories. Missing evidence never PASS. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `model/runner`, `model/RateGuard.tla`, `tools/history_checker/checker.h`.

Classes: HistoryChecker, ModelHarness.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-018, PRD-021, PRD-023, FR-017, FR-020, FR-021.

Acceptance criteria (not run):

- **RG-013-AC01** — Complete histories satisfy legal tenant order, grant conservation and integer-time interval bounds; small exhaustive and streaming checkers agree. Evidence: AT-17, AT-26.
- **RG-013-AC02** — Double-spend, duplicate grant, reject-all, bound-break and stale-epoch mutants emit reproducible counterexamples. Evidence: AT-21, AT-26.
- **RG-013-AC03** — Archive bounds/tool versions/state counts; resource exhaustion or incomplete provenance returns UNKNOWN. Evidence: AT-20, AT-26.

## RG-014

**Assemble release evidence and reproducible handoff** · Release C · Planned

Dependencies: RG-010, RG-012, RG-013.

Keep release A/B/C applicability explicit. Every claim points to the exact source/implementation/test revision and observed result; unresolved misses keep the applicable release incomplete. Use LLD sections 16 and 17 for exact sequencing and class ownership; evidence must be independent of production decision logic.

Proposed files: `docs/releases/manifest.json`, `docs/releases/requirements-evidence.json`, `scripts/reproduce.sh`.

Classes: release artifacts and runner integration.

Sources: [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md#17-class-design-and-construction-contracts). Requirements: PRD-010, PRD-011, PRD-012, PRD-021, PRD-023, FR-013, FR-020, FR-021, NFR-001, NFR-006.

Acceptance criteria (not run):

- **RG-014-AC01** — At least one million attempts per mode with zero observed model violations and seeded-defect detection have complete evidence. Evidence: AT-02, AT-17, AT-21, AT-26.
- **RG-014-AC02** — Two clean setup-and-run reproductions regenerate machine-readable results under pinned inputs. Evidence: AT-13.
- **RG-014-AC03** — Requirement-to-contract-to-design-to-check-to-observed-result links are complete; future implementation is never labeled delivered. Evidence: AT-20.


## Readiness clarification — 2026-11-12

The full replay command/report remains a Release B deliverable. Its independent strict decision oracle and golden fixtures are required earlier as test support for Release A; this does not move replay product scope into A. The performance p99 population and target-build lock are defined in PRD 8 / SRD 5 / LLD 5. No story is implemented or accepted by this clarification.
