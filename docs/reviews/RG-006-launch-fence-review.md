# RG-006 launch-fencing review

**Status:** Proposed follow-up design review. This is not a selected recovery contract or implemented fencing capability. Binding PRD/SRD rules and existing fail-closed behavior remain unchanged.

**Sources:** PRD 8, SRD 5 (D4/D5, FR-008/FR-022, AT-09/AT-28), HLD 5 A-03, LLD 11+, and an unpublished launch-fence draft. The review itself was read-only; no VM restart, filesystem recovery or implementation was performed. The Master publishes this note for follow-up.

## Proposed direction

An external cloud/hypervisor attestation service is **not inherently required for the stated v1 single trusted Docker Linux VM**, provided the operating contract explicitly excludes VM snapshots/restores, cloning, live migration, and competing Docker controllers. Treat a verified transition from the recorded old Linux boot ID to the current boot ID as evidence that the old guest kernel instance ended. Linux documents `/proc/sys/kernel/random/boot_id` as generated once and stable for that boot ([kernel documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)). This is a local boot-generation observation, not proof of VM identity, snapshot freshness, or clone uniqueness. Those remain trusted deployment assumptions.

This fits the stated failure model: the HLD already says coordinated rollback of the whole host and both state images is outside the detectable single-record model. A checksum, boot ID, or stable local machine identifier must not be presented as an anti-rollback attestation. If snapshot/clone rollback or concurrent copies of one VM are in scope, local state cannot distinguish them; then an independently authenticated VM-generation/fence source is a real blocker.

Docker's restart policy `no` does not automatically restart a container when it exits or the daemon restarts; other policies can ([Docker restart-policy documentation](https://docs.docker.com/engine/containers/start-containers-automatically/)). Require policy `no` on each created container and make the supervisor the sole actor allowed to create/start containers under the RateGuard domain. But that documentation alone is not a no-pending-Start proof. In pinned Moby 28.0.4, daemon startup restores persisted container records and tries to restore existing containerd tasks; it preserves a task it finds alive when live restore is enabled, and schedules a restart when daemon autorestart and container restart policy allow it ([pinned Moby 28.0.4 startup restore](https://raw.githubusercontent.com/moby/moby/v28.0.4/daemon/daemon.go), [restart path](https://raw.githubusercontent.com/moby/moby/v28.0.4/daemon/restart.go)). Therefore, cold-boot recovery requires a pinned and qualified daemon profile, including live-restore/autorestart settings, and a disposable-VM test. This review does not establish behavior for Docker Desktop or an arbitrary Engine build. The HLD's current wording “unreadable inventory blocks reset until a controlled complete VM shutdown provides positive fencing evidence” should be clarified: reboot evidence is conditional on the trusted-VM/no-rollback assumptions; it does not repair unreadable state or supply an inventory.

The VM identity must be an explicit trusted profile input bound to the configured runtime root/domain and expected Linux observer scope. A locally read machine ID, boot ID, Docker daemon ping, or double inventory query is not an independently authenticated VM identity or a no-pending-request barrier. If deployment cannot supply a stable VM profile and exclude snapshot/clone rollback, keep recovery `UNKNOWN`.

## Lifecycle cases

| Case | Safe rule |
| --- | --- |
| Initial epoch | Persist `CreateIntent` before one Create call. Do not Start until the definitive full container ID and labels are durably bound and the stopped container is checked. A possibly dispatched Create with a lost response is sticky unknown on this boot. |
| Healthy owner close | Close the Start gate, reject new leases, and join all in-flight Start calls. Only definitive, durably recorded outcomes permit normal exact-ID stop/exit verification. If an in-flight call times out or may have been sent, same-boot recovery remains blocked; an earlier stopped snapshot cannot order itself after a delayed Start. |
| Supervisor loss / unknown Start | Same boot: block. After a qualified full guest reboot and changed boot ID, a typed kernel-generation fence may attest that the exact recorded old kernel generation ended; it is not a reset token. Reopen in recovery-only mode, enumerate the entire RateGuard domain, require complete results and exact labels, check restart policy, stop/confirm any discovered live container, then record closure. Any missing/corrupt intent, incomplete inventory, boot/VM profile mismatch, unsupported runtime, or unqualified reboot remains blocked. |

PRD-025 / FR-022 require no overlap and block unknown process state; they do not require instantaneous remote stop. A reboot must never clear an unknown result by a caller boolean. The persisted old boot ID plus validated current boot ID and trusted deployment contract form the evidence path. Same-boot daemon/API observations cannot clear a possibly pending Start. Keep the native process probe's `HostBootMismatch` behavior; do not weaken it. A future recovery composition could accept a private `VerifiedKernelGenerationFence` bound to the trusted VM-profile ID, domain, exact old epoch/boot ID, current boot ID, and source manifest generation/digest. A verifier must check exact persisted-record binding, current Linux clock/provenance, same configured VM profile, and different old/current boot IDs, rejecting missing or mismatched values. That typed proof could compose with exact runtime inspection (container ID/labels, stopped, PID 0, restart disabled) when the prior PID is unobservable in the new kernel. It is a proposed proof boundary, not current evidence; runtime inspection still cannot prove a different future manager will not start that container.

## Unknown Create and inventory semantics

Persist a unique canonical `create_name` in each `CreateIntent` before Create; use that exact name only as a recovery lookup key. Start still requires a definitive full container ID durably bound to the intent. After an unknown Create, look up each unresolved name and also run bounded Engine listing with `all=true` and the stable domain label filter. Validate every full ID and all eight immutable labels; never use prefixes or discard malformed rows. A matching name with missing/wrong labels is a conflict and blocks recovery. Domain-label listing alone can miss an unlabelled orphan; exact intent names and the label sweep are both required. Apply strict response-byte and row-count caps. Truncation, cap hit, malformed/duplicate/conflicting identity, transport failure, or changing listing returns `Incomplete`, never “no orphan found.” Preserve known exact IDs for stop attempts. The Engine API documents listing all containers and label filters ([container-list API](https://docs.docker.com/reference/api/engine/version/v1.47/#tag/Container/operation/ContainerList)). Double listing is a diagnostic only, not a barrier against pending Create/Start or another controller.

This is not an atomic global snapshot. Require exclusive control of the RateGuard Docker domain during recovery; no operator, second supervisor, or external orchestrator may create/start matching containers while the sweep runs. If that assumption cannot be enforced, add a runtime-level exclusive-control mechanism before treating the list as complete. An unlabelled or malformed possible orphan is unresolved, not adoptable. In a healthy same-boot path, list-and-inspect cannot establish that an already-sent request is no longer queued; only completed/joined Start calls or a separately qualified kernel-generation fence closes that uncertainty.

## Contract change and remaining gates

Replace the draft's blanket “external attestation required to clear unknown Start” with: **a trusted full-VM reboot can clear old-kernel/daemon uncertainty only when the stored old boot identity and validated current identity differ, the same qualified VM/domain is in use, snapshot/clone/rollback is excluded, and complete domain inventory plus stop/exit verification succeeds.** Otherwise remain blocked. An external fence is required only if the deployment wants recovery despite failing one of those trust conditions.

The first safe implementation slice can support initial Create/Start with exact durable intent, a gate lease/join, definitive result persistence, and sticky unknown outcomes. It may implement healthy shutdown and known exact-ID stop while exposing no same-boot reset API. It does not complete reboot recovery. Remaining gates:

1. Bounded inventory plus exact Create-name lookup, preserving malformed/missing-label orphans as unresolved.
2. A typed kernel-generation fence bound to VM profile, old manifest generation/digest, old/current boot IDs, epoch, and domain; no boolean or caller-minted proof.
3. Pinned Moby/Docker configuration qualification in an owned disposable Linux VM, including daemon autorestart/live-restore behavior. GitHub runner observations and developer-laptop reboot do not qualify this.
4. Recovery composition and fault tests. AT-09 / FR-008 and AT-28 / FR-022 remain open until delayed Start, lost result, supervisor death, stale runtime state, and old-credit process cases show no overlap and correctly block unknown outcomes.

Bounded inventory can be implemented first as a diagnostic-only component. It must return records/issues, never `safe_to_reset` or a successor capability. The current inspect/stop API cannot satisfy the lifecycle gates by itself.

## Active effort estimate

- Freeze this trust-boundary wording and state transitions: **20–35 min**.
- Bounded inventory/intent-name diagnostic reader and incomplete-result tests: **90–150 min**.
- Durable initial Create/Start result journal and gate/join tests (sticky unknown only): **120–180 min**.
- Typed generation-fence verifier and recovery composition: **90–150 min**, excluding VM/Docker qualification.
- Owned disposable-VM/Moby-profile qualification: **60–120 min** after an environment is provisioned.
- If snapshot/clone rollback must be supported: provider/fence source selection **60–120 min** before estimating its integration and qualification.

These are active implementation estimates, not acceptance or safety claims.
