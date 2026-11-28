# RG-006 local lifecycle gate

This first RG-006 component translates PRD-007/024/025 and SRD FR-008/022 into an internal, bounded lifecycle state machine. Its source design inputs are LLD 5 §8, §12, A-03 and LLD-08.

## Required transitions

A newly constructed gate does not serve traffic before validated startup. An active epoch may enter DRAINING on authority, integrity, supervision or evidence failure. Observers of DRAINING stop new commits and forwarding. Isolated participants may still act under their old ACTIVE view; their actions remain in the old epoch.

CLOSED requires exit confirmation for every identity in the fixed old inventory. A stop request, timeout, disconnected channel, unknown process or reused PID cannot substitute for exit evidence. Identity comparisons must include the recorded process/container identity and boot/start identity. All registered participant roles remain in the inventory through closure.

A new epoch requires completed fencing plus fresh epoch and authority identity. Loss of the supervisor or its trusted inventory never authorizes adopting an existing active epoch. No automatic same-epoch process restart is supported.

## Component boundary

The local gate owns lifecycle state and validates exact-identity observations from an internal process-controller boundary. Production observation must eventually bind Docker inspection and OS evidence to the persisted inventory. Deterministic fake-controller tests verify the gate's decisions. They cannot establish actual process exit, durable inventory, exclusive supervisor ownership or deployment fencing.

The implementation must keep finite state, serialize lifecycle transitions, reject conflicting or stale evidence, and avoid external calls while holding state locks. A bounded configured inventory cannot silently grow after startup. Runtime limits and any narrower fixture constraints must be explicit implementation choices.

The manifest store, real process controller, launch/stop ordering, trust registry integration and recovery procedure need separate implementation and acceptance evidence. Full RG-006 and Release A acceptance remain open.
