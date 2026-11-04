# Principal contract closure review — 2026-11-04

**Input:** main PRD 6 / SRD 3 / HLD 2 / LLD 3.  
**Output:** proposed PRD 7 / SRD 4 / HLD 3 / LLD 4 on docs/spec-contract-closure-v1.  
**Review scope:** design semantics, concurrency, failure, arithmetic, interfaces and traceability. This report does not certify generated code or product safety.

| Finding | Severity | Disposition and evidence requirement |
| --- | --- | --- |
| PC-01 FR-021 row corrupted by misplaced AT-27 text | High | Repaired FR-021→AT-26; AT-27 is a standalone evidence row. Markdown table widths checked. |
| PC-02 uniform routing contradicted batched D8 routing | High | PRD-026 / FR-023 / AT-29 define exact rotated per-attempt formula; old trace remains labeled sensitivity. |
| PC-03 authority termination conflated with remote process cessation | Critical | PRD-025 / FR-022 / AT-28 distinguish ACTIVE, DRAINING and positively fenced CLOSED. |
| PC-04 witness merely recording authority-provided state could accept invalid transitions | Critical | LLD §16.1 independently recomputes each transition and enforces expected version, exact fingerprint and durable acknowledgment. |
| PC-05 cancellation/failed persistence could allow rollback and successor admission | Critical | Precommit cancellation releases without mutation; postcommit failure retains uncertainty and enters DRAINING; no successor until acknowledgment. |
| PC-06 same transaction retries and canceled coordinator behavior unspecified | High | Exact witness/grant fingerprint and sequence, one active resolver, expired coordinator never receives forwarding permission, grants activate once. |
| PC-07 grant cost had no operation binding | High | AcquireCredit includes operation ID; authority derives cost and checks optional transmitted cost matches immutable policy. |
| PC-08 enum/types/canonical encoding were incomplete | High | LLD §16.4 fixes widths, enum numbers, identifier lengths, typed canonical bytes, status handling and decoded payload limits. |
| PC-09 million-attempt interval validation described quadratic enumeration | High | LLD §16.5 defines checked prefix-min scan after sorting and preserves separate sequential-model checking. |
| PC-10 incomplete local histories could support false exact safety claims | Critical | Explicit Reserved/Published/Incomplete markers, gaps/unfinished producers cause UNKNOWN; concrete violations still fail. |
| PC-11 workload boundaries and denominators underdefined | High | LLD §16.6 fixes continuous warmup index, scheduled measurement membership, settlement wait, nearest-rank percentile and each ratio. |
| PC-13 class ownership and per-process construction underspecified | High | LLD §17 names classes, dependencies, lifecycle, concrete adapters and process composition; includes separate grant outcome and witness queue reservation contracts. |
| PC-14 implementation handoff lacked story links and explicit status | Medium | STORIES.md and context-blocks.json contain 14 linked planned stories, 42 criteria, proposed files, dependencies and source revisions. |
| PC-12 source/revision/traceability drift | Medium | Source revisions and FR-022/023/AT-28/29 mappings updated across the document set. |

## Checks actually performed

- Source content fetched from main before editing; observed revisions matched the input above.
- Markdown table column consistency and code-fence balance checked for all four edited documents.
- Deterministic performance schedule enumerated for N=1/3/8 over 300,000 measured attempts: counts are exactly 300,000; 100,000 per slot; and 37,500 per slot respectively. Each has exactly 30,000 cost-5 attempts.
- With fixed random seed 44, the proposed integer-time prefix interval scan agreed with independent exhaustive half-open interval enumeration on 1,000 small generated histories. This checks the stated formula on those fixtures only; it is not an implementation benchmark or proof for every history.
- JSON parsing, story IDs, acceptance IDs, dependency DAG, class references and generated story anchors checked before merge; remote readback is verified against the authored content.

## Disposition

Every semantic finding recorded in this review has a selected contract in this revision. The source-level behavior changes are limited to explicit routing/lifecycle clarification and trusted operation binding, with existing numerical thresholds preserved. Environment/tool versions must be locked before build; executable conformance, fault injection, model-checking and performance evidence must still pass before releases are complete. No review can guarantee that generated code will contain no bugs, and no results in this report represent implemented product behavior.
