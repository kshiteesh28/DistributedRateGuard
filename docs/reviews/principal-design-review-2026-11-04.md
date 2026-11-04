# Principal design review — 2026-11-04

**Scope:** PRD 6 and SRD 3 as contracts; HLD 1→2 and LLD 2→3.  
**Status:** Design fixes selected; implementation and verification evidence pending.  
**Reviewer role:** Senior principal engineer. No independent agent review is claimed for this pass.

| ID / severity | Gap | Fix / evidence required |
| --- | --- | --- |
| PE-01 / critical | Manifest alone cannot detect bucket/grant record rollback | A-01 independent witness validates pre-state and journaled post-state; no successful response before acknowledgment. Inject deletion/rollback, lost ack, journal corruption and witness death. |
| PE-02 / critical | Introducing durability can accidentally move commit timestamps or allow concurrent successors | Logical tenant reservation spans validation/flush; clock sampled once in serialized transition; terminate on ambiguous failure. Validate commit-order and clock histories. |
| PE-03 / high | Certificate validity on reused channels unspecified | A-02 checks peer/role/expiry on every RPC and fences trust rotation. Negative cert/EKU/SAN/expiry fixtures required. |
| PE-04 / critical | Supervisor failure could abandon old isolated spenders | A-03 exact inventory and process-exit evidence, no same-epoch adoption, controlled VM fencing when inventory is untrusted. |
| PE-05 / high | Volatile event publication could be misrepresented as exact crash accounting | A-04 reserves bounded slots and uses complete/incomplete markers; ranges/UNKNOWN when evidence missing; no fabricated refunds. |
| PE-06 / high | Backend retry/forwarding could imply exactly-once execution | Per-attempt forwarding CAS; disable application hedging/retries; no replay after adapter crash. Backend outcome may remain uncertain. |
| PE-07 / high | AcquireCredit success could be confused with admission ALLOW | Separate GRANTED allocation outcome; only local atomic spend produces CheckAdmission ALLOW. |
| PE-08 / medium | Encoding/status behavior left to implementer | A-05 numbered fields, unspecified enum rejection, typed canonical policy encoding and integer artifact representation. Golden compatibility vectors required. |
| PE-09 / high | Routing formula conflicts with short-window uniform interpretation | Retain D8 trace and report skew. Source clarification still required before disputed gate certification; do not silently alter PRD/SRD. |
| PE-10 / high | Authority-terminal wording may imply instant stop of isolated credit holders | Preserve old-epoch spend accounting and positive fencing. Source closure/notification semantics still require clarification. |
| PE-11 / high | Integrity path performance cost missing | Report witness exchanges, journal writes/flushes, bytes, queue wait and added memory alongside authority operations. Never bypass integrity to meet gates. |

Remaining source decisions: PE-09 and PE-10. Other fixes are selected design mechanisms with evidence gates. Proposed 2 GiB authority-witness journal cap is a new finite implementation cap, not a relaxed product gate. PRD/SRD are unchanged. No tests or benchmark results are claimed.

Links: [HLD revision 2](../HLD.md), [LLD revision 3](../LLD.md).
