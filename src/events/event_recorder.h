#pragma once

// RG-005 Release A in-memory correctness-event recorder.
// This header is self-contained C++20 and deliberately records no arbitrary payload.

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace rateguard::events {

using AttemptId = std::array<std::uint8_t, 16>;
using EpochId = std::array<std::uint8_t, 16>;
using PolicyDigest = std::array<std::uint8_t, 32>;

inline constexpr std::uint32_t kEventSchemaVersion = 1;
inline constexpr std::uint64_t kMaxRunBudgetBytes = 1ULL << 30;
inline constexpr std::uint64_t kFnv1a64OffsetBasis = 14695981039346656037ULL;
inline constexpr std::uint64_t kFnv1a64Prime = 1099511628211ULL;
inline constexpr std::uint64_t kRunMagicBytes = 8;

// Canonical fixed-width big-endian encoded extents. Header = magic[8], version[4],
// epoch[16], policy digest[32], producer count[4], planned bytes[8], budget[8].
// Producer envelope = owner[1], index[4], capacity[8]. Slot = status[1], sequence[8],
// stage[1], outcome[1], attempt[16], timestamp[8], cost[8], checksum[8]. Seal =
// sealed[1], incomplete[1], reserved[8], published[8], checksum[8]. Terminal =
// complete[1], encoded byte count[8], run checksum[8]. Unused slots are encoded too.
inline constexpr std::uint64_t kRunHeaderEncodedBytes = 80;
inline constexpr std::uint64_t kProducerEnvelopeEncodedBytes = 13;
inline constexpr std::uint64_t kEventSlotEncodedBytes = 51;
inline constexpr std::uint64_t kProducerSealEncodedBytes = 26;
inline constexpr std::uint64_t kRunTerminalEncodedBytes = 17;

// Enum values are part of the version-1 history encoding.
enum class ProducerOwner : std::uint8_t {
  WorkloadGenerator = 1,
  Authority = 2,
  Replica = 3,
  Adapter = 4,
  Backend = 5,
};

enum class Stage : std::uint8_t {
  Offered = 1,          // WorkloadGenerator
  StrictDecision = 2,   // Authority
  Responded = 3,        // Replica
  Received = 4,         // Adapter
  Forwarded = 5,        // Adapter
  Completed = 6,        // Backend
};

enum class Outcome : std::uint8_t {
  None = 0,
  Allow = 1,
  Limited = 2,
  Invalid = 3,
  Unauthenticated = 4,
  Unavailable = 5,
  Overloaded = 6,
  Error = 7,
};

enum class SlotStatus : std::uint8_t {
  Unused = 0,
  Reserved = 1,
  Published = 2,
  Incomplete = 3,
};

enum class RecorderError : std::uint8_t {
  None = 0,
  InvalidPlan,
  DuplicateProducer,
  ProducerNotFound,
  ProducerAlreadyAttached,
  ProducerSealed,
  RunStopped,
  ProducerPartitionExhausted,
  ForeignReservation,
  ReservationAlreadyConsumed,
  InvalidEvent,
  AllocationFailure,
};

template <class T>
using Result = std::variant<T, RecorderError>;

struct EventV1 final {
  Stage stage{Stage::Offered};
  Outcome outcome{Outcome::None};
  AttemptId attempt_id{};
  // Monotonic nanoseconds supplied by the owning stage at its event point.
  // The recorder does not impose cross-producer timestamp ordering.
  std::uint64_t timestamp_ns{0};
  std::uint64_t cost_units{0};
};

struct ProducerSpec final {
  ProducerOwner owner{ProducerOwner::WorkloadGenerator};
  std::uint32_t producer_index{0};
  std::uint64_t event_capacity{0};
};

struct RunPlan final {
  EpochId epoch_id{};
  PolicyDigest policy_digest{};
  std::vector<ProducerSpec> producers;
  // Smaller test budgets are valid. Exact-boundary plans are accepted.
  std::uint64_t budget_bytes{kMaxRunBudgetBytes};
};

struct EventSlotV1 final {
  SlotStatus status{SlotStatus::Unused};
  std::uint64_t producer_sequence{0};
  EventV1 event{};
  std::uint64_t checksum64{0};
};

struct ProducerSnapshotV1 final {
  ProducerOwner owner{ProducerOwner::WorkloadGenerator};
  std::uint32_t producer_index{0};
  std::uint64_t capacity{0};
  // Count of allocated sequences; valid sequence numbers are [1,reserved_count].
  std::uint64_t reserved_count{0};
  std::uint64_t published_count{0};
  bool sealed{false};
  bool incomplete{false};
  std::vector<EventSlotV1> slots;
  std::uint64_t seal_checksum64{0};
};

struct EventSnapshotV1 final {
  std::uint32_t schema_version{kEventSchemaVersion};
  EpochId epoch_id{};
  PolicyDigest policy_digest{};
  // Exact fixed-width encoded extent, including every unused allowance slot.
  std::uint64_t planned_bytes{0};
  std::uint64_t budget_bytes{0};
  bool complete{false};
  std::vector<ProducerSnapshotV1> producers;
  std::uint64_t checksum64{0};
};

namespace detail {

inline void FnvByte(std::uint64_t& hash, std::uint8_t byte) noexcept {
  hash ^= byte;
  hash *= kFnv1a64Prime;
}
inline void FnvU32(std::uint64_t& hash, std::uint32_t value) noexcept {
  for (int shift = 24; shift >= 0; shift -= 8)
    FnvByte(hash, static_cast<std::uint8_t>(value >> shift));
}
inline void FnvU64(std::uint64_t& hash, std::uint64_t value) noexcept {
  for (int shift = 56; shift >= 0; shift -= 8)
    FnvByte(hash, static_cast<std::uint8_t>(value >> shift));
}
template <std::size_t N>
inline void FnvArray(std::uint64_t& hash, const std::array<std::uint8_t, N>& value) noexcept {
  for (const auto byte : value) FnvByte(hash, byte);
}
inline void FnvTag(std::uint64_t& hash, const char* tag, std::size_t size) noexcept {
  for (std::size_t i = 0; i < size; ++i)
    FnvByte(hash, static_cast<std::uint8_t>(tag[i]));
}

inline std::uint64_t EventChecksum(const EventV1& event) noexcept {
  auto hash = kFnv1a64OffsetBasis;
  FnvTag(hash, "RGEV1", 5);
  FnvByte(hash, static_cast<std::uint8_t>(event.stage));
  FnvByte(hash, static_cast<std::uint8_t>(event.outcome));
  FnvArray(hash, event.attempt_id);
  FnvU64(hash, event.timestamp_ns);
  FnvU64(hash, event.cost_units);
  return hash;
}

inline std::uint64_t ProducerSealChecksum(ProducerOwner owner, std::uint32_t index,
    std::uint64_t capacity, std::uint64_t reserved, std::uint64_t published,
    bool sealed, bool incomplete, std::span<const EventSlotV1> slots) noexcept {
  auto hash = kFnv1a64OffsetBasis;
  FnvTag(hash, "RGPS1", 5);
  FnvByte(hash, static_cast<std::uint8_t>(owner));
  FnvU32(hash, index);
  FnvU64(hash, capacity);
  FnvU64(hash, reserved);
  FnvU64(hash, published);
  FnvByte(hash, sealed ? 1 : 0);
  FnvByte(hash, incomplete ? 1 : 0);
  for (const auto& slot : slots) {
    FnvByte(hash, static_cast<std::uint8_t>(slot.status));
    FnvU64(hash, slot.producer_sequence);
    FnvU64(hash, slot.checksum64);
  }
  return hash;
}

inline std::uint64_t SnapshotChecksum(const EventSnapshotV1& snapshot) noexcept {
  auto hash = kFnv1a64OffsetBasis;
  FnvTag(hash, "RGRN1", 5);
  FnvU32(hash, snapshot.schema_version);
  FnvArray(hash, snapshot.epoch_id);
  FnvArray(hash, snapshot.policy_digest);
  FnvU32(hash, static_cast<std::uint32_t>(snapshot.producers.size()));
  FnvU64(hash, snapshot.planned_bytes);
  FnvU64(hash, snapshot.budget_bytes);
  for (const auto& producer : snapshot.producers) {
    FnvByte(hash, static_cast<std::uint8_t>(producer.owner));
    FnvU32(hash, producer.producer_index);
    FnvU64(hash, producer.capacity);
    FnvU64(hash, producer.seal_checksum64);
  }
  FnvByte(hash, snapshot.complete ? 1 : 0);
  return hash;
}

inline bool StageOwnedBy(ProducerOwner owner, Stage stage) noexcept {
  switch (stage) {
    case Stage::Offered: return owner == ProducerOwner::WorkloadGenerator;
    case Stage::StrictDecision: return owner == ProducerOwner::Authority;
    case Stage::Responded: return owner == ProducerOwner::Replica;
    case Stage::Received:
    case Stage::Forwarded: return owner == ProducerOwner::Adapter;
    case Stage::Completed: return owner == ProducerOwner::Backend;
  }
  return false;
}

inline bool ValidOutcome(Outcome outcome) noexcept {
  return static_cast<std::uint8_t>(outcome) <= static_cast<std::uint8_t>(Outcome::Error);
}

inline bool CheckedAdd(std::uint64_t& value, std::uint64_t addend) noexcept {
  if (addend > std::numeric_limits<std::uint64_t>::max() - value) return false;
  value += addend;
  return true;
}
inline bool CheckedMultiplyAdd(std::uint64_t& total, std::uint64_t count,
                               std::uint64_t extent) noexcept {
  if (count != 0 && extent > std::numeric_limits<std::uint64_t>::max() / count) return false;
  return CheckedAdd(total, count * extent);
}

struct ProducerState final {
  explicit ProducerState(const ProducerSpec& spec)
      : owner(spec.owner), producer_index(spec.producer_index), capacity(spec.event_capacity),
        slots(static_cast<std::size_t>(spec.event_capacity)) {}

  mutable std::mutex mutex;
  ProducerOwner owner;
  std::uint32_t producer_index;
  std::uint64_t capacity;
  std::uint64_t reserved_count{0};
  std::uint64_t published_count{0};
  bool attached{false};
  bool ever_attached{false};
  bool sealed{false};
  bool incomplete{false};
  std::vector<EventSlotV1> slots;
  std::uint64_t seal_checksum64{0};
};

struct RunState final {
  EpochId epoch_id{};
  PolicyDigest policy_digest{};
  std::uint64_t planned_bytes{0};
  std::uint64_t budget_bytes{0};
  std::atomic<bool> stopped{false};
  std::mutex attach_mutex;
  std::vector<std::shared_ptr<ProducerState>> producers;
};

inline bool IsKnownOwner(ProducerOwner owner) noexcept {
  return owner >= ProducerOwner::WorkloadGenerator && owner <= ProducerOwner::Backend;
}
inline bool ValidatePlan(const RunPlan& plan, std::uint64_t& planned_bytes) noexcept {
  if (plan.producers.empty() || plan.producers.size() > std::numeric_limits<std::uint32_t>::max() ||
      plan.budget_bytes > kMaxRunBudgetBytes || plan.budget_bytes <
          kRunHeaderEncodedBytes + kRunTerminalEncodedBytes) return false;
  planned_bytes = kRunHeaderEncodedBytes;
  if (!CheckedAdd(planned_bytes, kRunTerminalEncodedBytes)) return false;
  const auto producer_min = kProducerEnvelopeEncodedBytes + kProducerSealEncodedBytes +
                            kEventSlotEncodedBytes;
  if (plan.producers.size() > (plan.budget_bytes - planned_bytes) / producer_min) return false;
  for (std::size_t i = 0; i < plan.producers.size(); ++i) {
    const auto& spec = plan.producers[i];
    if (!IsKnownOwner(spec.owner) || spec.event_capacity == 0 ||
        spec.event_capacity > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
    if (i != 0 && plan.producers[i - 1].owner == spec.owner &&
        plan.producers[i - 1].producer_index == spec.producer_index) return false;
    if (!CheckedAdd(planned_bytes, kProducerEnvelopeEncodedBytes) ||
        !CheckedMultiplyAdd(planned_bytes, spec.event_capacity, kEventSlotEncodedBytes) ||
        !CheckedAdd(planned_bytes, kProducerSealEncodedBytes)) return false;
  }
  return planned_bytes <= plan.budget_bytes && planned_bytes <= kMaxRunBudgetBytes;
}

}  // namespace detail

class EventRecorder final {
 public:
  class ProducerHandle;

  class EventReservation final {
   public:
    EventReservation(const EventReservation&) = delete;
    EventReservation& operator=(const EventReservation&) = delete;
    EventReservation(EventReservation&& other) noexcept
        : run_(std::move(other.run_)), producer_(std::move(other.producer_)),
          sequence_(std::exchange(other.sequence_, 0)), consumed_(std::exchange(other.consumed_, true)) {}
    EventReservation& operator=(EventReservation&& other) noexcept {
      if (this == &other) return *this;
      Abandon();
      run_ = std::move(other.run_);
      producer_ = std::move(other.producer_);
      sequence_ = std::exchange(other.sequence_, 0);
      consumed_ = std::exchange(other.consumed_, true);
      return *this;
    }
    ~EventReservation() { Abandon(); }
    [[nodiscard]] std::uint64_t producer_sequence() const noexcept { return sequence_; }

   private:
    friend class ProducerHandle;
    EventReservation(std::shared_ptr<detail::RunState> run,
                     std::shared_ptr<detail::ProducerState> producer,
                     std::uint64_t sequence) noexcept
        : run_(std::move(run)), producer_(std::move(producer)), sequence_(sequence) {}
    void Abandon() noexcept {
      if (consumed_ || !producer_ || sequence_ == 0) return;
      std::lock_guard lock(producer_->mutex);
      if (producer_->sealed) { consumed_ = true; return; }
      auto& slot = producer_->slots[static_cast<std::size_t>(sequence_ - 1)];
      if (slot.status == SlotStatus::Reserved && slot.producer_sequence == sequence_) {
        slot.status = SlotStatus::Incomplete;
        producer_->incomplete = true;
        if (run_) run_->stopped.store(true, std::memory_order_release);
      }
      consumed_ = true;
    }
    std::shared_ptr<detail::RunState> run_;
    std::shared_ptr<detail::ProducerState> producer_;
    std::uint64_t sequence_{0};
    bool consumed_{false};
  };

  class ProducerHandle final {
   public:
    ProducerHandle(const ProducerHandle&) = delete;
    ProducerHandle& operator=(const ProducerHandle&) = delete;
    ProducerHandle(ProducerHandle&& other) noexcept
        : run_(std::move(other.run_)), producer_(std::move(other.producer_)),
          detached_(std::exchange(other.detached_, true)) {}
    ProducerHandle& operator=(ProducerHandle&& other) noexcept {
      if (this == &other) return *this;
      Detach();
      run_ = std::move(other.run_);
      producer_ = std::move(other.producer_);
      detached_ = std::exchange(other.detached_, true);
      return *this;
    }
    ~ProducerHandle() { Detach(); }

    [[nodiscard]] Result<EventReservation> Reserve() noexcept {
      if (!run_ || !producer_) return RecorderError::ProducerNotFound;
      std::lock_guard lock(producer_->mutex);
      if (producer_->sealed) return RecorderError::ProducerSealed;
      if (run_->stopped.load(std::memory_order_acquire)) return RecorderError::RunStopped;
      if (producer_->reserved_count >= producer_->capacity) {
        producer_->incomplete = true;
        run_->stopped.store(true, std::memory_order_release);
        return RecorderError::ProducerPartitionExhausted;
      }
      const auto sequence = ++producer_->reserved_count;
      auto& slot = producer_->slots[static_cast<std::size_t>(sequence - 1)];
      slot.status = SlotStatus::Reserved;
      slot.producer_sequence = sequence;
      return EventReservation(run_, producer_, sequence);
    }

    [[nodiscard]] RecorderError Publish(EventReservation&& reservation,
                                        const EventV1& event) noexcept {
      if (!run_ || !producer_ || reservation.run_.get() != run_.get() ||
          reservation.producer_.get() != producer_.get()) return RecorderError::ForeignReservation;
      if (reservation.consumed_ || reservation.sequence_ == 0)
        return RecorderError::ReservationAlreadyConsumed;
      std::lock_guard lock(producer_->mutex);
      if (reservation.sequence_ > producer_->reserved_count ||
          reservation.sequence_ > producer_->slots.size()) {
        reservation.consumed_ = true;
        return RecorderError::ForeignReservation;
      }
      auto& slot = producer_->slots[static_cast<std::size_t>(reservation.sequence_ - 1)];
      if (slot.status != SlotStatus::Reserved ||
          slot.producer_sequence != reservation.sequence_) {
        reservation.consumed_ = true;
        producer_->incomplete = true;
        run_->stopped.store(true, std::memory_order_release);
        return RecorderError::ReservationAlreadyConsumed;
      }
      if (producer_->sealed) {
        reservation.consumed_ = true;
        return RecorderError::ProducerSealed;
      }
      if (!detail::StageOwnedBy(producer_->owner, event.stage) ||
          !detail::ValidOutcome(event.outcome)) {
        slot.status = SlotStatus::Incomplete;
        producer_->incomplete = true;
        run_->stopped.store(true, std::memory_order_release);
        reservation.consumed_ = true;
        return RecorderError::InvalidEvent;
      }
      slot.event = event;
      slot.checksum64 = detail::EventChecksum(event);
      slot.status = SlotStatus::Published;
      ++producer_->published_count;
      reservation.consumed_ = true;
      return RecorderError::None;
    }

    [[nodiscard]] RecorderError Seal() noexcept { return SealImpl(false); }
    [[nodiscard]] RecorderError SealIncomplete() noexcept { return SealImpl(true); }
    [[nodiscard]] ProducerOwner owner() const noexcept {
      return producer_ ? producer_->owner : ProducerOwner::WorkloadGenerator;
    }
    [[nodiscard]] std::uint32_t producer_index() const noexcept {
      return producer_ ? producer_->producer_index : 0;
    }

   private:
    friend class EventRecorder;
    ProducerHandle(std::shared_ptr<detail::RunState> run,
                   std::shared_ptr<detail::ProducerState> producer) noexcept
        : run_(std::move(run)), producer_(std::move(producer)) {}
    RecorderError SealImpl(bool incomplete) noexcept {
      if (!run_ || !producer_) return RecorderError::ProducerNotFound;
      std::lock_guard lock(producer_->mutex);
      if (producer_->sealed) return RecorderError::ProducerSealed;
      if (incomplete || producer_->published_count != producer_->reserved_count) {
        producer_->incomplete = true;
        run_->stopped.store(true, std::memory_order_release);
      }
      producer_->sealed = true;
      producer_->seal_checksum64 = detail::ProducerSealChecksum(
          producer_->owner, producer_->producer_index, producer_->capacity,
          producer_->reserved_count, producer_->published_count, producer_->sealed,
          producer_->incomplete, producer_->slots);
      return RecorderError::None;
    }
    void Detach() noexcept {
      if (detached_ || !producer_) return;
      std::lock_guard lock(producer_->mutex);
      if (!producer_->sealed) {
        producer_->incomplete = true;
        if (run_) run_->stopped.store(true, std::memory_order_release);
      }
      producer_->attached = false;
      detached_ = true;
    }
    std::shared_ptr<detail::RunState> run_;
    std::shared_ptr<detail::ProducerState> producer_;
    bool detached_{false};
  };

  [[nodiscard]] static Result<EventRecorder> Create(RunPlan plan) noexcept {
    std::uint64_t planned_bytes = 0;
    std::sort(plan.producers.begin(), plan.producers.end(), [](const auto& a, const auto& b) {
      return a.owner < b.owner || (a.owner == b.owner && a.producer_index < b.producer_index);
    });
    if (!detail::ValidatePlan(plan, planned_bytes)) return RecorderError::InvalidPlan;
    try {
      auto run = std::make_shared<detail::RunState>();
      run->epoch_id = plan.epoch_id;
      run->policy_digest = plan.policy_digest;
      run->planned_bytes = planned_bytes;
      run->budget_bytes = plan.budget_bytes;
      run->producers.reserve(plan.producers.size());
      for (const auto& spec : plan.producers)
        run->producers.push_back(std::make_shared<detail::ProducerState>(spec));
      return EventRecorder(std::move(run));
    } catch (...) {
      return RecorderError::AllocationFailure;
    }
  }

  EventRecorder(const EventRecorder&) = delete;
  EventRecorder& operator=(const EventRecorder&) = delete;
  EventRecorder(EventRecorder&&) noexcept = default;
  EventRecorder& operator=(EventRecorder&&) noexcept = default;

  [[nodiscard]] Result<ProducerHandle> AttachProducer(ProducerOwner owner,
                                                      std::uint32_t index) noexcept {
    if (!run_) return RecorderError::RunStopped;
    std::lock_guard lock(run_->attach_mutex);
    if (run_->stopped.load(std::memory_order_acquire)) return RecorderError::RunStopped;
    for (const auto& producer : run_->producers) {
      if (producer->owner != owner || producer->producer_index != index) continue;
      std::lock_guard producer_lock(producer->mutex);
      if (producer->attached || producer->ever_attached) return RecorderError::ProducerAlreadyAttached;
      // Attachment is one-shot. A detached producer is never reusable.
      producer->attached = true;
      producer->ever_attached = true;
      return ProducerHandle(run_, producer);
    }
    return RecorderError::ProducerNotFound;
  }

  // Caller must quiesce all owners before export. An unsealed/missing producer,
  // reserved gap, checksum inconsistency or stopped run is exported incomplete.
  [[nodiscard]] Result<EventSnapshotV1> ExportSnapshotV1() const noexcept {
    if (!run_) return RecorderError::RunStopped;
    try {
      EventSnapshotV1 snapshot;
      snapshot.epoch_id = run_->epoch_id;
      snapshot.policy_digest = run_->policy_digest;
      snapshot.planned_bytes = run_->planned_bytes;
      snapshot.budget_bytes = run_->budget_bytes;
      snapshot.producers.reserve(run_->producers.size());
      bool complete = !run_->stopped.load(std::memory_order_acquire);
      for (const auto& producer : run_->producers) {
        std::lock_guard lock(producer->mutex);
        ProducerSnapshotV1 item;
        item.owner = producer->owner;
        item.producer_index = producer->producer_index;
        item.capacity = producer->capacity;
        item.reserved_count = producer->reserved_count;
        item.published_count = producer->published_count;
        item.sealed = producer->sealed;
        item.incomplete = producer->incomplete;
        item.slots = producer->slots;
        item.seal_checksum64 = producer->seal_checksum64;
        if (!item.sealed || item.incomplete || item.reserved_count != item.published_count ||
            item.seal_checksum64 != detail::ProducerSealChecksum(
                item.owner, item.producer_index, item.capacity, item.reserved_count,
                item.published_count, item.sealed, item.incomplete, item.slots)) complete = false;
        for (std::size_t i = 0; i < item.slots.size(); ++i) {
          const auto& slot = item.slots[i];
          if (i < item.reserved_count) {
            if (slot.status != SlotStatus::Published || slot.producer_sequence != i + 1 ||
                slot.checksum64 != detail::EventChecksum(slot.event)) complete = false;
          } else if (slot.status != SlotStatus::Unused || slot.producer_sequence != 0) {
            complete = false;
          }
        }
        snapshot.producers.push_back(std::move(item));
      }
      snapshot.complete = complete;
      snapshot.checksum64 = detail::SnapshotChecksum(snapshot);
      return snapshot;
    } catch (...) {
      return RecorderError::AllocationFailure;
    }
  }

  [[nodiscard]] bool stopped() const noexcept {
    return !run_ || run_->stopped.load(std::memory_order_acquire);
  }
  [[nodiscard]] std::uint64_t planned_bytes() const noexcept {
    return run_ ? run_->planned_bytes : 0;
  }

 private:
  explicit EventRecorder(std::shared_ptr<detail::RunState> run) noexcept
      : run_(std::move(run)) {}
  std::shared_ptr<detail::RunState> run_;
};

}  // namespace rateguard::events
