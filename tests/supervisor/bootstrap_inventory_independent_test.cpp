#include "supervisor/bootstrap_inventory.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using namespace rateguard::supervisor;

#define CHECK(expr) do { if (!(expr)) { \
  std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
  std::abort(); \
} } while (false)

namespace {

BootstrapPlan Plan() {
  BootstrapPlan plan;
  plan.domain_id[0] = 0x51;
  plan.epoch_id[0] = 1;
  plan.authority_incarnation[0] = 2;
  plan.policy_digest[0] = 3;
  plan.expected_clock_identity.boot_uuid[0] = 4;
  plan.expected_clock_identity.namespace_device = 11;
  plan.expected_clock_identity.namespace_inode = 12;
  plan.expected_clock_identity.clock_id = 1;
  const auto add = [&](ParticipantRole role, std::uint32_t slot, const char* id,
                       std::uint8_t incarnation, char container) {
    PlannedParticipant p;
    p.role = role;
    p.slot_id = slot;
    p.participant_id = id;
    p.incarnation[0] = role == ParticipantRole::Authority
                           ? plan.authority_incarnation[0] : incarnation;
    p.container_id = std::string(64, container);
    plan.participants.push_back(p);
  };
  add(ParticipantRole::Authority, 0, "authority", 2, 'a');
  add(ParticipantRole::Witness, 0, "witness", 5, 'b');
  add(ParticipantRole::Replica, 0, "replica-zero", 6, 'c');
  add(ParticipantRole::Replica, UINT32_MAX, "replica-max", 7, 'd');
  add(ParticipantRole::Adapter, 0, "adapter-a", 8, 'e');
  add(ParticipantRole::Adapter, 0, "adapter-b", 9, 'f');
  return plan;
}

ObservedBootstrapIdentity Observation(const BootstrapPlan& plan, std::size_t index,
                                      std::uint64_t pid) {
  ObservedBootstrapIdentity value;
  value.participant = plan.participants.at(index);
  value.pid = pid;
  value.pid_start_ticks = pid + 1000;
  value.clock_identity = plan.expected_clock_identity;
  return value;
}

BootstrapInventory MustCreate(const BootstrapPlan& plan) {
  auto result = BootstrapInventory::Create(plan);
  CHECK(std::holds_alternative<BootstrapInventory>(result));
  return std::get<BootstrapInventory>(std::move(result));
}

BootstrapInventory MustRecord(const BootstrapInventory& prior,
                              const ObservedBootstrapIdentity& observed) {
  auto result = prior.RecordIdentity(observed);
  CHECK(result.status == BootstrapError::None);
  return std::move(result.next);
}

BootstrapInventory RoundTrip(const BootstrapInventory& value) {
  auto encoded = EncodeBootstrapInventoryV1(value);
  CHECK(std::holds_alternative<std::string>(encoded));
  auto decoded = DecodeBootstrapInventoryV1(std::get<std::string>(encoded));
  CHECK(std::holds_alternative<BootstrapInventory>(decoded));
  return std::get<BootstrapInventory>(std::move(decoded));
}

void TestNoReadyCandidateUntilExactFullRoster() {
  const auto plan = Plan();
  auto inventory = MustCreate(plan);
  CHECK(inventory.recorded_count() == 0);
  CHECK(inventory.revision() == 1);
  CHECK(std::holds_alternative<BootstrapError>(inventory.ReadyCandidate()));
  CHECK(std::get<BootstrapError>(inventory.ReadyCandidate()) == BootstrapError::IncompleteRoster);

  for (std::size_t i = 0; i < plan.participants.size(); ++i) {
    inventory = MustRecord(inventory, Observation(plan, i, 100 + i));
    CHECK(inventory.recorded_count() == i + 1);
    CHECK(inventory.revision() == i + 2);
    // The caller-visible state is modeled through encode/decode between every
    // launch step; this test does not claim those bytes were durably persisted.
    inventory = RoundTrip(inventory);
    if (i + 1 < plan.participants.size())
      CHECK(std::holds_alternative<BootstrapError>(inventory.ReadyCandidate()));
  }
  const auto ready = inventory.ReadyCandidate();
  CHECK(std::holds_alternative<EpochCandidate>(ready));
  const auto& candidate = std::get<EpochCandidate>(ready);
  CHECK(candidate.epoch_id == plan.epoch_id);
  CHECK(candidate.authority_incarnation == plan.authority_incarnation);
  CHECK(candidate.policy_digest == plan.policy_digest);
  CHECK(candidate.clock_identity == plan.expected_clock_identity);
  CHECK(candidate.participants.size() == plan.participants.size());
  for (std::size_t i = 0; i < plan.participants.size(); ++i) {
    const auto& planned = plan.participants[i];
    const auto found = std::find_if(candidate.participants.begin(), candidate.participants.end(),
        [&](const Participant& p) {
          return p.role == planned.role && p.participant_id == planned.participant_id;
        });
    CHECK(found != candidate.participants.end());
    const auto& actual = *found;
    CHECK(actual.role == planned.role);
    CHECK(actual.slot_id == planned.slot_id);
    CHECK(actual.participant_id == planned.participant_id);
    CHECK(actual.incarnation == planned.incarnation);
    CHECK(actual.process.container_id == planned.container_id);
    CHECK(actual.process.pid == 100 + i);
    CHECK(actual.process.pid_start_ticks == 1100 + i);
    CHECK(actual.clock_identity == plan.expected_clock_identity);
  }
}

void TestIdempotentRepeatAndImmutableIdentity() {
  const auto plan = Plan();
  auto inventory = MustCreate(plan);
  const auto first = Observation(plan, 0, 200);
  inventory = MustRecord(inventory, first);
  CHECK(inventory.revision() == 2);
  const auto duplicate = inventory.RecordIdentity(first);
  CHECK(duplicate.status == BootstrapError::None);
  CHECK(duplicate.next.recorded_count() == 1);
  CHECK(duplicate.next.revision() == inventory.revision());
  CHECK(!duplicate.next.recovery_required());

  auto replacement = first;
  replacement.pid_start_ticks += 1;
  const auto rejected = duplicate.next.RecordIdentity(replacement);
  CHECK(rejected.status == BootstrapError::IdentityMismatch);
  CHECK(rejected.next.recovery_required());
  CHECK(rejected.next.revision() == inventory.revision() + 1);
  CHECK(rejected.next.recovery_reason() == BootstrapError::IdentityMismatch);
  CHECK(std::holds_alternative<BootstrapError>(rejected.next.ReadyCandidate()));

  const auto retry = rejected.next.RecordIdentity(first);
  CHECK(retry.status == BootstrapError::RecoveryRequired);
  CHECK(retry.next.recovery_required());
  CHECK(retry.next.revision() == rejected.next.revision());
  CHECK(std::holds_alternative<BootstrapError>(retry.next.ReadyCandidate()));
}

void TestUnknownAndMismatchedObservationsLatchRecovery() {
  const auto plan = Plan();
  auto inventory = MustCreate(plan);
  for (const auto& bad_kind : {0, 1, 2, 3}) {
    auto bad = Observation(plan, 0, 300);
    if (bad_kind == 0) bad.participant.participant_id = "unplanned";
    if (bad_kind == 1) bad.participant.container_id = std::string(64, 'z');
    if (bad_kind == 2) bad.participant.incarnation[0] ^= 1;
    if (bad_kind == 3) bad.clock_identity.namespace_inode += 1;
    auto transition = inventory.RecordIdentity(bad);
    CHECK(transition.status != BootstrapError::None);
    CHECK(transition.next.recovery_required());
    CHECK(std::holds_alternative<BootstrapError>(transition.next.ReadyCandidate()));
  }

  auto unknown_role = Observation(plan, 0, 300);
  unknown_role.participant.role = ParticipantRole::Adapter;
  auto unknown = inventory.RecordIdentity(unknown_role);
  CHECK(unknown.status == BootstrapError::IdentityNotInPlan);
  CHECK(unknown.next.recovery_reason() == BootstrapError::IdentityNotInPlan);
}

void TestInvalidProcessIdentityAndPIDReuse() {
  const auto plan = Plan();
  for (const bool pid_zero : {false, true}) {
    auto inventory = MustCreate(plan);
    auto bad = Observation(plan, 0, 400);
    if (pid_zero) bad.pid = 0;
    else bad.pid_start_ticks = 0;
    const auto result = inventory.RecordIdentity(bad);
    CHECK(result.status != BootstrapError::None);
    CHECK(result.next.recovery_required());
  }

  auto inventory = MustCreate(plan);
  inventory = MustRecord(inventory, Observation(plan, 0, 500));
  auto reused_pid = Observation(plan, 1, 500);
  reused_pid.pid_start_ticks = 9000;  // Different start time cannot make two live PIDs unique.
  const auto collision = inventory.RecordIdentity(reused_pid);
  CHECK(collision.status == BootstrapError::DuplicateProcessIdentity);
  CHECK(collision.next.recovery_reason() == BootstrapError::DuplicateProcessIdentity);
  CHECK(collision.next.recovery_required());

}

void TestPlanValidationAndExplicitRecovery() {
  auto invalid = Plan();
  invalid.participants[2].container_id = invalid.participants[1].container_id;
  CHECK(std::holds_alternative<BootstrapError>(BootstrapInventory::Create(invalid)));

  invalid = Plan();
  invalid.expected_clock_identity.clock_id = 99;
  CHECK(std::holds_alternative<BootstrapError>(BootstrapInventory::Create(invalid)));

  auto inventory = MustCreate(Plan());
  const auto recovery = inventory.RequireRecovery(BootstrapError::InvalidEncoding);
  CHECK(recovery.recovery_required());
  CHECK(recovery.revision() == inventory.revision() + 1);
  CHECK(recovery.recovery_reason() == BootstrapError::InvalidEncoding);
  CHECK(std::holds_alternative<BootstrapError>(recovery.ReadyCandidate()));
  auto attempted_recover = recovery.RecordIdentity(Observation(Plan(), 0, 601));
  CHECK(attempted_recover.status == BootstrapError::RecoveryRequired);
  CHECK(attempted_recover.next.recovery_required());
  CHECK(attempted_recover.next.revision() == recovery.revision());
}

void TestCanonicalCodecRejectsMalformedAndUntrustedEdits() {
  const auto inventory = MustCreate(Plan());
  const auto encoded = EncodeBootstrapInventoryV1(inventory);
  CHECK(std::holds_alternative<std::string>(encoded));
  const auto canonical = std::get<std::string>(encoded);
  const auto round_trip = DecodeBootstrapInventoryV1(canonical);
  CHECK(std::holds_alternative<BootstrapInventory>(round_trip));

  auto whitespace = canonical;
  whitespace.push_back(' ');
  const auto noncanonical = DecodeBootstrapInventoryV1(whitespace);
  CHECK(std::get_if<BootstrapError>(&noncanonical) != nullptr);
  CHECK(std::get<BootstrapError>(noncanonical) == BootstrapError::NonCanonical);

  auto bad_digest = canonical;
  const auto hash = bad_digest.find("\"sha256\":\"");
  CHECK(hash != std::string::npos);
  const auto hash_digit = hash + 10;
  bad_digest[hash_digit] = bad_digest[hash_digit] == '0' ? '1' : '0';
  const auto digest_error = DecodeBootstrapInventoryV1(bad_digest);
  CHECK(std::get_if<BootstrapError>(&digest_error) != nullptr);
  CHECK(std::get<BootstrapError>(digest_error) == BootstrapError::DigestMismatch);

  // Duplicate keys are rejected even when their values would later fail schema validation.
  auto duplicate = canonical;
  const auto inventory_key = duplicate.find("\"inventory\":");
  CHECK(inventory_key != std::string::npos);
  duplicate.insert(inventory_key, "\"invent\\u006fry\":{},");
  const auto duplicate_error = DecodeBootstrapInventoryV1(duplicate);
  CHECK(std::get_if<BootstrapError>(&duplicate_error) != nullptr);
  CHECK(std::get<BootstrapError>(duplicate_error) == BootstrapError::DuplicateKey);

  auto unknown = canonical;
  const auto object = unknown.find('{');
  CHECK(object == 0);
  unknown.insert(object + 1, "\"unexpected\":0,");
  const auto unknown_error = DecodeBootstrapInventoryV1(unknown);
  CHECK(std::get_if<BootstrapError>(&unknown_error) != nullptr);
  CHECK(std::get<BootstrapError>(unknown_error) == BootstrapError::UnknownKey);

  const auto oversized = DecodeBootstrapInventoryV1(std::string(kMaxBootstrapBytes + 1, ' '));
  CHECK(std::get_if<BootstrapError>(&oversized) != nullptr);
  CHECK(std::get<BootstrapError>(oversized) == BootstrapError::TooLarge);
}

}  // namespace

int main() {
  static_assert(kMaxBootstrapBytes == 4U * 1024U * 1024U);
  TestNoReadyCandidateUntilExactFullRoster();
  TestIdempotentRepeatAndImmutableIdentity();
  TestUnknownAndMismatchedObservationsLatchRecovery();
  TestInvalidProcessIdentityAndPIDReuse();
  TestPlanValidationAndExplicitRecovery();
  TestCanonicalCodecRejectsMalformedAndUntrustedEdits();
  std::puts("independent bootstrap inventory checks passed");
}
