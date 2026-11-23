#include "supervisor/bootstrap_inventory.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <variant>

namespace {
using namespace rateguard::supervisor;

#define CHECK(condition) do { \
  if (!(condition)) { \
    std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
    std::abort(); \
  } \
} while (false)

std::string Hex(const std::array<std::uint8_t, 32>& bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (const auto byte : bytes) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 15]);
  }
  return out;
}

BootstrapPlan Plan() {
  BootstrapPlan plan;
  plan.domain_id.fill(0x10);
  plan.epoch_id.fill(0x11);
  plan.authority_incarnation.fill(0x22);
  plan.policy_digest.fill(0x33);
  plan.expected_clock_identity.boot_uuid.fill(0x44);
  plan.expected_clock_identity.namespace_device = 7;
  plan.expected_clock_identity.namespace_inode = 9;
  plan.expected_clock_identity.monotonic_offset_seconds = -2;
  plan.expected_clock_identity.monotonic_offset_nanoseconds = 123;
  plan.expected_clock_identity.boottime_offset_seconds = 3;
  plan.expected_clock_identity.boottime_offset_nanoseconds = 456;
  plan.expected_clock_identity.clock_id = 1;

  const auto participant = [](ParticipantRole role, std::uint32_t slot, std::string id,
                              std::uint8_t incarnation_byte, char suffix) {
    PlannedParticipant p;
    p.role = role;
    p.slot_id = slot;
    p.participant_id = std::move(id);
    p.incarnation.fill(incarnation_byte);
    p.container_id = std::string(63, 'a') + suffix;
    return p;
  };
  // Deliberately unsorted to verify canonical inventory order.
  plan.participants = {
      participant(ParticipantRole::Witness, 0, "witness", 0x66, '4'),
      participant(ParticipantRole::Adapter, 0, "adapter", 0x77, '3'),
      participant(ParticipantRole::Replica, 19, "replica", 0x88, '2'),
      participant(ParticipantRole::Authority, 0, "authority", 0x22, '1'),
  };
  return plan;
}

std::variant<BootstrapInventory, BootstrapError> NewInventory() {
  return BootstrapInventory::Create(Plan());
}

ObservedBootstrapIdentity Observation(const PlannedParticipant& participant, std::uint64_t pid) {
  return ObservedBootstrapIdentity{participant, pid, pid + 1000, Plan().expected_clock_identity};
}

BootstrapInventory Apply(const BootstrapInventory& prior, const ObservedBootstrapIdentity& observed) {
  auto transition = prior.RecordIdentity(observed);
  CHECK(transition.status == BootstrapError::None);
  return transition.next;
}

void TestStageProgressAndCodec() {
  auto created = NewInventory();
  CHECK(std::holds_alternative<BootstrapInventory>(created));
  auto inventory = std::get<BootstrapInventory>(created);
  CHECK(inventory.recorded_count() == 0);
  CHECK(std::get<BootstrapError>(inventory.ReadyCandidate()) == BootstrapError::IncompleteRoster);
  CHECK(inventory.records().front().planned.role == ParticipantRole::Authority);
  CHECK(inventory.records().back().planned.role == ParticipantRole::Witness);

  const auto encoded_initial = EncodeBootstrapInventoryV1(inventory);
  CHECK(std::holds_alternative<std::string>(encoded_initial));
  auto digest = BootstrapDigestV1(inventory);
  CHECK((std::holds_alternative<std::array<std::uint8_t, 32>>(digest)));
  CHECK(Hex(std::get<std::array<std::uint8_t, 32>>(digest)) ==
        "7d46c1694ecf5fb38622deb41273c40c7b4de26d2066c16ed1418bfcdd93e773");
  auto decoded = DecodeBootstrapInventoryV1(std::get<std::string>(encoded_initial));
  CHECK(std::holds_alternative<BootstrapInventory>(decoded));
  CHECK(EncodeBootstrapInventoryV1(std::get<BootstrapInventory>(decoded)) == encoded_initial);

  const auto original_plan = Plan();
  for (std::size_t index = 0; index < original_plan.participants.size(); ++index) {
    inventory = Apply(inventory, Observation(original_plan.participants[index], 100 + index));
    CHECK(inventory.recorded_count() == index + 1);
    if (index + 1 != original_plan.participants.size())
      CHECK(std::get<BootstrapError>(inventory.ReadyCandidate()) == BootstrapError::IncompleteRoster);
  }
  CHECK(inventory.revision() == 5);
  const auto complete = inventory.ReadyCandidate();
  CHECK(std::holds_alternative<EpochCandidate>(complete));
  CHECK(std::get<EpochCandidate>(complete).participants.size() == original_plan.participants.size());
  CHECK(std::get<EpochCandidate>(complete).participants[1].slot_id == 19);

  const auto repeated = inventory.RecordIdentity(Observation(original_plan.participants[0], 100));
  CHECK(repeated.status == BootstrapError::None);
  CHECK(repeated.next.revision() == inventory.revision());
  CHECK(EncodeBootstrapInventoryV1(repeated.next) == EncodeBootstrapInventoryV1(inventory));
  const auto final_encoded = EncodeBootstrapInventoryV1(inventory);
  CHECK(std::holds_alternative<std::string>(final_encoded));
  CHECK(std::holds_alternative<BootstrapInventory>(DecodeBootstrapInventoryV1(std::get<std::string>(final_encoded))));
}

void TestMismatchLatchesRecovery() {
  auto created = NewInventory();
  CHECK(std::holds_alternative<BootstrapInventory>(created));
  const auto inventory = std::get<BootstrapInventory>(created);
  auto unknown = Observation(Plan().participants.front(), 101);
  unknown.participant.participant_id = "not-registered";
  auto transition = inventory.RecordIdentity(unknown);
  CHECK(transition.status == BootstrapError::IdentityNotInPlan);
  CHECK(transition.next.recovery_required());
  CHECK(transition.next.recovery_reason() == BootstrapError::IdentityNotInPlan);
  CHECK(transition.next.revision() == inventory.revision() + 1);
  CHECK(std::get<BootstrapError>(transition.next.ReadyCandidate()) == BootstrapError::RecoveryRequired);

  auto correct = Observation(inventory.records().front().planned, 101);
  auto blocked = transition.next.RecordIdentity(correct);
  CHECK(blocked.status == BootstrapError::RecoveryRequired);
  CHECK(blocked.next.recovery_required());

  auto initial2 = NewInventory();
  CHECK(std::holds_alternative<BootstrapInventory>(initial2));
  auto wrong_clock = Observation(inventory.records().front().planned, 101);
  wrong_clock.clock_identity.namespace_inode++;
  auto clock_failure = std::get<BootstrapInventory>(initial2).RecordIdentity(wrong_clock);
  CHECK(clock_failure.status == BootstrapError::IdentityMismatch);
  CHECK(clock_failure.next.recovery_required());
}

void TestReplacementAndDuplicatePidLatch() {
  const auto plan = Plan();
  auto created = NewInventory();
  CHECK(std::holds_alternative<BootstrapInventory>(created));
  auto inventory = std::get<BootstrapInventory>(created);
  inventory = Apply(inventory, Observation(plan.participants[0], 200));
  auto replacement = inventory.RecordIdentity(Observation(plan.participants[0], 201));
  CHECK(replacement.status == BootstrapError::IdentityMismatch);
  CHECK(replacement.next.recovery_required());

  auto another = NewInventory();
  CHECK(std::holds_alternative<BootstrapInventory>(another));
  inventory = std::get<BootstrapInventory>(another);
  inventory = Apply(inventory, Observation(plan.participants[0], 300));
  auto duplicate = inventory.RecordIdentity(Observation(plan.participants[1], 300));
  CHECK(duplicate.status == BootstrapError::DuplicateProcessIdentity);
  CHECK(duplicate.next.recovery_required());
}

void TestCodecRejectsCorruptionDuplicatesAndCaps() {
  auto created = NewInventory();
  CHECK(std::holds_alternative<BootstrapInventory>(created));
  const auto encoded = EncodeBootstrapInventoryV1(std::get<BootstrapInventory>(created));
  CHECK(std::holds_alternative<std::string>(encoded));
  const auto good = std::get<std::string>(encoded);

  auto corrupted = good;
  const auto digest = corrupted.find("\"sha256\":\"");
  CHECK(digest != std::string::npos);
  corrupted[digest + 10] = corrupted[digest + 10] == '0' ? '1' : '0';
  CHECK(std::get<BootstrapError>(DecodeBootstrapInventoryV1(corrupted)) == BootstrapError::DigestMismatch);

  CHECK(std::get<BootstrapError>(DecodeBootstrapInventoryV1(good + " ")) == BootstrapError::NonCanonical);
  const std::string duplicate = "{\"inventory\":{},\"inventory\":{},\"sha256\":\"" +
      std::string(64, '0') + "\"}";
  CHECK(std::get<BootstrapError>(DecodeBootstrapInventoryV1(duplicate)) == BootstrapError::DuplicateKey);
  CHECK(std::get<BootstrapError>(DecodeBootstrapInventoryV1(std::string(kMaxBootstrapBytes + 1, ' '))) ==
        BootstrapError::TooLarge);
}

void TestInvalidPlansRejected() {
  auto plan = Plan();
  plan.participants[0].container_id = plan.participants[1].container_id;
  CHECK(std::get<BootstrapError>(BootstrapInventory::Create(plan)) == BootstrapError::InvalidPlan);
  plan = Plan();
  plan.participants.pop_back();
  CHECK(std::get<BootstrapError>(BootstrapInventory::Create(plan)) == BootstrapError::InvalidPlan);
  plan = Plan();
  plan.participants[2].slot_id = UINT32_MAX;  // fixed policy IDs are not constrained to [0, N)
  auto max_slot = BootstrapInventory::Create(plan);
  CHECK(std::holds_alternative<BootstrapInventory>(max_slot));
}

}  // namespace

int main() {
  TestStageProgressAndCodec();
  TestMismatchLatchesRecovery();
  TestReplacementAndDuplicatePidLatch();
  TestCodecRejectsCorruptionDuplicatesAndCaps();
  TestInvalidPlansRejected();
  return 0;
}
