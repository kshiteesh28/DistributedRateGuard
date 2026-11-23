#include "supervisor/manifest_codec.h"

#include <cstdio>
#include <cstdlib>
#include <array>
#include <cstdint>
#include <string>
#include <utility>
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
  out.reserve(64);
  for (auto byte : bytes) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 0x0f]);
  }
  return out;
}

ManifestV1 Fixture() {
  ManifestV1 m;
  m.candidate.epoch_id.fill(0x11);
  m.candidate.authority_incarnation.fill(0x22);
  m.candidate.policy_digest.fill(0x33);
  m.candidate.clock_identity.boot_uuid.fill(0x44);
  m.candidate.clock_identity.namespace_device = 7;
  m.candidate.clock_identity.namespace_inode = 9;
  m.candidate.clock_identity.monotonic_offset_seconds = -2;
  m.candidate.clock_identity.monotonic_offset_nanoseconds = 123;
  m.candidate.clock_identity.boottime_offset_seconds = 3;
  m.candidate.clock_identity.boottime_offset_nanoseconds = 456;
  m.candidate.clock_identity.clock_id = 1;
  m.generation = 1;
  m.transition_operation_id.fill(0x55);
  m.phase = ManifestPhase::Prepared;

  const auto participant = [&](ParticipantRole role, std::uint32_t slot,
                               std::string id, std::uint8_t incarnation_byte,
                               std::uint64_t pid) {
    Participant p;
    p.role = role;
    p.slot_id = slot;
    p.participant_id = std::move(id);
    p.incarnation.fill(incarnation_byte);
    p.process.container_id = std::string(63, 'a') + static_cast<char>('0' + pid % 10);
    p.process.pid = pid;
    p.process.pid_start_ticks = pid + 10;
    p.clock_identity = m.candidate.clock_identity;
    return p;
  };
  m.candidate.participants = {
      participant(ParticipantRole::Witness, 0, "witness", 0x66, 104),
      participant(ParticipantRole::Adapter, 0, "adapter", 0x77, 103),
      participant(ParticipantRole::Replica, 19, "replica", 0x88, 102),
      participant(ParticipantRole::Authority, 0, "authority", 0x22, 101),
  };
  return m;
}

ManifestCodecError Error(const ManifestDecodeResult& result) {
  CHECK(std::holds_alternative<ManifestCodecError>(result));
  return std::get<ManifestCodecError>(result);
}

void TestRoundTripAndCanonicalOrdering() {
  const auto input = Fixture();
  const auto encoded = EncodeManifestV1(input);
  CHECK(std::holds_alternative<std::string>(encoded));
  const auto& text = std::get<std::string>(encoded);
  const auto decoded = DecodeManifestV1(text);
  CHECK(std::holds_alternative<ManifestV1>(decoded));
  const auto& result = std::get<ManifestV1>(decoded);
  CHECK(result.candidate.epoch_id == input.candidate.epoch_id);
  CHECK(result.candidate.policy_digest == input.candidate.policy_digest);
  CHECK(result.candidate.clock_identity == input.candidate.clock_identity);
  CHECK(result.phase == input.phase && result.generation == input.generation);
  CHECK(result.transition_operation_id == input.transition_operation_id);
  CHECK(result.candidate.participants.front().role == ParticipantRole::Authority);
  CHECK(result.candidate.participants.back().role == ParticipantRole::Witness);
  CHECK(EncodeManifestV1(result) == encoded);

  const auto digest = ManifestDigestV1(input);
  CHECK((std::holds_alternative<std::array<std::uint8_t, 32>>(digest)));
  CHECK(Hex(std::get<std::array<std::uint8_t, 32>>(digest)) ==
        "727dfdb75bbcb4197d5000724c63c9d0b3db726238e5d0fa0670cabf1f655b0d");

  // A changed but valid manifest with a recomputed digest is parseable. The
  // digest is integrity checking, not authenticated rollback protection.
  auto changed = input;
  changed.candidate.participants.front().process.pid += 100;
  const auto changed_encoded = EncodeManifestV1(changed);
  CHECK(std::holds_alternative<std::string>(changed_encoded));
  const auto changed_decoded = DecodeManifestV1(std::get<std::string>(changed_encoded));
  CHECK(std::holds_alternative<ManifestV1>(changed_decoded));
  const auto changed_digest = ManifestDigestV1(changed);
  CHECK((std::holds_alternative<std::array<std::uint8_t, 32>>(changed_digest)));
  CHECK((std::get<std::array<std::uint8_t, 32>>(changed_digest) !=
         std::get<std::array<std::uint8_t, 32>>(digest)));
}

void TestStrictEnvelopeFailures() {
  const auto encoded = EncodeManifestV1(Fixture());
  CHECK(std::holds_alternative<std::string>(encoded));
  const auto good = std::get<std::string>(encoded);
  CHECK(Error(DecodeManifestV1(good + " ")) == ManifestCodecError::NonCanonical);

  std::string wrong_digest = good;
  const auto marker = wrong_digest.find("\"sha256\":\"");
  CHECK(marker != std::string::npos);
  const auto nibble = marker + 10;
  wrong_digest[nibble] = wrong_digest[nibble] == '0' ? '1' : '0';
  CHECK(Error(DecodeManifestV1(wrong_digest)) == ManifestCodecError::DigestMismatch);

  const auto duplicate = std::string("{\"manifest\":{},\"manifest\":{},\"sha256\":\"") +
      std::string(64, '0') + "\"}";
  CHECK(Error(DecodeManifestV1(duplicate)) == ManifestCodecError::DuplicateKey);

  auto unknown = good;
  const auto phase = unknown.find("\"phase\":\"PREPARED\"");
  CHECK(phase != std::string::npos);
  unknown.insert(phase, "\"extra\":1,");
  CHECK(Error(DecodeManifestV1(unknown)) == ManifestCodecError::UnknownKey);

  CHECK(Error(DecodeManifestV1(std::string(kMaxManifestBytes + 1, ' '))) ==
        ManifestCodecError::TooLarge);
}

void TestNonCanonicalIntegerAndClockValues() {
  const auto encoded = EncodeManifestV1(Fixture());
  CHECK(std::holds_alternative<std::string>(encoded));
  auto bad_generation = std::get<std::string>(encoded);
  const auto gen = bad_generation.find("\"generation\":\"1\"");
  CHECK(gen != std::string::npos);
  bad_generation.replace(gen, std::string("\"generation\":\"1\"").size(),
                         "\"generation\":\"01\"");
  CHECK(Error(DecodeManifestV1(bad_generation)) == ManifestCodecError::InvalidValue);

  auto duplicate_escaped_key = std::get<std::string>(encoded);
  duplicate_escaped_key.insert(1, "\"sha256\":\"" + std::string(64, '0') + "\",\"sha\\u0036a256\":\"" +
                                   std::string(64, '0') + "\",");
  CHECK(Error(DecodeManifestV1(duplicate_escaped_key)) == ManifestCodecError::DuplicateKey);

  auto invalid = Fixture();
  invalid.candidate.clock_identity.monotonic_offset_nanoseconds = 1'000'000'000U;
  CHECK(std::get<ManifestCodecError>(EncodeManifestV1(invalid)) == ManifestCodecError::InvalidValue);
  invalid = Fixture();
  invalid.generation = 0;
  CHECK(std::get<ManifestCodecError>(EncodeManifestV1(invalid)) == ManifestCodecError::InvalidValue);
}

}  // namespace

int main() {
  TestRoundTripAndCanonicalOrdering();
  TestStrictEnvelopeFailures();
  TestNonCanonicalIntegerAndClockValues();
  return 0;
}
