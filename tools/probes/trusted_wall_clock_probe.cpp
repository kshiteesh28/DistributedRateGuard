#include "security/trusted_wall_clock.h"

#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

using namespace rateguard::security;

namespace {
struct Capture {
  std::optional<SynchronizationStatus> synchronization;
  std::optional<RawWallTime> realtime;
};

class CapturingPlatform final : public ITrustedWallClockPlatform {
 public:
  explicit CapturingPlatform(std::shared_ptr<Capture> capture)
      : capture_(std::move(capture)) {}

  TrustedWallClockResult<SynchronizationStatus> ReadSynchronization() override {
    auto result = native_.ReadSynchronization();
    if (const auto* status = std::get_if<SynchronizationStatus>(&result))
      capture_->synchronization = *status;
    return result;
  }

  TrustedWallClockResult<RawWallTime> ReadRealtime() override {
    auto result = native_.ReadRealtime();
    if (const auto* sample = std::get_if<RawWallTime>(&result))
      capture_->realtime = *sample;
    return result;
  }

 private:
  std::shared_ptr<Capture> capture_;
  NativeTrustedWallClockPlatform native_;
};

void EmitJson(const Capture& capture, bool trusted,
              const TrustedWallClockFailureReason* reason) {
#if defined(__linux__)
  constexpr std::string_view platform = "linux";
#else
  constexpr std::string_view platform = "unsupported";
#endif
  std::cout << "{\"platform\":\"" << platform << "\",\"sync_state\":";
  if (capture.synchronization)
    std::cout << capture.synchronization->state;
  else
    std::cout << "null";
  std::cout << ",\"status_flags\":";
  if (capture.synchronization)
    std::cout << capture.synchronization->flags;
  else
    std::cout << "null";
  std::cout << ",\"trusted\":" << (trusted ? "true" : "false")
            << ",\"failure_reason\":";
  if (reason)
    std::cout << '"' << FailureReasonName(*reason) << '"';
  else
    std::cout << "null";
  if (trusted && capture.realtime) {
    std::cout << ",\"unix_seconds\":" << capture.realtime->seconds
              << ",\"nanoseconds\":" << capture.realtime->nanoseconds;
  }
  std::cout << "}\n";
}
}  // namespace

int main() {
  try {
    auto capture = std::make_shared<Capture>();
    std::unique_ptr<ITrustedWallClockPlatform> platform =
        std::make_unique<CapturingPlatform>(capture);
    auto clock_result = TrustedWallClock::Create(std::move(platform));
    if (auto* clock = std::get_if<std::unique_ptr<TrustedWallClock>>(&clock_result)) {
      const bool trusted = (*clock)->Healthy() && capture->synchronization &&
                           capture->realtime;
      if (trusted) {
        EmitJson(*capture, true, nullptr);
        return 0;
      }
      const auto reason = TrustedWallClockFailureReason::LatchedFailure;
      EmitJson(*capture, false, &reason);
      return 2;
    }
    const auto& failure = std::get<TrustedWallClockFailure>(clock_result);
    EmitJson(*capture, false, &failure.reason);
    return 2;
  } catch (...) {
    const auto reason = TrustedWallClockFailureReason::PlatformUnavailable;
    EmitJson(Capture{}, false, &reason);
    return 1;
  }
}
