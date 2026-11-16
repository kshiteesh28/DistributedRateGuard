#include "security/trusted_wall_clock.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <limits>
#include <memory>
#include <thread>
#include <utility>

using namespace rateguard::security;

namespace {
int failures = 0;
void Expect(bool ok, const char* label) {
  if (!ok) { std::cerr << "FAIL: " << label << '\n'; ++failures; }
}
TrustedWallClockFailure Error(TrustedWallClockFailureReason reason) {
  using namespace rateguard::v1::contract;
  return {{ErrorCategory::Dependency, ErrorCode::Unavailable,
           RetryDisposition::Never, Commitment::NotCommitted}, reason};
}
template <class T> bool FailedAs(const TrustedWallClockResult<T>& value,
                                TrustedWallClockFailureReason reason) {
  const auto* e = std::get_if<TrustedWallClockFailure>(&value);
  return e && e->reason == reason &&
         e->service_error.category == rateguard::v1::contract::ErrorCategory::Dependency &&
         e->service_error.code == rateguard::v1::contract::ErrorCode::Unavailable &&
         e->service_error.commitment == rateguard::v1::contract::Commitment::NotCommitted;
}

class FakePlatform final : public ITrustedWallClockPlatform {
 public:
  struct Counters { std::atomic<unsigned> sync_calls{0}; std::atomic<unsigned> time_calls{0}; };
  std::shared_ptr<Counters> counters = std::make_shared<Counters>();
  std::deque<TrustedWallClockResult<SynchronizationStatus>> syncs;
  std::deque<TrustedWallClockResult<RawWallTime>> times;
  TrustedWallClockResult<SynchronizationStatus> ReadSynchronization() override {
    ++counters->sync_calls;
    if (syncs.empty()) return SynchronizationStatus{0,0};
    auto result=std::move(syncs.front()); syncs.pop_front(); return result;
  }
  TrustedWallClockResult<RawWallTime> ReadRealtime() override {
    ++counters->time_calls;
    if (times.empty()) return RawWallTime{100,0};
    auto result=std::move(times.front()); times.pop_front(); return result;
  }
};
auto Create(std::unique_ptr<FakePlatform> p) {
  return TrustedWallClock::Create(std::unique_ptr<ITrustedWallClockPlatform>(std::move(p)));
}

void StateAndFlagCases() {
  for (std::int32_t state=0; state<=4; ++state) {
    auto p=std::make_unique<FakePlatform>();
    p->syncs={SynchronizationStatus{state,0}};
    p->times={RawWallTime{1700000000,123},RawWallTime{1700000001,0}};
    auto c=Create(std::move(p));
    auto* clock=std::get_if<std::unique_ptr<TrustedWallClock>>(&c);
    Expect(clock && (*clock)->Healthy(), "synchronization states 0..4 accepted after initial sample");
    if (clock) {
      auto n=(*clock)->Now();
      Expect(std::get_if<WallTime>(&n)!=nullptr, "accepted synchronization state permits later sample");
    }
  }
  auto time_error=std::make_unique<FakePlatform>();
  time_error->syncs={SynchronizationStatus{5,0}};
  Expect(FailedAs(Create(std::move(time_error)),TrustedWallClockFailureReason::TimeErrorState),
         "TIME_ERROR state fails before factory readiness");
  for (std::int32_t state : {-1,6,std::numeric_limits<std::int32_t>::max()}) {
    auto unknown=std::make_unique<FakePlatform>(); unknown->syncs={SynchronizationStatus{state,0}};
    Expect(FailedAs(Create(std::move(unknown)),TrustedWallClockFailureReason::UnknownState),
           "unknown synchronization state fails closed");
  }
  auto unsync=std::make_unique<FakePlatform>(); unsync->syncs={SynchronizationStatus{0,0x0040}};
  Expect(FailedAs(Create(std::move(unsync)),TrustedWallClockFailureReason::UnsynchronizedFlag),
         "STA_UNSYNC fails closed");
  auto clockerr=std::make_unique<FakePlatform>(); clockerr->syncs={SynchronizationStatus{0,0x1000}};
  Expect(FailedAs(Create(std::move(clockerr)),TrustedWallClockFailureReason::ClockErrorFlag),
         "STA_CLOCKERR fails closed");
  auto both=std::make_unique<FakePlatform>(); both->syncs={SynchronizationStatus{0,0x1040}};
  Expect(FailedAs(Create(std::move(both)),TrustedWallClockFailureReason::UnsynchronizedFlag),
         "combined rejected flags fail with deterministic first reason");
  auto other=std::make_unique<FakePlatform>(); other->syncs={SynchronizationStatus{4,0x0002}};
  Expect(std::holds_alternative<std::unique_ptr<TrustedWallClock>>(Create(std::move(other))),
         "unrelated status flags do not cause false distrust");
}

void InitialReadAndNumericCases() {
  auto unavailable=std::make_unique<FakePlatform>();
  unavailable->syncs={Error(TrustedWallClockFailureReason::SynchronizationSyscall)};
  Expect(FailedAs(Create(std::move(unavailable)),TrustedWallClockFailureReason::SynchronizationSyscall),
         "initial adjtimex failure blocks readiness");
  auto time_failure=std::make_unique<FakePlatform>();
  time_failure->times={Error(TrustedWallClockFailureReason::RealtimeSyscall)};
  Expect(FailedAs(Create(std::move(time_failure)),TrustedWallClockFailureReason::RealtimeSyscall),
         "initial realtime failure blocks readiness");

  const std::array<RawWallTime,5> invalid{{{-1,0},{0,-1},{0,1'000'000'000},
      {std::numeric_limits<std::int64_t>::min(),0},{1, std::numeric_limits<std::int64_t>::max()}}};
  for (const auto raw : invalid) {
    auto p=std::make_unique<FakePlatform>(); p->times={raw};
    Expect(std::holds_alternative<TrustedWallClockFailure>(Create(std::move(p))),
           "invalid initial wall sample blocks readiness");
  }
  auto max_ok=std::make_unique<FakePlatform>();
  max_ok->times={RawWallTime{std::numeric_limits<std::int64_t>::max(),999'999'999}};
  auto max_clock=Create(std::move(max_ok));
  Expect(std::holds_alternative<std::unique_ptr<TrustedWallClock>>(max_clock),
         "maximum representable trusted wall time is accepted");
  auto boundary=std::make_unique<FakePlatform>(); boundary->times={RawWallTime{0,0}};
  auto c=Create(std::move(boundary));
  Expect(std::holds_alternative<std::unique_ptr<TrustedWallClock>>(c), "Unix epoch boundary is valid");
}

void StickyAndOrderingCases() {
  auto p=std::make_unique<FakePlatform>();
  p->syncs={SynchronizationStatus{0,0},SynchronizationStatus{5,0},SynchronizationStatus{0,0}};
  p->times={RawWallTime{100,0},RawWallTime{101,0},RawWallTime{102,0}};
  auto c=Create(std::move(p)); auto* ptr=std::get_if<std::unique_ptr<TrustedWallClock>>(&c);
  Expect(ptr && (*ptr)->Healthy(), "valid startup clock healthy");
  if (ptr) {
    Expect(FailedAs((*ptr)->Now(),TrustedWallClockFailureReason::TimeErrorState),
           "live TIME_ERROR latches failure");
    Expect(!(*ptr)->Healthy(), "latched wall-clock failure clears health");
    Expect(FailedAs((*ptr)->Now(),TrustedWallClockFailureReason::TimeErrorState),
           "first error remains sticky without recovery");
  }
  auto backwards=std::make_unique<FakePlatform>();
  backwards->times={RawWallTime{100,1},RawWallTime{100,0}};
  auto bc=Create(std::move(backwards)); auto* bp=std::get_if<std::unique_ptr<TrustedWallClock>>(&bc);
  if (bp) Expect(FailedAs((*bp)->Now(),TrustedWallClockFailureReason::BackwardsRead),
                 "backward UTC observation latches trust loss");
  else Expect(false,"backward scenario initialized");
  auto equal=std::make_unique<FakePlatform>(); equal->times={RawWallTime{100,7},RawWallTime{100,7}};
  auto ec=Create(std::move(equal)); auto* ep=std::get_if<std::unique_ptr<TrustedWallClock>>(&ec);
  if (ep) Expect(std::holds_alternative<WallTime>((*ep)->Now()),"equal realtime observations are legal");
  else Expect(false,"equal scenario initialized");
  auto short_circuit=std::make_unique<FakePlatform>();
  short_circuit->syncs={Error(TrustedWallClockFailureReason::SynchronizationSyscall)};
  auto counts=short_circuit->counters;
  (void)Create(std::move(short_circuit));
  Expect(counts->time_calls.load()==0,"failed status check does not read realtime");
}

void ConcurrentSerializationCase() {
  constexpr std::size_t n = 24;
  auto p=std::make_unique<FakePlatform>();
  p->syncs.emplace_back(SynchronizationStatus{0,0});
  p->times.emplace_back(RawWallTime{100,0});
  for (std::size_t i=1;i<=n;++i) {
    p->syncs.emplace_back(SynchronizationStatus{0,0});
    p->times.emplace_back(RawWallTime{100+static_cast<std::int64_t>(i),0});
  }
  auto result=Create(std::move(p));
  auto* clock=std::get_if<std::unique_ptr<TrustedWallClock>>(&result);
  Expect(clock!=nullptr,"concurrency fixture creates trusted clock");
  if (!clock) return;
  std::array<std::int64_t,n> values{};
  std::array<bool,n> ok{};
  std::array<std::thread,n> threads;
  for (std::size_t i=0;i<n;++i) {
    threads[i]=std::thread([&,i] {
      auto sample=(*clock)->Now();
      if (const auto* value=std::get_if<WallTime>(&sample)) {
        values[i]=value->unix_seconds;
        ok[i]=true;
      }
    });
  }
  for (auto& thread:threads) thread.join();
  for (bool success:ok) Expect(success,"serialized concurrent realtime query succeeds");
  std::sort(values.begin(),values.end());
  for (std::size_t i=0;i<n;++i)
    Expect(values[i]==101+static_cast<std::int64_t>(i),"concurrent samples preserve increasing source order");
}

}  // namespace

int main() {
  StateAndFlagCases();
  InitialReadAndNumericCases();
  StickyAndOrderingCases();
  ConcurrentSerializationCase();
  if (failures != 0) return EXIT_FAILURE;
  std::cout << "independent trusted wall-clock checks passed\n";
  return EXIT_SUCCESS;
}
