#include "authority/bucket_math.h"

#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <variant>

namespace authority = rateguard::authority;
using authority::BucketDecision;
using authority::BucketMath;
using authority::BucketPolicy;
using authority::BucketState;
using authority::MathResult;
using authority::ServiceError;

namespace {
void PrintError(const ServiceError& error) {
  std::cout << "ERR " << static_cast<unsigned>(error.category) << ' '
            << static_cast<unsigned>(error.code) << ' '
            << static_cast<unsigned>(error.retry) << ' '
            << static_cast<unsigned>(error.commitment) << '\n';
}
void PrintState(const BucketState& state) {
  std::cout << "OK " << state.balance_subunits << ' '
            << state.last_refill_ns << '\n';
}
void PrintDecision(const BucketDecision& decision) {
  std::cout << "OK ";
  if (decision.outcome == authority::DecisionOutcome::Allow) std::cout << "ALLOW ";
  else if (decision.outcome == authority::DecisionOutcome::Limited) std::cout << "LIMITED ";
  else std::cout << "OTHER ";
  std::cout << decision.next.balance_subunits << ' '
            << decision.next.last_refill_ns << ' ';
  if (decision.retry_delay_ns) std::cout << *decision.retry_delay_ns;
  else std::cout << '-';
  std::cout << '\n';
}
template <class T, class Printer>
void PrintResult(const MathResult<T>& result, Printer printer) {
  if (const auto* error = std::get_if<ServiceError>(&result)) PrintError(*error);
  else printer(std::get<T>(result));
}
}  // namespace

int main() {
  char op = 0;
  while (std::cin >> op) {
    if (op == 'R') {
      std::uint64_t capacity, rate, balance, last, now;
      if (!(std::cin >> capacity >> rate >> balance >> last >> now)) return 2;
      PrintResult(BucketMath::Refill({capacity, rate}, {balance, last}, now), PrintState);
    } else if (op == 'D') {
      std::uint64_t capacity, rate, balance, last, cost, now;
      if (!(std::cin >> capacity >> rate >> balance >> last >> cost >> now)) return 2;
      PrintResult(BucketMath::Decide({capacity, rate}, {balance, last}, cost, now), PrintDecision);
    } else if (op == 'T') {
      std::uint64_t deficit, rate;
      if (!(std::cin >> deficit >> rate)) return 2;
      PrintResult(BucketMath::RetryDelay(deficit, rate),
                  [](std::uint64_t ns) { std::cout << "OK " << ns << '\n'; });
    } else {
      std::cerr << "unknown operation: " << op << '\n';
      return 2;
    }
  }
  return 0;
}
