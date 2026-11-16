#pragma once

#include <string>
#include <vector>

#include "rateguard/security/peer_identity.h"

namespace rateguard::security::test {

struct EphemeralIdentity final {
  RegisteredPeer registered;
  std::string certificate_pem;
  std::string private_key_pem;
};

// Test-only authority and identities. All keys are generated in memory; callers
// must never print or serialize private_key_pem/certificate_pem.
class EphemeralPki final {
 public:
  EphemeralPki();
  ~EphemeralPki();
  EphemeralPki(const EphemeralPki&) = delete;
  EphemeralPki& operator=(const EphemeralPki&) = delete;

  const std::string& root_certificate_pem() const;
  const EphemeralIdentity& Issue(PeerRole role, std::string uri);
  const EphemeralIdentity& IssueWithValidity(PeerRole role, std::string uri,
                                              long not_before_seconds_from_now,
                                              long not_after_seconds_from_now);
  const EphemeralIdentity& IssueWithUriSans(PeerRole role,
                                            std::vector<std::string> uri_sans);

 private:
  struct Impl;
  Impl* impl_;
};

}  // namespace rateguard::security::test
