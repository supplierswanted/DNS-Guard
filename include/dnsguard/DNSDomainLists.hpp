#pragma once
#include "DNSTrafficCollector.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

namespace dnsguard {
inline constexpr std::size_t max_domain_list_entries = 32768;

struct DNSDomainListsConfig {
    bool enabled = false;
    bool include_subdomains = false;
    std::vector<Name> allowed;
    std::vector<Name> denied;
};

struct DNSDomainListMatch {
    std::uint8_t confidence;
    std::uint32_t rule_version;
    std::string_view reason;
};

struct DNSDomainListAssessment {
    std::optional<DNSDomainListMatch> allowed;
    std::optional<DNSDomainListMatch> denied;
};

enum class DNSDomainListError : std::uint8_t {
    invalid_name,
    too_many_entries
};

using DNSDomainListResult =
    std::variant<DNSDomainListAssessment, DNSDomainListError>;

[[nodiscard]] std::optional<DNSDomainListError> validateDNSDomainListsConfig(
    const DNSDomainListsConfig& config);
[[nodiscard]] DNSDomainListResult evaluateDNSDomainLists(
    const DNSQueryObservation& observation,
    const DNSDomainListsConfig& config);
}
