#include "dnsguard/DNSDomainLists.hpp"
#include <algorithm>

namespace dnsguard {
namespace {
bool validList(const std::vector<Name>& domains) {
    for (const auto& domain : domains) {
        if (!sameName(domain, domain)) {
            return false;
        }
    }
    return true;
}

enum class MatchScope {
    exact,
    subdomain
};

bool matchesSuffixAt(const Name& name, std::size_t offset, const Name& suffix) {
    if (name.wire.size() - offset != suffix.wire.size()) {
        return false;
    }

    const auto fold = [](std::uint8_t value) {
        return value >= 'A' && value <= 'Z'
            ? static_cast<std::uint8_t>(value + ('a' - 'A'))
            : value;
    };
    return std::equal(name.wire.begin() + static_cast<Bytes::difference_type>(offset), name.wire.end(),
                      suffix.wire.begin(),
                      [&](std::uint8_t left, std::uint8_t right) {
                          return fold(left) == fold(right);
                      });
}

bool isSubdomainOf(const Name& name, const Name& domain) {
    // A strict parent must have a shorter wire name. Avoid validating/scanning
    // impossible candidates on each miss.
    if (domain.wire.size() >= name.wire.size()) return false;
    if (!sameName(domain, domain)) {
        return false;
    }
    for (std::size_t offset = 0; name.wire[offset] != 0;) {
        offset += static_cast<std::size_t>(name.wire[offset]) + 1;
        if (matchesSuffixAt(name, offset, domain)) {
            return true;
        }
    }
    return false;
}

std::optional<MatchScope> findMatch(
    const std::vector<Name>& domains,
    const Name& name,
    bool include_subdomains) {
    for (const auto& domain : domains) {
        if (sameName(domain, name)) {
            return MatchScope::exact;
        }
    }
    if (include_subdomains) {
        for (const auto& domain : domains) {
            if (isSubdomainOf(name, domain)) {
                return MatchScope::subdomain;
            }
        }
    }
    return std::nullopt;
}
}

std::optional<DNSDomainListError> validateDNSDomainListsConfig(
    const DNSDomainListsConfig& config) {
    if (config.allowed.size() > max_domain_list_entries ||
        config.denied.size() > max_domain_list_entries - config.allowed.size()) {
        return DNSDomainListError::too_many_entries;
    }
    if (!validList(config.allowed) || !validList(config.denied)) {
        return DNSDomainListError::invalid_name;
    }
    return std::nullopt;
}

DNSDomainListResult evaluateDNSDomainLists(
    const DNSQueryObservation& observation,
    const DNSDomainListsConfig& config) {
    DNSDomainListAssessment assessment;
    if (!config.enabled) {
        return assessment;
    }
    if (config.allowed.size() > max_domain_list_entries ||
        config.denied.size() > max_domain_list_entries - config.allowed.size()) {
        return DNSDomainListError::too_many_entries;
    }
    if (!sameName(observation.name, observation.name)) {
        return DNSDomainListError::invalid_name;
    }

    const auto allowed = findMatch(
        config.allowed, observation.name, config.include_subdomains);
    if (allowed) {
        assessment.allowed = DNSDomainListMatch{
            .confidence = 100,
            .rule_version = 1,
            .reason = *allowed == MatchScope::exact
                ? "exact configured allow-list match"
                : "subdomain configured allow-list match"
        };
    }
    const auto denied = findMatch(
        config.denied, observation.name, config.include_subdomains);
    if (denied) {
        assessment.denied = DNSDomainListMatch{
            .confidence = 100,
            .rule_version = 1,
            .reason = *denied == MatchScope::exact
                ? "exact configured deny-list match"
                : "subdomain configured deny-list match"
        };
    }
    return assessment;
}
}
