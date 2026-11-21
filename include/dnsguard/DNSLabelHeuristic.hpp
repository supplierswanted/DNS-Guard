#pragma once
#include "DNSTrafficCollector.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>

namespace dnsguard {
struct DNSLabelHeuristicConfig {
    bool enabled = false;
    std::size_t label_length_threshold = 50;
};

struct DNSLabelHeuristicAssessment {
    std::uint8_t confidence;
    std::uint32_t rule_version;
    std::size_t observed_label_length;
    std::size_t threshold;
    std::string_view reason;
};

enum class DNSLabelHeuristicError : std::uint8_t {
    invalid_config,
    invalid_observation
};

using DNSLabelHeuristicResult =
    std::variant<std::optional<DNSLabelHeuristicAssessment>,
                 DNSLabelHeuristicError>;

[[nodiscard]] DNSLabelHeuristicResult evaluateDNSLabelLength(
    const DNSQueryObservation& observation,
    const DNSLabelHeuristicConfig& config = {});
}
