#include "dnsguard/DNSLabelHeuristic.hpp"

#include <algorithm>

namespace dnsguard {
DNSLabelHeuristicResult evaluateDNSLabelLength(
    const DNSQueryObservation& observation,
    const DNSLabelHeuristicConfig& config) {
    if (!config.enabled) {
        return std::optional<DNSLabelHeuristicAssessment>{};
    }
    if (config.label_length_threshold == 0 ||
        config.label_length_threshold > 63) {
        return DNSLabelHeuristicError::invalid_config;
    }
    if (!sameName(observation.name, observation.name)) {
        return DNSLabelHeuristicError::invalid_observation;
    }

    std::size_t longest_label = 0;
    for (std::size_t offset = 0; observation.name.wire[offset] != 0;) {
        const auto label_length = observation.name.wire[offset];
        longest_label = std::max(longest_label,
                                 static_cast<std::size_t>(label_length));
        offset += static_cast<std::size_t>(label_length) + 1;
    }
    if (longest_label < config.label_length_threshold) {
        return std::optional<DNSLabelHeuristicAssessment>{};
    }
    return DNSLabelHeuristicAssessment{
        .confidence = 25,
        .rule_version = 1,
        .observed_label_length = longest_label,
        .threshold = config.label_length_threshold,
        .reason = "DNS label length met configured anomaly threshold"
    };
}
}
