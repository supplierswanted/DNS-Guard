#pragma once
#include "DNSTrafficCollector.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

namespace dnsguard {
inline constexpr std::size_t max_dns_query_rate_keys = 65536;
inline constexpr std::chrono::seconds::rep
    max_dns_query_rate_window_seconds = 365LL * 24 * 60 * 60;

struct DNSQueryRateConfig {
    bool enabled = false;
    std::size_t max_tracked_keys = 4096;
    std::size_t query_threshold = 100;
    std::chrono::seconds window{60};
};

struct DNSQueryRateAssessment {
    std::uint8_t confidence;
    std::uint32_t rule_version;
    std::size_t query_count;
    std::size_t threshold;
    std::string_view reason;
};

enum class DNSQueryRateError : std::uint8_t {
    invalid_config,
    invalid_observation,
    allocation_failure
};

[[nodiscard]] std::optional<DNSQueryRateError> validateDNSQueryRateConfig(
    const DNSQueryRateConfig& config) noexcept;

using DNSQueryRateResult =
    std::variant<std::optional<DNSQueryRateAssessment>, DNSQueryRateError>;

class DNSQueryRateMonitor {
public:
    explicit DNSQueryRateMonitor(DNSQueryRateConfig config = {});

    [[nodiscard]] DNSQueryRateResult observe(
        const DNSQueryObservation& observation);

private:
    struct Entry {
        Name name;
        IPAddress source;
        std::uint16_t question_type;
        std::uint16_t question_class;
        std::chrono::steady_clock::time_point window_started;
        std::chrono::steady_clock::time_point last_seen;
        std::size_t query_count;
        bool reported;
    };

    DNSQueryRateConfig config_;
    std::optional<DNSQueryRateError> config_error_;
    std::mutex mutex_;
    std::vector<Entry> entries_;
};
}
