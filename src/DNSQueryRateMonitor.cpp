#include "dnsguard/DNSQueryRateMonitor.hpp"

#include <algorithm>
#include <new>
#include <utility>

namespace dnsguard {
std::optional<DNSQueryRateError> validateDNSQueryRateConfig(
    const DNSQueryRateConfig& config) noexcept {
    if (config.max_tracked_keys == 0 ||
        config.max_tracked_keys > max_dns_query_rate_keys ||
        config.query_threshold < 2 || config.window.count() <= 0 ||
        config.window.count() > max_dns_query_rate_window_seconds) {
        return DNSQueryRateError::invalid_config;
    }
    return std::nullopt;
}

DNSQueryRateMonitor::DNSQueryRateMonitor(DNSQueryRateConfig config)
    : config_(config), config_error_(validateDNSQueryRateConfig(config)) {}

DNSQueryRateResult DNSQueryRateMonitor::observe(
    const DNSQueryObservation& observation) {
    if (config_error_) {
        return *config_error_;
    }
    if (!config_.enabled) {
        return std::optional<DNSQueryRateAssessment>{};
    }
    if (!sameName(observation.name, observation.name)) {
        return DNSQueryRateError::invalid_observation;
    }

    std::lock_guard lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
        [&](const Entry& entry) {
            return now - entry.last_seen >= config_.window;
        }), entries_.end());
    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&](const Entry& entry) {
            return entry.source == observation.source.address &&
                entry.question_type == observation.question_type &&
                entry.question_class == observation.question_class &&
                sameName(entry.name, observation.name);
        });

    if (it == entries_.end()) {
        try {
            Entry entry{
                .name = observation.name,
                .source = observation.source.address,
                .question_type = observation.question_type,
                .question_class = observation.question_class,
                .window_started = now,
                .last_seen = now,
                .query_count = 1,
                .reported = false
            };
            if (entries_.size() == config_.max_tracked_keys) {
                const auto oldest = std::min_element(
                    entries_.begin(), entries_.end(),
                    [](const Entry& left, const Entry& right) {
                        return left.last_seen < right.last_seen;
                    });
                *oldest = std::move(entry);
            } else {
                entries_.push_back(std::move(entry));
            }
        } catch (const std::bad_alloc&) {
            return DNSQueryRateError::allocation_failure;
        }
        return std::optional<DNSQueryRateAssessment>{};
    }

    // shortcut: fixed windows can miss bursts across a boundary; use sliding timestamps if precision is required.
    if (now - it->window_started >= config_.window) {
        it->window_started = now;
        it->query_count = 0;
        it->reported = false;
    }
    it->last_seen = now;
    if (it->query_count < config_.query_threshold) {
        ++it->query_count;
    }
    if (!it->reported && it->query_count >= config_.query_threshold) {
        it->reported = true;
        return DNSQueryRateAssessment{
            .confidence = 50,
            .rule_version = 1,
            .query_count = it->query_count,
            .threshold = config_.query_threshold,
            .reason = "query count reached configured threshold"
        };
    }
    return std::optional<DNSQueryRateAssessment>{};
}
}
