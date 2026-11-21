#pragma once
#include "dnsguard/DNSMessage.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dnsguard {
class DNSResponseCache {
public:
    struct Stats { std::uint64_t hits, misses; std::size_t entries; };
    std::optional<Bytes> get(const Bytes& query, std::uint64_t policy_epoch);
    void put(const Bytes& query, const Bytes& response, const DNSMessage& parsed_query,
             std::uint64_t policy_epoch);
    Stats stats() const;
private:
    struct Ttl { std::size_t offset; std::uint32_t original; };
    struct Entry {
        std::string key;
        Bytes response;
        std::vector<Ttl> ttls;
        std::chrono::steady_clock::time_point inserted;
        std::uint32_t lifetime;
        std::uint64_t policy_epoch;
    };
    mutable std::mutex mutex_;
    std::list<Entry> entries_;
    std::unordered_map<std::string, std::list<Entry>::iterator> index_;
    std::atomic<std::uint64_t> hits_{0}, misses_{0};
};
}
