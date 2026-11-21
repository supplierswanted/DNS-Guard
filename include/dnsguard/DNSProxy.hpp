#pragma once
#include "DNSDomainLists.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stop_token>
#include <string>

namespace dnsguard {
struct DNSCacheStats { std::uint64_t hits, misses; std::size_t entries; };
struct ProxyConfig {
    std::string listen_ipv4 = "127.0.0.1";
    std::uint16_t listen_port = 5353;
    std::string upstream_ipv4;
    std::uint16_t upstream_port = 53;
    std::string secondary_upstream_ipv4;
    std::uint16_t secondary_upstream_port = 53;
    bool rebind_protection = false;
    unsigned timeout_ms = 2000, workers = 4, queue_capacity = 64;
    DNSDomainListsConfig lists{};
    // Optional second listener, always bound only to IPv6 loopback (::1).
    std::uint16_t listen_ipv6_port = 0;
    // Set by loadProxyConfig; direct in-memory configurations remain static.
    std::filesystem::path config_path, blocklist_path, allowlist_path, feedlist_path;
};
[[nodiscard]] ProxyConfig loadProxyConfig(const std::filesystem::path& path);
class DNSProxy {
public:
    explicit DNSProxy(ProxyConfig config);
    ~DNSProxy();
    DNSProxy(const DNSProxy&) = delete;
    DNSProxy& operator=(const DNSProxy&) = delete;
    // One-shot event loop. Call on one thread and join it before destruction.
    void run(std::stop_token stop);
    [[nodiscard]] DNSCacheStats cacheStats() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
