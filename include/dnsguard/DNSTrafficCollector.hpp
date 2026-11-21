#pragma once
#include "DNSErrors.hpp"
#include "DNSMessage.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <span>
#include <variant>
#include <condition_variable>

namespace dnsguard {
enum class DNSTransport : std::uint8_t {
    udp,
    tcp
};

using IPAddress = std::variant<IPv4, IPv6>;

struct Endpoint {
    IPAddress address;
    std::uint16_t port;
};

struct DNSCaptureMetadata {
    std::chrono::system_clock::time_point captured_at;
    DNSTransport transport;
    Endpoint source;
    Endpoint destination;
};

struct CapturedDNSPacket {
    DNSCaptureMetadata metadata;
    Bytes payload;
};

struct DNSQueryObservation {
    Name name;
    std::uint16_t question_type;
    std::uint16_t question_class;
    std::chrono::system_clock::time_point captured_at;
    DNSTransport transport;
    Endpoint source;
};

enum class DNSObservationSkip : std::uint8_t {
    response,
    no_questions,
    multiple_questions,
    unsupported_opcode
};

using DNSObservationResult =
    std::variant<DNSQueryObservation, ParseError, DNSObservationSkip>;

[[nodiscard]] DNSObservationResult normalizeDNSQuery(
    const CapturedDNSPacket& packet);

struct CollectorConfig {
    std::size_t queue_capacity = 1024;
    std::size_t max_queued_payload_bytes = 16 * 1024 * 1024;
};

enum class EnqueueStatus : std::uint8_t {
    queued,
    queue_full,
    byte_limit_reached,
    payload_too_large,
    allocation_failure,
    closed
};

class DNSTrafficCollector {
public:
    explicit DNSTrafficCollector(CollectorConfig config = {});

    [[nodiscard]] EnqueueStatus ingest(
        std::span<const std::uint8_t> payload,
        DNSCaptureMetadata metadata);

    [[nodiscard]] std::optional<CapturedDNSPacket> tryPop();
    [[nodiscard]] std::optional<CapturedDNSPacket> waitPop();
    void close();

    [[nodiscard]] bool cacheResponse(const DNSMessage& response);
    [[nodiscard]] std::optional<std::vector<Record>> lookup(const Question& question);

    [[nodiscard]] std::uint64_t droppedCount() const;

private:
    struct CachedAnswer {
        Question question;
        std::vector<Record> answers;
        std::chrono::steady_clock::time_point stored_at;
        std::chrono::steady_clock::time_point expires_at;
    };

    static constexpr std::size_t answer_cache_capacity_ = 1024;

    CollectorConfig config_;
    mutable std::mutex mutex_;
    std::condition_variable queue_changed_;
    std::deque<CapturedDNSPacket> queue_;
    std::size_t reserved_packets_ = 0;
    std::size_t accounted_payload_bytes_ = 0;
    std::uint64_t dropped_count_ = 0;
    bool closed_ = false;

    mutable std::mutex cache_mutex_;
    std::deque<CachedAnswer> answer_cache_;
};

}
