#include "dnsguard/DNSTrafficCollector.hpp"
#include "dnsguard/DNSParser.hpp"

#include <algorithm>
#include <mutex>
#include <new>
#include <utility>
#include <type_traits>
#include <iterator>

namespace dnsguard {

namespace {
std::optional<std::uint32_t> cacheableTtl(const DNSMessage& message) {
    if (!message.header.qr || message.header.opcode != 0 || message.header.tc ||
        message.responseCode() != 0 || message.questions.size() != 1 ||
        message.answers.empty()) {
        return std::nullopt;
    }

    auto ttl = message.answers.front().ttl;
    for (const auto& answer : message.answers) {
        // RFC 2181 section 8: a received TTL with bit 31 set is zero.
        if ((answer.ttl & 0x80000000u) != 0) return std::nullopt;
        ttl = std::min(ttl, answer.ttl);
    }

    if (ttl == 0) {
        return std::nullopt;
    }

    return ttl;
}
}

DNSTrafficCollector::DNSTrafficCollector(CollectorConfig config)
    : config_(config) {
    if (config_.queue_capacity == 0) {
        config_.queue_capacity = 1;
    }
}

DNSObservationResult normalizeDNSQuery(const CapturedDNSPacket& packet) {
    auto parsed = parseDNSMessage(packet.payload);
    if (const auto* error = std::get_if<ParseError>(&parsed)) {
        return *error;
    }

    auto& message = std::get<DNSMessage>(parsed);
    if (message.header.qr) {
        return DNSObservationSkip::response;
    }
    if (message.header.opcode != 0) {
        return DNSObservationSkip::unsupported_opcode;
    }
    if (message.questions.empty()) {
        return DNSObservationSkip::no_questions;
    }
    if (message.questions.size() != 1) {
        return DNSObservationSkip::multiple_questions;
    }

    auto& question = message.questions.front();
    return DNSQueryObservation{
        .name = std::move(question.name),
        .question_type = question.type,
        .question_class = question.qclass,
        .captured_at = packet.metadata.captured_at,
        .transport = packet.metadata.transport,
        .source = packet.metadata.source
    };
}

EnqueueStatus DNSTrafficCollector::ingest(
    std::span<const std::uint8_t> payload,
    DNSCaptureMetadata metadata) {
    constexpr std::size_t max_dns_message_size = 65535;
    {
        std::lock_guard lock(mutex_);

        if (closed_) {
            ++dropped_count_;
            return EnqueueStatus::closed;
        }

        if (payload.size() > max_dns_message_size) {
            ++dropped_count_;
            return EnqueueStatus::payload_too_large;
        }

        if (reserved_packets_ >= config_.queue_capacity ||
            queue_.size() >= config_.queue_capacity - reserved_packets_) {
            ++dropped_count_;
            return EnqueueStatus::queue_full;
        }

        if (payload.size() > config_.max_queued_payload_bytes - accounted_payload_bytes_) {
            ++dropped_count_;
            return EnqueueStatus::byte_limit_reached;
        }

        ++reserved_packets_;
        accounted_payload_bytes_ += payload.size();
    }

    bool wake_all = false;
    try {
        Bytes owned_payload(payload.begin(), payload.end());
        CapturedDNSPacket packet{
            .metadata = std::move(metadata),
            .payload = std::move(owned_payload)
        };

        {
            std::lock_guard lock(mutex_);
            queue_.push_back(std::move(packet));
            --reserved_packets_;
            wake_all = closed_;
        }
    } catch (const std::bad_alloc&) {
        {
            std::lock_guard lock(mutex_);
            --reserved_packets_;
            accounted_payload_bytes_ -= payload.size();
            ++dropped_count_;
            wake_all = closed_;
        }
        if (wake_all) {
            queue_changed_.notify_all();
        }
        return EnqueueStatus::allocation_failure;
    }

    if (wake_all) {
        queue_changed_.notify_all();
    } else {
        queue_changed_.notify_one();
    }
    return EnqueueStatus::queued;
}

std::optional<CapturedDNSPacket> DNSTrafficCollector::tryPop() {
    std::lock_guard lock(mutex_);

    if (queue_.empty()) {
        return std::nullopt;
    }

    CapturedDNSPacket packet = std::move(queue_.front());
    accounted_payload_bytes_ -= packet.payload.size();
    queue_.pop_front();
    return packet;
}

std::optional<CapturedDNSPacket> DNSTrafficCollector::waitPop() {
    std::unique_lock lock(mutex_);
    queue_changed_.wait(lock, [this] {
        return !queue_.empty() || (closed_ && reserved_packets_ == 0);
    });

    if (queue_.empty()) {
        return std::nullopt;
    }

    CapturedDNSPacket packet = std::move(queue_.front());
    accounted_payload_bytes_ -= packet.payload.size();
    queue_.pop_front();
    if (!queue_.empty()) {
        queue_changed_.notify_one();
    }
    return packet;
}

bool DNSTrafficCollector::cacheResponse(const DNSMessage& response) try {
    const auto ttl = cacheableTtl(response);
    if (!ttl || !sameName(response.questions.front().name,
                          response.questions.front().name)) {
        return false;
    }

    // Bound each of the 1024 entries to 16 KiB of accounted storage.
    std::size_t remaining = 16 * 1024;
    auto charge = [&](std::size_t size) {
        if (size > remaining) return false;
        remaining -= size;
        return true;
    };
    if (response.answers.size() > remaining / sizeof(Record) ||
        !charge(response.answers.size() * sizeof(Record)) ||
        !charge(response.questions.front().name.wire.size())) return false;
    for (const auto& answer : response.answers) {
        if (!charge(answer.owner.wire.size())) return false;
        const bool fits = std::visit([&](const auto& data) {
            using T = std::decay_t<decltype(data)>;
            if constexpr (std::is_same_v<T, Bytes>) return charge(data.size());
            else if constexpr (std::is_same_v<T, Name>) return charge(data.wire.size());
            else if constexpr (std::is_same_v<T, MX>) return charge(data.exchange.wire.size());
            else if constexpr (std::is_same_v<T, SOA>)
                return charge(data.mname.wire.size()) && charge(data.rname.wire.size());
            else if constexpr (std::is_same_v<T, TXT>) {
                if (data.strings.size() > remaining / sizeof(Bytes) ||
                    !charge(data.strings.size() * sizeof(Bytes))) return false;
                for (const auto& part : data.strings) if (!charge(part.size())) return false;
                return true;
            } else return true;
        }, answer.data);
        if (!fits) return false;
    }
    std::lock_guard lock(cache_mutex_);
    const auto now = std::chrono::steady_clock::now();
    CachedAnswer entry{
        .question = response.questions.front(),
        .answers = response.answers,
        .stored_at = now,
        .expires_at = now + std::chrono::seconds(
            static_cast<std::chrono::seconds::rep>(*ttl))
    };

    // Commit before eviction: a failed allocation leaves existing entries intact.
    answer_cache_.push_back(std::move(entry));
    for (auto it = answer_cache_.begin(); it != std::prev(answer_cache_.end());) {
        const bool same_question =
            it->question.type == response.questions.front().type &&
            it->question.qclass == response.questions.front().qclass &&
            sameName(it->question.name, response.questions.front().name);
        if (it->expires_at <= now || same_question) {
            it = answer_cache_.erase(it);
        } else {
            ++it;
        }
    }
    if (answer_cache_.size() > answer_cache_capacity_) {
        answer_cache_.pop_front();
    }
    return true;
} catch (const std::bad_alloc&) {
    return false;
}

std::optional<std::vector<Record>> DNSTrafficCollector::lookup(
    const Question& question) {
    std::lock_guard lock(cache_mutex_);
    const auto now = std::chrono::steady_clock::now();

    for (auto it = answer_cache_.begin(); it != answer_cache_.end();) {
        if (it->expires_at <= now) {
            it = answer_cache_.erase(it);
            continue;
        }

        if (it->question.type == question.type &&
            it->question.qclass == question.qclass &&
            sameName(it->question.name, question.name)) {
            auto answers = it->answers;
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->stored_at).count();
            const auto elapsed_seconds = static_cast<std::uint32_t>(elapsed);
            for (auto& answer : answers) {
                answer.ttl = answer.ttl > elapsed_seconds
                    ? answer.ttl - elapsed_seconds
                    : 0;
            }
            return answers;
        }
        ++it;
    }
    return std::nullopt;
}

void DNSTrafficCollector::close() {
    {
        std::lock_guard lock(mutex_);
        closed_ = true;
    }
    queue_changed_.notify_all();
}

std::uint64_t DNSTrafficCollector::droppedCount() const {
    std::lock_guard lock(mutex_);
    return dropped_count_;
}

} // namespace dnsguard

