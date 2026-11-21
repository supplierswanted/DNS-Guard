#include "DNSResponseCache.hpp"
#include "ParserInternal.hpp"
#include "dnsguard/DNSParser.hpp"
#include <algorithm>

namespace dnsguard {
namespace {
constexpr std::size_t max_entries = 256;
constexpr std::uint32_t max_lifetime = 300;
std::string key(const Bytes& query) {
    return std::string(query.begin()+2,query.end());
}
void writeTtl(Bytes& response, std::size_t offset, std::uint32_t ttl) {
    for (int shift : {24,16,8,0}) response[offset++] = static_cast<std::uint8_t>(ttl >> shift);
}
}

std::optional<Bytes> DNSResponseCache::get(const Bytes& query, std::uint64_t policy_epoch) {
    if (query.size() < 12) return std::nullopt;
    std::lock_guard lock(mutex_);
    const auto found = index_.find(key(query));
    if (found == index_.end()) { ++misses_; return std::nullopt; }
    auto entry = found->second;
    const auto age = std::chrono::steady_clock::now() - entry->inserted;
    if (entry->policy_epoch != policy_epoch || age >= std::chrono::seconds(entry->lifetime)) {
        entries_.erase(entry);
        index_.erase(found);
        ++misses_;
        return std::nullopt;
    }
    const auto elapsed = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(age + std::chrono::milliseconds(999)).count());
    auto response = entry->response;
    response[0]=query[0]; response[1]=query[1];
    for (const auto& ttl : entry->ttls)
        writeTtl(response,ttl.offset,ttl.original > elapsed ? ttl.original-elapsed : 0);
    entries_.splice(entries_.begin(),entries_,entry);
    ++hits_;
    return response;
}

void DNSResponseCache::put(const Bytes& query, const Bytes& response,
                           const DNSMessage& parsed_query, std::uint64_t policy_epoch) {
    if (query.size() < 12 || response.size() < 12 || response.size() > 512 ||
        parsed_query.questions.size() != 1 || parsed_query.edns ||
        !parsed_query.additional.empty() || !parsed_query.authority.empty() ||
        !parsed_query.answers.empty() || parsed_query.questions[0].qclass != 1 ||
        (parsed_query.questions[0].type != 1 && parsed_query.questions[0].type != 28)) return;
    const auto parsed = parseDNSMessageBounded(response,{}, {4096,4096});
    const auto* message = std::get_if<DNSMessage>(&parsed);
    if (!message || !message->header.qr || message->header.tc || message->edns ||
        message->header.id != parsed_query.header.id || message->questions.size() != 1 ||
        !sameName(message->questions[0].name,parsed_query.questions[0].name) ||
        message->questions[0].type != parsed_query.questions[0].type ||
        message->questions[0].qclass != 1 || !message->additional.empty()) return;
    const bool positive = message->header.rcode == 0 && !message->answers.empty() &&
        message->answers.size() <= 16 && message->authority.empty() &&
        std::all_of(message->answers.begin(),message->answers.end(),[&](const Record& rr) {
            return rr.type == parsed_query.questions[0].type && rr.rrclass == 1 &&
                sameName(rr.owner,parsed_query.questions[0].name);
        });
    const bool negative = (message->header.rcode == 3 ||
        (message->header.rcode == 0 && message->answers.empty())) &&
        message->answers.empty() && message->authority.size() == 1 &&
        message->authority[0].type == 6 && message->authority[0].rrclass == 1 &&
        std::holds_alternative<SOA>(message->authority[0].data);
    if (!positive && !negative) return;

    try {
        detail::Cursor cursor{response,0,response.size()};
        detail::readHeader(cursor);
        detail::Names names{{},64,4096};
        detail::readQuestion(cursor,names);
        std::vector<Ttl> ttls;
        ttls.reserve(positive ? message->answers.size() : 1);
        auto collect = [&] {
            names.decode(cursor);
            cursor.u16(); cursor.u16();
            const auto offset = cursor.pos;
            const auto ttl = cursor.u32();
            cursor.take(cursor.u16());
            ttls.push_back({offset,ttl});
        };
        for (std::size_t i=0;i<message->answers.size();++i) collect();
        for (std::size_t i=0;i<message->authority.size();++i) collect();
        if (negative) ttls[0].original = std::min(ttls[0].original,
            std::get<SOA>(message->authority[0].data).minimum);
        std::uint32_t lifetime = max_lifetime;
        for (const auto& ttl : ttls) lifetime = std::min(lifetime,ttl.original);
        if (!lifetime) return;
        Entry entry{key(query),response,std::move(ttls),std::chrono::steady_clock::now(),
                    lifetime,policy_epoch};
        std::lock_guard lock(mutex_);
        if (auto found = index_.find(entry.key); found != index_.end()) {
            entries_.erase(found->second);
            index_.erase(found);
        }
        entries_.push_front(std::move(entry));
        try { index_.emplace(entries_.front().key,entries_.begin()); }
        catch (...) { entries_.pop_front(); throw; }
        if (entries_.size() > max_entries) {
            index_.erase(entries_.back().key);
            entries_.pop_back();
        }
    } catch (const ParseError&) { return; }
}

DNSResponseCache::Stats DNSResponseCache::stats() const {
    std::lock_guard lock(mutex_);
    return {hits_.load(),misses_.load(),entries_.size()};
}
}
