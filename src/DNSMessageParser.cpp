#include "ParserInternal.hpp"
#include <new>
#include <limits>

namespace dnsguard {
DNSParseResult parseDNSMessage(detail::View packet, ParseLimits limits) {
    constexpr auto unlimited = std::numeric_limits<std::size_t>::max();
    return parseDNSMessageBounded(packet, limits, {unlimited, unlimited});
}

DNSParseResult parseDNSMessageBounded(detail::View packet, ParseLimits limits, MessageBudget budget) {
    if (packet.size() > 65535 || packet.size() > limits.message_bytes)
        return ParseError{ErrorCode::resource_limit, 0};
    try {
        detail::Cursor c{packet, 0, packet.size()};
        DNSMessage msg{};
        msg.header = detail::readHeader(c);
        const auto& h = msg.header;
        const auto records = std::size_t{h.answers} + h.authority + h.additional;
        if (h.questions > limits.questions) return ParseError{ErrorCode::resource_limit, 4};
        if (records > limits.records) return ParseError{ErrorCode::resource_limit, 6};
        // A root question needs 5 bytes, a root RR at least 11. Check
        // before reserve so impossible counts cannot amplify a short packet.
        if (5u * h.questions + 11u * records > packet.size() - c.pos)
            return ParseError{ErrorCode::truncated, packet.size()};
        detail::Names names{{}, limits.pointer_hops, budget.pointer_hops};
        msg.questions.reserve(h.questions);
        for (unsigned i = 0; i < h.questions; ++i)
            msg.questions.push_back(detail::readQuestion(c, names));
        auto section = [&](std::vector<Record>& out, unsigned count) {
            out.reserve(count);
            for (unsigned i = 0; i < count; ++i) {
                const auto start = c.pos;
                const auto& rr = out.emplace_back(detail::readRecord(c, names, budget.txt_strings));
                if (rr.type == 41) {
                    if (&out != &msg.additional || msg.edns || packet[start] != 0)
                        throw ParseError{ErrorCode::invalid_rdata, start};
                    msg.edns = DNSMessage::Edns{rr.rrclass, static_cast<std::uint8_t>(rr.ttl >> 24),
                        static_cast<std::uint8_t>(rr.ttl >> 16), static_cast<std::uint16_t>(rr.ttl)};
                }
            }
        };
        section(msg.answers, h.answers);
        section(msg.authority, h.authority);
        section(msg.additional, h.additional);
        if (c.pos != c.end) return ParseError{ErrorCode::trailing_data, c.pos};
        return msg;
    } catch (ParseError error) {
        return error;
    } catch (const std::bad_alloc&) {
        return ParseError{ErrorCode::allocation_failure, 0};
    }
}
}
