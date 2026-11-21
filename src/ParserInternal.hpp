#pragma once
#include "dnsguard/DNSParser.hpp"
#include <bitset>


namespace dnsguard::detail {
using View = std::span<const std::uint8_t>;

// Absolute positions. end is exclusive, including inside RDATA.
struct Cursor {
    View packet;
    std::size_t pos, end;
    ErrorCode short_read = ErrorCode::truncated;

    View take(std::size_t n) {
        if (pos > end || end > packet.size() || n > end - pos) {
            throw ParseError{short_read, pos};
        }
        auto result = packet.subspan(pos, n);
        pos += n;
        return result;
    }
    std::uint8_t byte() { return take(1)[0]; }
    std::uint16_t u16() {
        auto b = take(2);
        return static_cast<std::uint16_t>((b[0] << 8) | b[1]);
    }
    std::uint32_t u32() {
        const std::uint32_t high = u16();
        return (high << 16) | u16();
    }
};
struct Names {
    std::bitset<16384> boundaries; // All possible 14-bit targets.
    std::size_t max_hops;
    std::size_t remaining_hops;
    Name decode(Cursor& input);
};
Header readHeader(Cursor&);
Question readQuestion(Cursor&, Names&);
Record readRecord(Cursor&, Names&, std::size_t& remaining_strings);
}
