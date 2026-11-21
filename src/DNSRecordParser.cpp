#include "ParserInternal.hpp"
#include <algorithm>

namespace dnsguard::detail {
namespace {
template<class Address>
Address address(Cursor& c) {
    Address result{};
    auto bytes = c.take(result.size());
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

RData readData(Cursor& c, Names& names, std::uint16_t type, std::uint16_t rrclass,
               std::size_t& remaining_strings) {
    switch (type) {
    case 1:
        if (rrclass == 1) return address<IPv4>(c);
        break;
    case 28:
        if (rrclass == 1) return address<IPv6>(c);
        break;
    case 2: case 5: case 12:
        return names.decode(c);
    case 15:
        return MX{c.u16(), names.decode(c)};
    case 6:
        return SOA{names.decode(c), names.decode(c), c.u32(), c.u32(),
                   c.u32(), c.u32(), c.u32()};
    case 16: {
        if (c.pos == c.end) {
            throw ParseError{ErrorCode::invalid_rdata, c.pos};
        }
        auto scan = c;
        std::size_t strings = 0;
        do {
            if (strings == remaining_strings && scan.pos < scan.end)
                throw ParseError{ErrorCode::resource_limit, scan.pos};
            scan.take(scan.byte());
            ++strings;
        } while (scan.pos < scan.end);
        remaining_strings -= strings;
        TXT result;
        result.strings.reserve(strings);
        do {
            const auto count = c.byte();
            auto part = c.take(count);
            result.strings.emplace_back(part.begin(), part.end());
        } while (c.pos < c.end);
        return result;
    }
    }
    if (type == 41) {
        // Keep unknown options verbatim after validating their TLV framing.
        auto options = c;
        while (options.pos < options.end) {
            options.u16(); // OPTION-CODE
            const auto length = options.u16();
            options.take(length);
        }
    }
    auto bytes = c.take(c.end - c.pos);
    return Bytes(bytes.begin(), bytes.end());
}
}

Record readRecord(Cursor& c, Names& names, std::size_t& remaining_strings) {
    Record rr{};
    rr.owner = names.decode(c);
    rr.type = c.u16();
    rr.rrclass = c.u16();
    rr.ttl = c.u32();
    rr.rdlength = c.u16();
    const auto start = c.pos;
    c.take(rr.rdlength);
    Cursor data{c.packet, start, c.pos, ErrorCode::invalid_rdata};
    rr.data = readData(data, names, rr.type, rr.rrclass, remaining_strings);
    if (data.pos != data.end) throw ParseError{ErrorCode::invalid_rdata, data.pos};
    return rr;
}
}
