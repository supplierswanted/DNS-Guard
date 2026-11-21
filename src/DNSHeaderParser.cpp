#include "ParserInternal.hpp"

namespace dnsguard::detail {
Header readHeader(Cursor& c) {
    Header h{};
    h.id = c.u16();
    const auto flags_offset = c.pos;
    h.flags = c.u16();
    if ((h.flags & 0x0040u) != 0) {
        throw ParseError{ErrorCode::invalid_header, flags_offset};
    }
    auto flag = [&](unsigned mask) { return (h.flags & mask) != 0; };
    h.qr = flag(0x8000);
    h.opcode = static_cast<std::uint8_t>((h.flags >> 11) & 15);
    h.aa = flag(0x0400);
    h.tc = flag(0x0200);
    h.rd = flag(0x0100);
    h.ra = flag(0x0080);
    h.ad = flag(0x0020);
    h.cd = flag(0x0010);
    h.rcode = static_cast<std::uint8_t>(h.flags & 15);
    h.questions = c.u16();
    h.answers = c.u16();
    h.authority = c.u16();
    h.additional = c.u16();
    return h;
}
}
