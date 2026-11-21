#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace dnsguard {
using Bytes = std::vector<std::uint8_t>;
// Expanded length-prefixed labels, including the terminating zero.
// This retains case, embedded NULs, literal dots and label boundaries.
struct Name { Bytes wire; };
[[nodiscard]] std::optional<std::string> displayName(const Name& name);
[[nodiscard]] bool sameName(const Name& a, const Name& b) noexcept;
struct Header {
    std::uint16_t id, flags;
    bool qr, aa, tc, rd, ra, ad, cd;
    std::uint8_t opcode, rcode;
    std::uint16_t questions, answers, authority, additional;
};
struct Question {
    Name name;
    std::uint16_t type, qclass;
};
using IPv4 = std::array<std::uint8_t, 4>;
using IPv6 = std::array<std::uint8_t, 16>;
struct MX { std::uint16_t preference; Name exchange; };
struct SOA {
    Name mname, rname;
    std::uint32_t serial, refresh, retry, expire, minimum;
};
struct TXT { std::vector<Bytes> strings; };
using RData = std::variant<IPv4, IPv6, Name, MX, TXT, SOA, Bytes>;
struct Record {
    Name owner;
    std::uint16_t type, rrclass;
    std::uint32_t ttl;
    std::uint16_t rdlength;
    RData data;
};
struct DNSMessage {
    Header header;
    std::vector<Question> questions;
    std::vector<Record> answers, authority, additional;
    struct Edns {
        std::uint16_t udp_payload_size;
        std::uint8_t extended_rcode, version;
        std::uint16_t flags;
        [[nodiscard]] bool dnssec_ok() const { return (flags & 0x8000u) != 0; }
    };
    std::optional<Edns> edns{};
    [[nodiscard]] std::uint16_t responseCode() const {
        return static_cast<std::uint16_t>(((edns ? edns->extended_rcode : 0) << 4) | header.rcode);
    }
};
}
