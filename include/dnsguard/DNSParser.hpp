#pragma once
#include "DNSErrors.hpp"
#include "DNSMessage.hpp"
#include <span>

namespace dnsguard {
struct ParseLimits {
    std::size_t message_bytes = 65535;
    std::size_t questions = 64;
    std::size_t records = 2048; // Combined across all three RR sections.
    std::size_t pointer_hops = 64; // Per expanded name.
};
using DNSParseResult = std::variant<DNSMessage, ParseError>;
[[nodiscard]] DNSParseResult parseDNSMessage(std::span<const std::uint8_t> packet,
                                            ParseLimits limits = {});
// Totals across one complete message. Callers choose limits for their workload.
struct MessageBudget {
    std::size_t pointer_hops = 0;
    std::size_t txt_strings = 0;
};
[[nodiscard]] DNSParseResult parseDNSMessageBounded(std::span<const std::uint8_t> packet,
                                                    ParseLimits limits, MessageBudget budget);
}
