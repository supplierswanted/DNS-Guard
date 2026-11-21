#include "dnsguard/DNSMessage.hpp"
#include <algorithm>

namespace dnsguard {
namespace {
bool wellFormed(const Bytes& wire) noexcept {
    if (wire.size() > 255) return false;
    for (std::size_t pos = 0; pos < wire.size();) {
        const auto size = wire[pos++];
        if (!size) return pos == wire.size();
        if (size > 63 || size > wire.size() - pos) return false;
        pos += size;
    }
    return false;
}
}

bool sameName(const Name& a, const Name& b) noexcept {
    // Valid length octets are below 'A', so folding the whole sequence
    // preserves both label boundaries and every non-ASCII octet.
    auto fold = [](unsigned c) { return c >= 65 && c <= 90 ? c + 32 : c; };
    return a.wire.size() == b.wire.size() && wellFormed(a.wire) && wellFormed(b.wire)
        && std::equal(a.wire.begin(), a.wire.end(), b.wire.begin(),
                      [&](auto x, auto y) { return fold(x) == fold(y); });
}

std::optional<std::string> displayName(const Name& name) {
    if (!wellFormed(name.wire)) return std::nullopt;
    std::string out;
    for (std::size_t pos = 0; name.wire[pos] != 0;) {
        const auto count = name.wire[pos++];
        for (unsigned i = 0; i < count; ++i) {
            const unsigned c = name.wire[pos++];
            if (c < 33 || c > 126) {
                out.push_back('\\');
                for (auto divisor : {100u, 10u, 1u})
                    out.push_back(static_cast<char>('0' + c / divisor % 10));
            } else {
                if (c == '.' || c == '\\' || c == '"' || c == '(' ||
                    c == ')' || c == ';' || c == '@' || c == '$') {
                    out.push_back('\\');
                }
                out.push_back(static_cast<char>(c));
            }
        }
        out.push_back('.');
    }
    if (out.empty()) out.push_back('.');
    return out;
}
}
