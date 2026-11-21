#include "dnsguard/DNSParser.hpp"
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto result = dnsguard::parseDNSMessage({data, size});
    if (auto* msg = std::get_if<dnsguard::DNSMessage>(&result)) {
        if (msg->questions.size() != msg->header.questions ||
            msg->answers.size() != msg->header.answers ||
            msg->authority.size() != msg->header.authority ||
            msg->additional.size() != msg->header.additional) std::abort();
    } else if (std::get<dnsguard::ParseError>(result).offset > size) {
        std::abort();
    }
    return 0;
}
