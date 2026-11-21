#include "dnsguard/DNSTrafficCollector.hpp"
#include <cstdlib>
#include <iostream>
#include <new>

// Isolated executable: fail exactly one ordinary allocation, then restore.
namespace { thread_local int fail_after = -1; }
void* operator new(std::size_t size) {
    if (fail_after == 0) {
        fail_after = -1;
        throw std::bad_alloc{};
    }
    if (fail_after > 0) --fail_after;
    if (auto* p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void* operator new[](std::size_t n) { return ::operator new(n); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

int main() {
    using namespace dnsguard;
    DNSMessage response{};
    response.header.qr = true;
    response.questions.push_back({Name{{1,'a',0}},1,1});
    response.answers.push_back({Name{{1,'a',0}},1,1,60,4,IPv4{192,0,2,1}});
    unsigned failures = 0;
    for (int position = 0; position < 12; ++position) {
        DNSTrafficCollector collector;
        if (!collector.cacheResponse(response)) return 1;
        auto replacement = response;
        replacement.answers[0].data = IPv4{192,0,2,2};
        fail_after = position;
        bool saved = false;
        try { saved = collector.cacheResponse(replacement); }
        catch (...) { fail_after = -1; return 2; }
        fail_after = -1;
        auto found = collector.lookup(response.questions[0]);
        if (!found || found->size() != 1) return 3;
        const auto expected = saved ? IPv4{192,0,2,2} : IPv4{192,0,2,1};
        if (std::get<IPv4>(found->front().data) != expected) return 4;
        failures += !saved;
    }
    if (!failures) return 5;
    std::cout << "Cache allocation failures handled: " << failures << '\n';
}
