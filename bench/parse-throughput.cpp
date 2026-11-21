// Single-thread, in-memory replay. Usage: bench tests/fixtures/resolver-dns.hex
#include "dnsguard/DNSParser.hpp"
#include <array>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace dnsguard;
using Clock = std::chrono::steady_clock;

namespace {
std::vector<Bytes> load(const char* path) {
    std::ifstream input(path);
    std::vector<Bytes> packets;
    for (std::string line; std::getline(input, line);) {
        std::istringstream row(line);
        std::string offset;
        if (!(row >> offset)) continue;
        if (offset != "0000") throw std::runtime_error("unexpected fixture offset");
        auto& packet = packets.emplace_back();
        unsigned octet;
        while (row >> std::hex >> octet) {
            if (octet > 255) throw std::runtime_error("invalid octet");
            packet.push_back(static_cast<std::uint8_t>(octet));
        }
        if (!row.eof()) throw std::runtime_error("invalid fixture");
    }
    if (packets.size() != 6) throw std::runtime_error("expected six fixture messages");
    return packets;
}

Bytes compressed() {
    Bytes p{0,1,0x81,0x80,0,1,0,128,0,0,0,0,7,'e','x','a','m','p','l','e',0,0,1,0,1};
    for (unsigned i = 0; i < 128; ++i)
        p.insert(p.end(), {0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,static_cast<std::uint8_t>(i)});
    return p;
}

Bytes largeTxt() {
    // One root-owned TXT RR, 240 strings of 255 bytes each.
    Bytes p{0,1,0x81,0x80,0,0,0,1,0,0,0,0,0,0,16,0,1,0,0,0,60,0xf0,0};
    for (unsigned i = 0; i < 240; ++i) {
        p.push_back(255);
        p.insert(p.end(), 255, 'x');
    }
    return p;
}

void window(const std::vector<Bytes>& packets, std::span<const unsigned> sequence,
            const char* name, unsigned index, double seconds) {
    const auto start = Clock::now();
    std::uint64_t messages = 0;
    double elapsed;
    do {
        for (unsigned batch = 0; batch < 32; ++batch)
            for (auto i : sequence) {
                auto result = parseDNSMessage(packets[i]);
                if (!std::holds_alternative<DNSMessage>(result))
                    throw std::runtime_error("benchmark input rejected");
            }
        messages += 32 * sequence.size();
        elapsed = std::chrono::duration<double>(Clock::now() - start).count();
    } while (elapsed < seconds);
    if (index)
        std::cout << name << ',' << index << ',' << messages << ',' << elapsed << ','
                  << static_cast<std::uint64_t>(static_cast<double>(messages)/elapsed) << std::endl;
}
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    auto packets = load(argv[1]);
    packets.push_back(compressed());
    packets.push_back(largeTxt());
    std::cerr << "message sizes:";
    for (const auto& p : packets) std::cerr << ' ' << p.size();
    std::cerr << '\n';
    const std::array<unsigned,6> real{0,1,2,3,4,5};
    const std::array<unsigned,1> rr{6}, txt{7};
    const std::array<unsigned,8> mixed{0,1,2,3,4,5,6,7};
    std::cout << "workload,window,messages,seconds,messages_per_second\n";
    window(packets,mixed,"warmup",0,1);
    for (unsigned i=1; i<=5; ++i) {
        window(packets,real,"small",i,1);
        window(packets,rr,"compressed",i,1);
        window(packets,txt,"txt",i,1);
    }
    for (unsigned i=1; i<=6; ++i) window(packets,real,"small_sustained",i,10);
    for (unsigned i=1; i<=6; ++i) window(packets,mixed,"mixed_sustained",i,10);
}
