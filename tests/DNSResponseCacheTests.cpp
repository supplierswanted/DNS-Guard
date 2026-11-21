#include "DNSResponseCache.hpp"
#include "dnsguard/DNSParser.hpp"
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace dnsguard;
static void check(bool value) {
    if (!value) { std::cerr << "cache test failed\n"; std::exit(1); }
}
static void u32(Bytes& p, std::uint32_t n) {
    for (int shift : {24,16,8,0}) p.push_back(static_cast<std::uint8_t>(n >> shift));
}
static Bytes query(std::uint16_t id) {
    return {static_cast<std::uint8_t>(id >> 8),static_cast<std::uint8_t>(id),1,0,
            0,1,0,0,0,0,0,0,5,'c','a','c','h','e',7,'e','x','a','m','p','l','e',0,0,1,0,1};
}
static Bytes positive(Bytes q) {
    q[2]=0x81; q[3]=0x80; q[7]=1;
    q.insert(q.end(),{0xc0,12,0,1,0,1}); u32(q,2);
    q.insert(q.end(),{0,4,1,2,3,4});
    return q;
}
static Bytes negative(Bytes q) {
    q[2]=0x81; q[3]=0x83; q[9]=1;
    q.insert(q.end(),{0xc0,12,0,6,0,1}); u32(q,9);
    q.insert(q.end(),{0,24,0xc0,12,0xc0,12});
    for (int i=0;i<4;++i) u32(q,0);
    u32(q,2);
    return q;
}
int main() {
    DNSResponseCache cache;
    const auto first=query(0x1234), next=query(0xabcd);
    const auto parsed=std::get<DNSMessage>(parseDNSMessage(first));
    cache.put(first,positive(first),parsed,1);
    auto hit=cache.get(next,1);
    check(hit && (*hit)[0]==0xab && (*hit)[1]==0xcd);
    check(std::get<DNSMessage>(parseDNSMessage(*hit)).answers[0].ttl == 2);
    check(!cache.get(next,2)); // New policy cannot use an old answer.
    std::this_thread::sleep_for(std::chrono::milliseconds(2100));
    check(!cache.get(next,1));
    cache.put(first,negative(first),parsed,3);
    hit=cache.get(next,3);
    check(hit && ((*hit)[3]&15)==3);
    check(std::get<DNSMessage>(parseDNSMessage(*hit)).authority[0].ttl == 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(2100));
    check(!cache.get(next,3));
    auto zero=positive(first);
    for (std::size_t i=zero.size()-10;i<zero.size()-6;++i) zero[i]=0;
    cache.put(first,zero,parsed,4);
    check(!cache.get(next,4));
    for (int n=0;n<300;++n) {
        auto distinct=query(0x1234);
        distinct[13]=static_cast<std::uint8_t>('a'+n/26);
        distinct[14]=static_cast<std::uint8_t>('a'+n%26);
        cache.put(distinct,positive(distinct),
                  std::get<DNSMessage>(parseDNSMessage(distinct)),5);
    }
    check(cache.stats().entries == 256);
    auto oldest=query(0x1234);
    oldest[13]='a'; oldest[14]='a';
    check(!cache.get(oldest,5));
    std::atomic<bool> invalid=false;
    std::vector<std::thread> workers;
    for (int worker=0;worker<4;++worker) workers.emplace_back([&] {
        for (int i=0;i<1000;++i) {
            cache.put(first,positive(first),parsed,6);
            if (auto answer=cache.get(next,6); answer &&
                !std::holds_alternative<DNSMessage>(parseDNSMessage(*answer))) invalid=true;
        }
    });
    for (auto& worker:workers) worker.join();
    check(!invalid && cache.stats().entries <= 256 && cache.stats().hits > 0);
}
