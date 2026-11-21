// In-memory component costs; allocation bytes are requested totals, not RSS.
#include "dnsguard/DNSDomainLists.hpp"
#include "dnsguard/DNSQueryRateMonitor.hpp"
#include <atomic>
#include <barrier>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
std::atomic<bool> counting{false};
std::atomic<std::uint64_t> allocations{0}, requested_bytes{0};
std::uint64_t checksum = 0;
using Clock = std::chrono::steady_clock;
}

// Replacement is confined to this executable. Current public data structures
// use ordinary allocations; these counters do not track allocator metadata.
void* operator new(std::size_t bytes) {
    if (void* p = std::malloc(bytes ? bytes : 1)) {
        if (counting.load(std::memory_order_relaxed)) {
            allocations.fetch_add(1, std::memory_order_relaxed);
            requested_bytes.fetch_add(bytes, std::memory_order_relaxed);
        }
        return p;
    }
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void* operator new[](std::size_t bytes) { return ::operator new(bytes); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

namespace {
using namespace dnsguard;
void require(bool condition) {
    if (!condition) throw std::runtime_error("benchmark output check failed");
}
Name name(unsigned key) {
    // Equal-width names make comparisons consistent across last-hit and miss.
    std::string label("q");
    label.append(std::to_string(100000u + key));
    Bytes wire{static_cast<std::uint8_t>(label.size())};
    wire.insert(wire.end(), label.begin(), label.end());
    wire.push_back(0);
    return Name{std::move(wire)};
}
DNSQueryObservation observation(unsigned key) {
    return {name(key),1,1,{},DNSTransport::udp,{IPv4{192,0,2,1},12345}};
}
void beginCounts() {
    allocations.store(0, std::memory_order_relaxed);
    requested_bytes.store(0, std::memory_order_relaxed);
    counting.store(true, std::memory_order_relaxed);
}
void report(const std::string& label, unsigned run, std::uint64_t ops, Clock::time_point start) {
    const auto elapsed = std::chrono::duration<double,std::nano>(Clock::now()-start).count();
    counting.store(false, std::memory_order_relaxed);
    const double n = static_cast<double>(ops);
    std::cout << label << ',' << run << ',' << ops << ',' << elapsed/n << ','
              << static_cast<double>(allocations.load())/n << ','
              << static_cast<double>(requested_bytes.load())/n << '\n';
}
template<class Work>
void measure(const std::string& label, unsigned run, unsigned ops, Work work) {
    beginCounts();
    const auto start = Clock::now();
    std::uint64_t successes = 0;
    for (unsigned i=0; i<ops; ++i) successes += work(i);
    report(label,run,ops,start);
    require(successes == ops);
    checksum += successes;
}

void lists(unsigned run) {
    for (unsigned size : {0u,64u,4096u,10728u}) {
        DNSDomainListsConfig config;
        config.enabled = true;
        config.include_subdomains = true;
        for (unsigned i=0; i<size; ++i) config.denied.push_back(name(i));
        require(!validateDNSDomainListsConfig(config));
        const auto hit = observation(size ? size-1 : 0);
        const auto miss = observation(50000);
        const std::string label = "list_" + std::to_string(size);
        measure(label+"_hitlast",run,2000,[&](unsigned) {
            auto result = evaluateDNSDomainLists(hit,config);
            const auto* value = std::get_if<DNSDomainListAssessment>(&result);
            return value && value->denied.has_value() == (size != 0);
        });
        measure(label+"_miss",run,2000,[&](unsigned) {
            auto result = evaluateDNSDomainLists(miss,config);
            const auto* value = std::get_if<DNSDomainListAssessment>(&result);
            return value && !value->denied;
        });
    }
}

void cache(unsigned run) {
    DNSTrafficCollector collector;
    DNSMessage response{};
    response.header.qr = true;
    response.header.flags = 0x8180;
    response.header.questions = response.header.answers = 1;
    response.questions.push_back({name(0),1,1});
    response.answers.push_back({name(0),1,1,60,4,IPv4{192,0,2,1}});
    for (unsigned i=0; i<1024; ++i) {
        response.questions[0].name = response.answers[0].owner = name(i);
        require(collector.cacheResponse(response));
    }
    const Question hit{name(1023),1,1}, miss{name(10000),1,1};
    measure("cache_1024_hitlast",run,2000,[&](unsigned) {
        auto result = collector.lookup(hit);
        return result && result->size() == 1 &&
            std::get<IPv4>(result->front().data) == IPv4{192,0,2,1};
    });
    measure("cache_1024_miss",run,2000,[&](unsigned) { return !collector.lookup(miss); });
}

void sequentialQueue(unsigned run) {
    DNSTrafficCollector collector;
    const Bytes payload(128,42);
    DNSCaptureMetadata metadata{};
    measure("collector_ingest_pop_pair",run,10000,[&](unsigned) {
        if (collector.ingest(payload,metadata) != EnqueueStatus::queued) return false;
        auto result = collector.tryPop();
        return result && result->payload == payload;
    });
}

bool validRate(const DNSQueryRateResult& result) {
    return std::get_if<std::optional<DNSQueryRateAssessment>>(&result) != nullptr;
}
DNSQueryRateConfig rateConfig() {
    DNSQueryRateConfig config;
    config.enabled = true;
    config.query_threshold = std::numeric_limits<std::size_t>::max();
    return config;
}
void rate(unsigned run) {
    DNSQueryRateMonitor monitor(rateConfig());
    for (unsigned i=0; i<4096; ++i) require(validRate(monitor.observe(observation(i))));
    const auto hit = observation(4095);
    measure("rate_4096_hitlast",run,2000,[&](unsigned) { return validRate(monitor.observe(hit)); });
    std::vector<DNSQueryObservation> misses;
    for (unsigned i=0; i<1000; ++i) misses.push_back(observation(4096+i));
    measure("rate_4096_miss",run,1000,[&](unsigned i) { return validRate(monitor.observe(misses[i])); });
}

void concurrentQueue(unsigned run) {
    DNSTrafficCollector collector;
    const Bytes payload(128,42);
    const DNSCaptureMetadata metadata{};
    std::atomic<std::uint64_t> accepted{0}, popped{0}, bad{0};
    std::barrier gate(6); // Four producers, one consumer, and the timer.
    std::vector<std::jthread> producers;
    for (unsigned producer=0; producer<4; ++producer) {
        producers.emplace_back([&] {
            gate.arrive_and_wait();
            std::uint64_t local = 0;
            for (unsigned i=0; i<2000; ++i) {
                const auto result = collector.ingest(payload,metadata);
                if (result == EnqueueStatus::queued) ++local;
                else if (result != EnqueueStatus::queue_full) ++bad;
            }
            accepted += local;
        });
    }
    std::jthread consumer([&] {
        gate.arrive_and_wait();
        while (auto packet = collector.waitPop()) {
            if (packet->payload != payload) ++bad;
            ++popped;
        }
    });
    beginCounts();
    const auto start = Clock::now();
    gate.arrive_and_wait();
    for (auto& producer : producers) producer.join();
    collector.close();
    consumer.join();
    report("collector_4producers_1consumer_attempt",run,8000,start);
    require(!bad && accepted == popped && accepted+collector.droppedCount() == 8000);
    checksum += accepted.load();
    std::cerr << "queue_run=" << run << " accepted=" << accepted << " dropped=" << collector.droppedCount() << '\n';
}

void concurrentRate(unsigned run) {
    DNSQueryRateMonitor monitor(rateConfig());
    for (unsigned i=0; i<4096; ++i) require(validRate(monitor.observe(observation(i))));
    const auto hit = observation(4095);
    std::barrier gate(5);
    std::atomic<std::uint64_t> successes{0};
    std::vector<std::jthread> workers;
    for (unsigned worker=0; worker<4; ++worker) {
        workers.emplace_back([&] {
            gate.arrive_and_wait();
            std::uint64_t local = 0;
            for (unsigned i=0; i<1000; ++i) local += validRate(monitor.observe(hit));
            successes += local;
        });
    }
    beginCounts();
    const auto start = Clock::now();
    gate.arrive_and_wait();
    for (auto& worker : workers) worker.join();
    report("rate_4096_concurrent4_hitlast",run,4000,start);
    require(successes == 4000);
    checksum += successes.load();
}
}

int main() {
    try {
        std::cout << std::fixed << std::setprecision(3)
                  << "name,run,ops,ns_per_op,allocs_per_op,bytes_per_op\n";
        for (unsigned run=1; run<=5; ++run) {
            lists(run);
            cache(run);
            sequentialQueue(run);
            rate(run);
            concurrentQueue(run);
            concurrentRate(run);
        }
        std::cerr << "verified_checksum=" << checksum << '\n';
    } catch (const std::exception& error) {
        counting.store(false);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
