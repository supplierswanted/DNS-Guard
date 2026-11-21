// Profiling-only host. Start with config, send requests, then newline on stdin.
#include "dnsguard/DNSProxy.hpp"
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <new>
#include <thread>

namespace {
std::atomic<std::uint64_t> allocations{0}, requested_bytes{0}, large_buffers{0};
std::atomic<bool> measure{false};
}
void* operator new(std::size_t size) {
    if (measure.load(std::memory_order_relaxed)) {
        allocations.fetch_add(1,std::memory_order_relaxed);
        requested_bytes.fetch_add(size,std::memory_order_relaxed);
        if (size == 65536) large_buffers.fetch_add(1,std::memory_order_relaxed);
    }
    if (auto* p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    try {
        dnsguard::DNSProxy proxy(dnsguard::loadProxyConfig(argv[1]));
        std::exception_ptr error;
        std::jthread worker([&](std::stop_token stop) {
            try { proxy.run(stop); } catch (...) { error = std::current_exception(); }
        });
        // All startup costs precede measurement.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        measure.store(true);
        std::cout << "READY" << std::endl;
        std::cin.get();
        worker.request_stop(); worker.join();
        measure.store(false);
        if (error) std::rethrow_exception(error);
        std::cout << "allocations=" << allocations.load() << " requested_bytes="
                  << requested_bytes.load() << " buffers_65536=" << large_buffers.load() << '\n';
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
