#include "dnsguard/DNSProxy.hpp"
#include "dnsguard/DNSParser.hpp"
#include "ParserInternal.hpp"
#include "DNSResponseCache.hpp"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <algorithm>
#include <cerrno>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <utility>

namespace dnsguard {
namespace {
using Clock = std::chrono::steady_clock;
#ifdef _WIN32
using Handle = SOCKET;
using Length = int;
using BufferLength = int;
constexpr Handle invalid = INVALID_SOCKET;
using Poll = WSAPOLLFD;
int pollSockets(Poll* p, unsigned count, int ms) { return WSAPoll(p,count,ms); }
void release(Handle h) { closesocket(h); }
struct Runtime {
    Runtime() { WSADATA data{}; if (WSAStartup(MAKEWORD(2,2),&data)) throw std::runtime_error("WSAStartup failed"); }
    ~Runtime() { WSACleanup(); }
};
#else
using Handle = int;
using Length = socklen_t;
using BufferLength = std::size_t;
constexpr Handle invalid = -1;
using Poll = pollfd;
int pollSockets(Poll* p, unsigned count, int ms) {
    const auto result = poll(p,count,ms);
    return result < 0 && errno == EINTR ? 0 : result;
}
void release(Handle h) { ::close(h); }
struct Runtime {};
#endif
struct Socket {
    Handle h = invalid;
    Socket() = default;
    explicit Socket(Handle value) : h(value) {}
    ~Socket() { if (h != invalid) release(h); }
    Socket(Socket&& other) noexcept : h(std::exchange(other.h,invalid)) {}
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            if (h != invalid) release(h);
            h = std::exchange(other.h,invalid);
        }
        return *this;
    }
    Socket(const Socket&) = delete;
};
void nonblocking(Handle h) {
#ifdef _WIN32
    u_long yes = 1;
    if (ioctlsocket(h,static_cast<long>(FIONBIO),&yes)) throw std::runtime_error("nonblocking socket failed");
#else
    if (fcntl(h,F_SETFL,O_NONBLOCK) == -1) throw std::runtime_error("nonblocking socket failed");
#endif
}
Socket makeSocket(int type, int family = AF_INET) {
    Socket s(::socket(family,type,0));
    if (s.h == invalid) throw std::runtime_error("socket creation failed");
    nonblocking(s.h);
    return s;
}
sockaddr_in address(const std::string& ip, std::uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET,ip.c_str(),&a.sin_addr) != 1) throw std::runtime_error("numeric IPv4 address required");
    return a;
}
bool ready(Handle h, short events, Clock::time_point end, std::stop_token stop) {
    while (!stop.stop_requested() && Clock::now() < end) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(end-Clock::now()).count();
        Poll p{h,events,0};
        const auto result = pollSockets(&p,1,static_cast<int>(std::clamp<decltype(left)>(left,1,50)));
        if (result > 0) return (p.revents & events) != 0;
        if (result < 0) return false;
    }
    return false;
}
bool connected(Handle h, const sockaddr_in& dest, Clock::time_point end, std::stop_token stop) {
    if (::connect(h,reinterpret_cast<const sockaddr*>(&dest),sizeof(dest)) == 0) return true;
    if (!ready(h,POLLOUT,end,stop)) return false;
    int error = 0;
    Length size = sizeof(error);
    return getsockopt(h,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&size) == 0 && !error;
}
bool transfer(Handle h, std::span<std::uint8_t> bytes, bool writing,
              Clock::time_point end, std::stop_token stop) {
    while (!bytes.empty()) {
        if (!ready(h,writing ? POLLOUT : POLLIN,end,stop)) return false;
#ifdef MSG_NOSIGNAL
        constexpr int flags = MSG_NOSIGNAL;
#else
        constexpr int flags = 0;
#endif
        const auto size = static_cast<BufferLength>(bytes.size());
        const auto n = writing ? ::send(h,reinterpret_cast<const char*>(bytes.data()),size,flags)
                               : ::recv(h,reinterpret_cast<char*>(bytes.data()),size,0);
        if (n <= 0) return false;
        bytes = bytes.subspan(static_cast<std::size_t>(n));
    }
    return true;
}
bool frame(Handle h, Bytes& data, bool writing, Clock::time_point end, std::stop_token stop) {
    std::array<std::uint8_t,2> prefix{
        static_cast<std::uint8_t>(data.size() >> 8),static_cast<std::uint8_t>(data.size())};
    if (!transfer(h,prefix,writing,end,stop)) return false;
    if (!writing) {
        const auto size = (static_cast<unsigned>(prefix[0]) << 8) | prefix[1];
        if (size < 12) return false;
        data.resize(size);
    }
    return transfer(h,data,writing,end,stop);
}
DNSMessage parse(const Bytes& p) {
    auto result = parseDNSMessageBounded(p,{}, {4096,4096});
    if (auto* message = std::get_if<DNSMessage>(&result)) return std::move(*message);
    throw std::runtime_error("invalid DNS message");
}
void setId(Bytes& p, std::uint16_t id) {
    p[0] = static_cast<std::uint8_t>(id >> 8); p[1] = static_cast<std::uint8_t>(id);
}
Bytes reply(const DNSMessage& query, unsigned code, bool truncated = false) {
    // Rebuild an uncompressed single question, avoiding pointers into omitted sections.
    const auto& q = query.questions[0];
    Bytes p(12+q.name.wire.size()+4,0);
    setId(p,query.header.id);
    p[2] = static_cast<std::uint8_t>(0x80 | (query.header.rd ? 1 : 0) | (truncated ? 2 : 0));
    p[3] = static_cast<std::uint8_t>(0x80 | (query.header.cd ? 0x10 : 0) | code);
    p[5] = 1;
    std::copy(q.name.wire.begin(),q.name.wire.end(),p.begin()+12);
    auto at = 12+q.name.wire.size();
    for (auto n : {q.type,q.qclass}) {
        p[at++] = static_cast<std::uint8_t>(n >> 8); p[at++] = static_cast<std::uint8_t>(n);
    }
    return p;
}
std::uint16_t randomId() {
    std::uint16_t id = 0;
#ifdef _WIN32
    if (BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&id),sizeof(id),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("secure random ID failed");
#else
    if (getrandom(&id,sizeof(id),0) != sizeof(id)) throw std::runtime_error("secure random ID failed");
#endif
    return id;
}
bool matches(const DNSMessage& query, const DNSMessage& response, std::uint16_t id) {
    return response.header.qr && response.header.id == id && response.header.opcode == 0 &&
        response.questions.size() == 1 && sameName(query.questions[0].name,response.questions[0].name) &&
        query.questions[0].type == response.questions[0].type &&
        query.questions[0].qclass == response.questions[0].qclass;
}
bool localAddress(const IPv4& ip) {
    const auto a=ip[0], b=ip[1];
    return a == 0 || a == 10 || a == 127 || a >= 224 ||
        (a == 100 && b >= 64 && b <= 127) || (a == 169 && b == 254) ||
        (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
        (a == 198 && (b == 18 || b == 19));
}
bool localAddress(const IPv6& ip) {
    if ((ip[0] & 0xfe) == 0xfc || (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) ||
        (std::all_of(ip.begin(),ip.end()-1,[](auto part) { return part == 0; }) && ip[15] <= 1))
        return true;
    return std::all_of(ip.begin(),ip.begin()+10,[](auto part) { return part == 0; }) &&
        ip[10] == 0xff && ip[11] == 0xff &&
        localAddress(IPv4{ip[12],ip[13],ip[14],ip[15]});
}
}

struct DNSProxy::Impl {
    struct Rules {
        bool enabled, subdomains;
        std::uint64_t generation;
        std::unordered_set<std::string> allowed, denied;

        static std::string key(const Name& name) {
            std::string value(name.wire.begin(),name.wire.end());
            for (auto& c : value)
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            return value;
        }
        static bool contains(const std::unordered_set<std::string>& set,
                             const std::string& name, bool subdomains) {
            if (set.contains(name)) return true;
            if (subdomains) {
                for (std::size_t offset = 0; offset < name.size() && name[offset] != 0;) {
                    offset += static_cast<std::size_t>(static_cast<unsigned char>(name[offset])) + 1;
                    if (set.contains(name.substr(offset))) return true;
                }
            }
            return false;
        }
        explicit Rules(DNSDomainListsConfig value, std::uint64_t version)
            : enabled(value.enabled), subdomains(value.include_subdomains), generation(version) {
            allowed.reserve(value.allowed.size());
            denied.reserve(value.denied.size());
            for (const auto& name : value.allowed) allowed.insert(key(name));
            for (const auto& name : value.denied) denied.insert(key(name));
        }
        bool rejects(const Name& name) const {
            if (!enabled) return false;
            const auto value = key(name);
            return !contains(allowed,value,subdomains) && contains(denied,value,subdomains);
        }
        bool allows(const Name& name) const {
            return enabled && contains(allowed,key(name),subdomains);
        }
    };
    Runtime runtime;
    ProxyConfig config;
    std::atomic<std::shared_ptr<const Rules>> active_rules;
    DNSResponseCache cache;
    std::uint64_t next_generation = 1;
    sockaddr_in upstream{}, secondary{};
    bool has_secondary = false;
    Socket udp, tcp, udp6, tcp6;
    struct Job {
        Bytes payload;
        sockaddr_storage client{};
        Length client_length{};
        Handle listener = invalid;
        Socket connection;
        Clock::time_point deadline;
    };
    std::mutex mutex;
    std::condition_variable changed;
    std::deque<Job> jobs;
    bool closing = false;
    std::atomic_flag started = ATOMIC_FLAG_INIT;
    std::vector<std::jthread> workers;

    explicit Impl(ProxyConfig value) : config(std::move(value)) {
        const auto local = address(config.listen_ipv4,config.listen_port);
        upstream = address(config.upstream_ipv4,config.upstream_port);
        if (!config.secondary_upstream_ipv4.empty()) {
            secondary = address(config.secondary_upstream_ipv4,config.secondary_upstream_port);
            has_secondary = true;
        }
        const auto upstream_ip = ntohl(upstream.sin_addr.s_addr);
        const auto secondary_ip = ntohl(secondary.sin_addr.s_addr);
        if ((ntohl(local.sin_addr.s_addr) >> 24) != 127 || !config.listen_port ||
            !config.upstream_port || !upstream_ip || (upstream_ip >> 24) >= 224 ||
            (upstream.sin_addr.s_addr == local.sin_addr.s_addr && upstream.sin_port == local.sin_port) ||
            (!has_secondary && config.secondary_upstream_port != 53) ||
            (has_secondary && (!config.secondary_upstream_port || !secondary_ip ||
             (secondary_ip >> 24) >= 224 ||
             (secondary.sin_addr.s_addr == local.sin_addr.s_addr && secondary.sin_port == local.sin_port) ||
             (secondary.sin_addr.s_addr == upstream.sin_addr.s_addr && secondary.sin_port == upstream.sin_port))) ||
            config.timeout_ms < 100 || config.timeout_ms > 10000 ||
            !config.workers || config.workers > 32 || !config.queue_capacity || config.queue_capacity > 256 ||
            validateDNSDomainListsConfig(config.lists))
            throw std::runtime_error("unsafe or invalid proxy configuration");
        active_rules.store(std::make_shared<const Rules>(std::move(config.lists),next_generation));
        udp = makeSocket(SOCK_DGRAM); tcp = makeSocket(SOCK_STREAM);
#ifdef _WIN32
        int exclusive = 1;
        for (auto h : {udp.h,tcp.h})
            if (setsockopt(h,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<char*>(&exclusive),sizeof(exclusive)))
                throw std::runtime_error("exclusive socket bind failed");
#endif
        for (auto h : {udp.h,tcp.h})
            if (::bind(h,reinterpret_cast<const sockaddr*>(&local),sizeof(local)))
                throw std::runtime_error("loopback port already in use or bind failed");
        if (::listen(tcp.h,static_cast<int>(config.queue_capacity))) throw std::runtime_error("listen failed");
        if (config.listen_ipv6_port) {
            sockaddr_in6 local6{};
            local6.sin6_family = AF_INET6;
            local6.sin6_port = htons(config.listen_ipv6_port);
            local6.sin6_addr = in6addr_loopback;
            udp6 = makeSocket(SOCK_DGRAM,AF_INET6);
            tcp6 = makeSocket(SOCK_STREAM,AF_INET6);
            int yes = 1;
            for (auto h : {udp6.h,tcp6.h}) {
                if (setsockopt(h,IPPROTO_IPV6,IPV6_V6ONLY,reinterpret_cast<char*>(&yes),sizeof(yes)))
                    throw std::runtime_error("IPv6-only socket failed");
#ifdef _WIN32
                if (setsockopt(h,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<char*>(&yes),sizeof(yes)))
                    throw std::runtime_error("exclusive IPv6 socket bind failed");
#endif
                if (::bind(h,reinterpret_cast<const sockaddr*>(&local6),sizeof(local6)))
                    throw std::runtime_error("IPv6 loopback port already in use or bind failed");
            }
            if (::listen(tcp6.h,static_cast<int>(config.queue_capacity)))
                throw std::runtime_error("IPv6 listen failed");
        }
    }
    Bytes exchange(Bytes query, const DNSMessage& message, bool use_tcp,
                   Clock::time_point end, std::stop_token stop,
                   const Rules& rules, const sockaddr_in& server) {
        const auto id = randomId();
        setId(query,id);
        Socket remote = makeSocket(use_tcp ? SOCK_STREAM : SOCK_DGRAM);
        if (!connected(remote.h,server,end,stop)) return {};
        Bytes answer;
        if (use_tcp) {
            if (!frame(remote.h,query,true,end,stop) || !frame(remote.h,answer,false,end,stop)) return {};
        } else {
            if (!ready(remote.h,POLLOUT,end,stop) ||
                ::send(remote.h,reinterpret_cast<const char*>(query.data()),static_cast<BufferLength>(query.size()),0)
                    != static_cast<int>(query.size()) || !ready(remote.h,POLLIN,end,stop)) return {};
            std::array<std::uint8_t,65536> received;
            const auto count = ::recv(remote.h,reinterpret_cast<char*>(received.data()),static_cast<BufferLength>(received.size()),0);
            if (count < 12 || count > 65535) return {};
            answer.assign(received.begin(),received.begin()+count);
            // A TC response may omit part of a section. Parse its question separately
            // and only retry TCP after validating its source, ID, opcode and question.
            if ((answer[2] & 2) != 0) {
                detail::Cursor cursor{answer,0,answer.size()};
                DNSMessage partial{};
                partial.header = detail::readHeader(cursor);
                if (partial.header.questions != 1) return {};
                detail::Names names{{},64,4096};
                partial.questions.push_back(detail::readQuestion(cursor,names));
                if (matches(message,partial,id))
                    return exchange(std::move(query),message,true,end,stop,rules,server);
                return {};
            }
        }
        const auto response = parse(answer);
        if (!matches(message,response,id)) return {};
        const Name* current = &message.questions[0].name;
        // Follow only the queried CNAME chain; cap work on cyclic or hostile answers.
        for (unsigned hop = 0; hop < 16; ++hop) {
            const auto record = std::find_if(response.answers.begin(),response.answers.end(),
                [&](const Record& rr) { return rr.type == 5 && rr.rrclass == message.questions[0].qclass &&
                    sameName(rr.owner,*current); });
            if (record == response.answers.end()) break;
            if (std::find_if(std::next(record),response.answers.end(),
                    [&](const Record& rr) { return rr.type == 5 && rr.rrclass == record->rrclass &&
                        sameName(rr.owner,record->owner); }) != response.answers.end())
                return reply(message,2);
            const auto* target = std::get_if<Name>(&record->data);
            if (!target) break;
            if (rules.rejects(*target)) return reply(message,5);
            if (sameName(*current,*target)) break;
            current = target;
            if (hop == 15) return reply(message,2);
        }
        if (config.rebind_protection && !rules.allows(message.questions[0].name)) {
            for (const auto& rr : response.answers) {
                if (rr.rrclass != 1 || !sameName(rr.owner,*current)) continue;
                if (const auto* ip = std::get_if<IPv4>(&rr.data); ip && localAddress(*ip))
                    return reply(message,5);
                if (const auto* ip = std::get_if<IPv6>(&rr.data); ip && localAddress(*ip))
                    return reply(message,5);
            }
        }
        setId(answer,message.header.id);
        return answer;
    }
    Bytes process(const Bytes& packet, bool use_tcp, Clock::time_point end, std::stop_token stop) {
        const auto query = parse(packet);
        const auto rules = active_rules.load();
        if (query.header.qr || query.header.opcode != 0 || query.questions.size() != 1 ||
            !query.answers.empty() || !query.authority.empty()) return {};
        if (query.questions[0].type == 251 || query.questions[0].type == 252 ||
            std::any_of(query.additional.begin(),query.additional.end(),
                        [](const Record& rr) { return rr.type == 249 || rr.type == 250; }))
            return reply(query,5); // Transfers and authenticated ID rewriting are unsupported.
        if (rules->rejects(query.questions[0].name)) return reply(query,5);
        const bool cacheable = !query.edns && query.additional.empty() &&
            query.questions[0].qclass == 1 &&
            (query.questions[0].type == 1 || query.questions[0].type == 28);
        if (cacheable)
            if (auto hit = cache.get(packet,rules->generation)) return std::move(*hit);
        try {
            const auto now = Clock::now();
            const auto first_end = has_secondary ? now + (end-now)/2 : end;
            auto result = exchange(packet,query,use_tcp,first_end,stop,*rules,upstream);
            if (result.empty() && has_secondary)
                result = exchange(packet,query,use_tcp,end,stop,*rules,secondary);
            if (result.empty()) return reply(query,2);
            const auto udp_limit = query.edns ? std::clamp<unsigned>(query.edns->udp_payload_size,512,4096) : 512u;
            if (!use_tcp && result.size() > udp_limit) return reply(query,0,true);
            if (cacheable) cache.put(packet,result,query,rules->generation);
            return result;
        } catch (const std::runtime_error&) { return reply(query,2); }
    }
    void work(std::stop_token stop) {
        for (;;) {
            Job job;
            {
                std::unique_lock lock(mutex);
                changed.wait(lock,[&] { return closing || !jobs.empty(); });
                if (closing) return;
                job = std::move(jobs.front()); jobs.pop_front();
            }
            try {
                if (job.connection.h != invalid) {
                    for (unsigned n=0; n<16 && !stop.stop_requested(); ++n) {
                        Bytes request;
                        if (!frame(job.connection.h,request,false,job.deadline,stop)) break;
                        auto answer = process(request,true,job.deadline,stop);
                        if (answer.empty() || !frame(job.connection.h,answer,true,job.deadline,stop)) break;
                    }
                } else {
                    auto answer = process(job.payload,false,job.deadline,stop);
                    if (!answer.empty() && !stop.stop_requested())
                        ::sendto(job.listener,reinterpret_cast<const char*>(answer.data()),static_cast<BufferLength>(answer.size()),0,
                                 reinterpret_cast<const sockaddr*>(&job.client),job.client_length);
                }
            } catch (const std::exception&) {
                // Malformed input, resource exhaustion or a peer disconnect ends this job.
            }
        }
    }
    void finish() {
        {
            std::lock_guard lock(mutex);
            closing = true; jobs.clear();
        }
        for (auto& worker : workers) worker.request_stop();
        changed.notify_all();
        workers.clear();
    }
    static std::optional<std::uint64_t> fileStamp(const std::filesystem::path& path) {
        if (path.empty()) return std::nullopt;
        std::ifstream file(path,std::ios::binary);
        if (!file) return std::nullopt;
        std::array<char,8192> buffer;
        std::uint64_t hash = 14695981039346656037ull;
        std::size_t total = 0;
        // Windows can give two quick replacements the same modification time.
        while (file.read(buffer.data(),static_cast<std::streamsize>(buffer.size())) || file.gcount()) {
            const auto count = static_cast<std::size_t>(file.gcount());
            if (count > 4*1024*1024 - total) return std::nullopt;
            total += count;
            for (std::size_t i = 0; i < count; ++i)
                hash = (hash ^ static_cast<unsigned char>(buffer[i])) * 1099511628211ull;
        }
        return file.eof() ? std::optional{hash} : std::nullopt;
    }
    void refreshLists(std::optional<std::uint64_t>& block_stamp,
                      std::optional<std::uint64_t>& allow_stamp,
                      std::optional<std::uint64_t>& feed_stamp) {
        if (config.config_path.empty() || (config.blocklist_path.empty() &&
            config.allowlist_path.empty() && config.feedlist_path.empty())) return;
        const auto block = fileStamp(config.blocklist_path), allow = fileStamp(config.allowlist_path);
        const auto feed = fileStamp(config.feedlist_path);
        if (block == block_stamp && allow == allow_stamp && feed == feed_stamp) return;
        block_stamp = block;
        allow_stamp = allow;
        feed_stamp = feed;
        try {
            auto fresh = loadProxyConfig(config.config_path);
            if (fresh.blocklist_path != config.blocklist_path || fresh.allowlist_path != config.allowlist_path ||
                fresh.feedlist_path != config.feedlist_path ||
                fresh.listen_ipv4 != config.listen_ipv4 || fresh.listen_port != config.listen_port ||
                fresh.listen_ipv6_port != config.listen_ipv6_port || fresh.upstream_ipv4 != config.upstream_ipv4 ||
                fresh.upstream_port != config.upstream_port ||
                fresh.secondary_upstream_ipv4 != config.secondary_upstream_ipv4 ||
                fresh.secondary_upstream_port != config.secondary_upstream_port ||
                fresh.rebind_protection != config.rebind_protection ||
                fresh.timeout_ms != config.timeout_ms ||
                fresh.workers != config.workers || fresh.queue_capacity != config.queue_capacity)
                throw std::runtime_error("restart required for non-list configuration changes");
            active_rules.store(std::make_shared<const Rules>(std::move(fresh.lists),++next_generation));
        } catch (const std::exception& error) {
            std::cerr << "DNS list reload rejected: " << error.what() << '\n';
        }
    }
    void run(std::stop_token stop) {
        if (started.test_and_set()) throw std::logic_error("DNSProxy run may only be called once");
        try {
            // One bounded receive area; queued jobs own only their actual payload.
            std::array<std::uint8_t,65536> received;
            for (unsigned i=0;i<config.workers;++i)
                workers.emplace_back([this](std::stop_token token) { work(token); });
            std::optional<std::uint64_t> block_stamp, allow_stamp, feed_stamp;
            auto next_reload = Clock::time_point::min();
            while (!stop.stop_requested()) {
                if (Clock::now() >= next_reload) {
                    refreshLists(block_stamp,allow_stamp,feed_stamp);
                    next_reload = Clock::now() + std::chrono::seconds(1);
                }
                std::array<Poll,4> listeners{{{udp.h,POLLIN,0},{tcp.h,POLLIN,0},
                                              {udp6.h,POLLIN,0},{tcp6.h,POLLIN,0}}};
                const unsigned listener_count = config.listen_ipv6_port ? 4u : 2u;
                const auto count = pollSockets(listeners.data(),listener_count,50);
                if (count < 0) throw std::runtime_error("listener polling failed");
                for (unsigned i=0;i<listener_count;++i) {
                    if (!(listeners[i].revents & POLLIN)) continue;
                    Job job;
                    job.deadline = Clock::now()+std::chrono::milliseconds(config.timeout_ms);
                    job.client_length = sizeof(job.client);
                    if (i % 2 == 0) {
                        job.listener = listeners[i].fd;
                        const auto n = ::recvfrom(job.listener,reinterpret_cast<char*>(received.data()),
                            static_cast<BufferLength>(received.size()),0,reinterpret_cast<sockaddr*>(&job.client),&job.client_length);
                        if (n < 12 || n > 65535) continue;
                        job.payload.assign(received.begin(),received.begin()+n);
                    } else {
                        job.connection = Socket(::accept(listeners[i].fd,reinterpret_cast<sockaddr*>(&job.client),&job.client_length));
                        if (job.connection.h == invalid) continue;
                        nonblocking(job.connection.h);
                    }
                    const bool loopback = job.client.ss_family == AF_INET
                        ? (ntohl(reinterpret_cast<const sockaddr_in*>(&job.client)->sin_addr.s_addr) >> 24) == 127
                        : job.client.ss_family == AF_INET6 &&
                          IN6_IS_ADDR_LOOPBACK(&reinterpret_cast<const sockaddr_in6*>(&job.client)->sin6_addr);
                    if (!loopback) continue;
                    {
                        std::lock_guard lock(mutex);
                        if (jobs.size() >= config.queue_capacity) continue;
                        jobs.push_back(std::move(job));
                    }
                    changed.notify_one();
                }
            }
        } catch (...) { finish(); throw; }
        finish();
    }
};
DNSProxy::DNSProxy(ProxyConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {}
DNSProxy::~DNSProxy() = default;
void DNSProxy::run(std::stop_token stop) { impl_->run(stop); }
DNSCacheStats DNSProxy::cacheStats() const {
    const auto value = impl_->cache.stats();
    return {value.hits,value.misses,value.entries};
}
}
