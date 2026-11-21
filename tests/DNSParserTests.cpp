#include "dnsguard/DNSParser.hpp"
#include "dnsguard/DNSDomainLists.hpp"
#include "dnsguard/DNSLabelHeuristic.hpp"
#include "dnsguard/DNSQueryRateMonitor.hpp"
#include "dnsguard/DNSTrafficCollector.hpp"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace dnsguard;
namespace {
#define CHECK(expr) do { if (!(expr)) throw std::runtime_error(#expr); } while (false)
void append(Bytes& out, const Bytes& tail) { out.insert(out.end(), tail.begin(), tail.end()); }
void word(Bytes& out, unsigned value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}
Bytes header(unsigned q, unsigned a, unsigned ns = 0, unsigned ar = 0) {
    Bytes out{0x12,0x34,0x81,0x80};
    for (auto count : {q,a,ns,ar}) word(out, count);
    return out;
}
Bytes queryHeader(unsigned q) {
    auto out = header(q,0);
    out[2] = 0x01;
    out[3] = 0x00;
    return out;
}
const Bytes domain{3,'W','w','w',7,'e','x','a','m','p','l','e',0};
void question(Bytes& p, const Bytes& name, unsigned type = 1) {
    append(p,name);
    word(p,type);
    word(p,1);
}
void record(Bytes& p, unsigned type, const Bytes& data, const Bytes& owner = {0}, unsigned cls = 1) {
    append(p,owner);
    word(p,type);
    word(p,cls);
    append(p,{0xfe,0xdc,0xba,0x98});
    word(p,static_cast<unsigned>(data.size()));
    append(p,data);
}
DNSMessage valid(const Bytes& p, ParseLimits limits = {}) {
    auto r = parseDNSMessage(p,limits);
    CHECK(std::holds_alternative<DNSMessage>(r));
    return std::get<DNSMessage>(std::move(r));
}
void errorNames() {
    CHECK(errorCodeName(ErrorCode::truncated) == "truncated");
    CHECK(errorCodeName(ErrorCode::invalid_label) == "invalid_label");
    CHECK(errorCodeName(ErrorCode::invalid_pointer) == "invalid_pointer");
    CHECK(errorCodeName(ErrorCode::name_too_long) == "name_too_long");
    CHECK(errorCodeName(ErrorCode::invalid_rdata) == "invalid_rdata");
    CHECK(errorCodeName(ErrorCode::resource_limit) == "resource_limit");
    CHECK(errorCodeName(ErrorCode::trailing_data) == "trailing_data");
    CHECK(errorCodeName(ErrorCode::allocation_failure) == "allocation_failure");
    CHECK(errorCodeName(ErrorCode::invalid_header) == "invalid_header");
}
ParseError invalid(const Bytes& p, ErrorCode code, ParseLimits limits = {}) {
    auto r = parseDNSMessage(p,limits);
    CHECK(std::holds_alternative<ParseError>(r));
    auto e = std::get<ParseError>(r);
    CHECK(e.code == code && e.offset <= p.size());
    return e;
}
void headers() {
    auto p = header(1,0);
    p[2] = 1; p[3] = 0;
    question(p,domain,65000);
    auto m = valid(p);
    CHECK(m.header.id == 0x1234 && m.header.flags == 0x0100 && !m.header.qr && m.header.rd);
    CHECK(m.questions.size() == 1 && m.questions[0].type == 65000 && m.questions[0].qclass == 1);
    CHECK(m.questions[0].name.wire == domain);
    p[2] = 0xaf; p[3] = 0xb3;
    auto h = valid(p).header;
    CHECK(h.qr && h.opcode == 5 && h.aa && h.tc && h.rd && h.ra && h.ad && h.cd && h.rcode == 3);
    auto reserved_flag = header(0,0);
    reserved_flag[3] |= 0x40;
    CHECK(invalid(reserved_flag, ErrorCode::invalid_header).offset == 2);
    for (std::size_t n = 0; n < 12; ++n)
        invalid(Bytes(n,0),ErrorCode::truncated);
}
void names() {
    CHECK(displayName(Name{{0}}) == ".");
    CHECK(displayName(Name{domain}) == "Www.example.");
    CHECK(displayName(Name{{5,'.','\\',0,10,255,0}}) == R"(\.\\\000\010\255.)");
    CHECK(displayName(Name{{7,'a','"','(',')',';','@','$',0}}) ==
          "a\\\"\\(\\)\\;\\@\\$.");
    CHECK(sameName(Name{{1,'X',0}}, Name{{1,'x',0}}));
    CHECK(!sameName(Name{{3,'a','.','b',0}}, Name{{1,'a',1,'b',0}}));
    CHECK(!sameName(Name{{1,0xe0,0}}, Name{{1,0xc0,0}}));
    for (const auto& bad : std::vector<Bytes>{{}, {0,1}, {2,'x'}, {64,0}, {1,'a'}}) {
        CHECK(!displayName(Name{bad}));
        CHECK(!sameName(Name{bad}, Name{bad}));
    }
    auto p = header(3,0);
    question(p,{3,0,'.',255,0});
    question(p,{1,'Z',0xc0,12});
    question(p,{0xc0,23}); // Pointer to the pointer in question two.
    auto m = valid(p);
    CHECK(m.questions[1].name.wire == Bytes({1,'Z',3,0,'.',255,0}));
    CHECK(m.questions[2].name.wire == m.questions[0].name.wire);
    ParseLimits l;
    l.pointer_hops = 1;
    invalid(p,ErrorCode::resource_limit,l);
    for (auto target : {0,12,13,250}) {
        auto bad = header(2,0);
        question(bad,{2,0,0,0});
        // Header, self, interior, and outside respectively.
        question(bad,{0xc0,static_cast<std::uint8_t>(target == 12 ? 20 : target)});
        invalid(bad,ErrorCode::invalid_pointer);
    }
    auto loop = header(1,0);
    question(loop,{1,'x',0xc0,12});
    invalid(loop,ErrorCode::invalid_pointer);
    auto suffix = header(2,0);
    question(suffix,domain);
    question(suffix,{0xc0,16});
    CHECK(valid(suffix).questions[1].name.wire == Bytes({7,'e','x','a','m','p','l','e',0}));
    auto forward = header(1,0);
    question(forward,{0xc0,15});
    invalid(forward,ErrorCode::invalid_pointer);
    for (auto tag : {64,128}) {
        auto bad = header(1,0);
        question(bad,{static_cast<std::uint8_t>(tag)});
        CHECK(invalid(bad,ErrorCode::invalid_label).offset == 12);
    }
    auto truncated = header(1,0);
    append(truncated,{10,1,2,3,4});
    invalid(truncated,ErrorCode::truncated);
    Bytes longest;
    for (auto n : {63,63,63,61}) {
        longest.push_back(static_cast<std::uint8_t>(n));
        longest.insert(longest.end(),static_cast<std::size_t>(n),'a');
    }
    longest.push_back(0);
    auto max = header(1,0);
    question(max,longest);
    CHECK(valid(max).questions[0].name.wire.size() == 255);
    auto compressed = header(2,0);
    question(compressed,longest);
    const auto second = compressed.size();
    question(compressed,{0xc0,12});
    CHECK(valid(compressed).questions[1].name.wire == longest);
    compressed.resize(second);
    question(compressed,{1,'x',0xc0,12});
    invalid(compressed,ErrorCode::name_too_long);
    longest[192] = 62;
    longest.insert(longest.end()-1,'a');
    auto too_long = header(1,0);
    question(too_long,longest);
    invalid(too_long,ErrorCode::name_too_long);
}
void records() {
    auto p = header(1,5,2,2);
    question(p,domain);
    const Bytes ptr{0xc0,12};
    record(p,1,{192,0,2,1},ptr);
    Bytes ipv6(16,0); ipv6.front() = 0x20; ipv6.back() = 1;
    record(p,28,ipv6,ptr);
    record(p,5,ptr,ptr);
    record(p,12,ptr,ptr);
    record(p,15,{0x12,0x34,0xc0,12},ptr);
    record(p,2,ptr,ptr);
    Bytes soa{0xc0,12,0xc0,12};
    for (auto value : {1,2,3,4,5}) append(soa,{0xaa,0xbb,0xcc,static_cast<std::uint8_t>(value)});
    record(p,6,soa,ptr);
    record(p,16,{0,3,'a',0,255},ptr);
    record(p,65001,{0xff,0,1},ptr);
    auto m = valid(p);
    CHECK(m.answers.size()==5 && m.authority.size()==2 && m.additional.size()==2);
    auto& a = m.answers[0];
    CHECK(a.owner.wire == domain && a.type==1 && a.rrclass==1 && a.ttl==0xfedcba98 && a.rdlength==4);
    CHECK(std::get<IPv4>(a.data) == IPv4({192,0,2,1}));
    auto v6 = std::get<IPv6>(m.answers[1].data);
    CHECK(std::equal(v6.begin(),v6.end(),ipv6.begin()));
    for (auto* r : {&m.answers[2],&m.answers[3],&m.authority[0]})
        CHECK(std::get<Name>(r->data).wire == domain);
    auto& mx = std::get<MX>(m.answers[4].data);
    CHECK(mx.preference==0x1234 && mx.exchange.wire==domain);
    auto& s = std::get<SOA>(m.authority[1].data);
    CHECK(s.mname.wire==domain && s.rname.wire==domain && s.serial==0xaabbcc01);
    CHECK(s.refresh==0xaabbcc02 && s.retry==0xaabbcc03 && s.expire==0xaabbcc04 && s.minimum==0xaabbcc05);
    CHECK(std::get<TXT>(m.additional[0].data).strings == std::vector<Bytes>({{}, {'a',0,255}}));
    CHECK(std::get<Bytes>(m.additional[1].data)==Bytes({255,0,1}));
    for (std::size_t n=0; n<p.size(); ++n) {
        auto r = parseDNSMessage(std::span(p).first(n));
        CHECK(std::holds_alternative<ParseError>(r));
    }
    auto unknown_class = header(0,1);
    record(unknown_class,1,{0x12,0x34},{0},3);
    CHECK(std::get<Bytes>(valid(unknown_class).answers[0].data)==Bytes({0x12,0x34}));
    // A suffix first seen inside a previous record's RDATA is a valid target.
    auto aliases = header(0,2);
    record(aliases,5,domain);
    record(aliases,2,{0xc0,27});
    CHECK(std::get<Name>(valid(aliases).answers[1].data).wire ==
          Bytes({7,'e','x','a','m','p','l','e',0}));
}
void edns() {
    const Bytes options{0xfd,0xe8,0,2,0xab,0xcd,0,12,0,0};
    auto p = header(0,0,0,1);
    record(p,41,options,{0},1232);
    // Fixture TTL FE DC BA 98 encodes extended RCODE, version and flags.
    auto m = valid(p);
    CHECK(m.edns && m.edns->udp_payload_size == 1232 && m.edns->extended_rcode == 0xfe);
    CHECK(m.edns->version == 0xdc && m.edns->flags == 0xba98 && m.edns->dnssec_ok());
    CHECK(m.responseCode() == 0xfe0 && std::get<Bytes>(m.additional[0].data) == options);
    p[3] |= 3;
    CHECK(valid(p).responseCode() == 0xfe3);
    for (const auto& data : std::vector<Bytes>{{1}, {0,1,0}, {0,1,0,2,0}}) {
        auto bad = header(0,0,0,1);
        record(bad,41,data);
        invalid(bad,ErrorCode::invalid_rdata);
    }
    for (auto bad : {header(0,1), header(0,0,1)}) {
        record(bad,41,{});
        invalid(bad,ErrorCode::invalid_rdata);
    }
    auto bad = header(0,0,0,2);
    record(bad,41,{});
    record(bad,41,{});
    invalid(bad,ErrorCode::invalid_rdata);
    bad = header(0,0,0,1);
    record(bad,41,{},domain);
    invalid(bad,ErrorCode::invalid_rdata);
}
void captures(const char* path) {
    std::ifstream file(path);
    CHECK(file.is_open());
    std::string line;
    unsigned frame = 0;
    while (std::getline(file,line)) {
        std::istringstream row(line);
        std::string token;
        if (!(row >> token)) continue;
        CHECK(token == "0000" && frame < 6);
        Bytes wire;
        while (row >> token) {
            unsigned value = 0;
            auto end = token.data() + token.size();
            auto parsed = std::from_chars(token.data(), end, value, 16);
            CHECK(token.size() == 2 && parsed.ec == std::errc{} && parsed.ptr == end);
            wire.push_back(static_cast<std::uint8_t>(value));
        }
        const auto m = valid(wire);
        const bool response = frame % 2 != 0;
        CHECK(m.header.qr == response && m.questions.size() == 1);
        CHECK(displayName(m.questions[0].name) == (frame < 4 ? "example.com." : "missing.example.invalid."));
        CHECK(m.questions[0].type == (frame == 2 || frame == 3 ? 28 : 1));
        CHECK(m.responseCode() == (frame == 5 ? 3 : 0));
        CHECK(m.edns.has_value() == !response);
        if (m.edns) CHECK(m.edns->udp_payload_size == 1232 && !m.edns->dnssec_ok());
        CHECK(m.answers.size() == (frame == 1 || frame == 3 ? 2u : 0u));
        if (frame == 1) {
            CHECK(std::get<IPv4>(m.answers[0].data) == IPv4({172,66,147,243}));
            CHECK(std::get<IPv4>(m.answers[1].data) == IPv4({104,20,23,154}));
        }
        if (frame == 3) {
            // TShark: 2606:4700:10::6814:179a and 2606:4700:10::ac42:93f3.
            IPv6 ip{0x26,6,0x47,0,0,0x10,0,0,0,0,0,0,0x68,0x14,0x17,0x9a};
            CHECK(std::get<IPv6>(m.answers[0].data) == ip);
            ip[12]=0xac; ip[13]=0x42; ip[14]=0x93; ip[15]=0xf3;
            CHECK(std::get<IPv6>(m.answers[1].data) == ip);
        }
        ++frame;
    }
    CHECK(file.eof() && frame == 6);
}
void trafficCollector() {
    DNSTrafficCollector collector({.queue_capacity = 2});
    CHECK(collector.droppedCount() == 0);

    Bytes payload{1,2,3,4};
    DNSCaptureMetadata first{{}, DNSTransport::udp, {IPv4({127,0,0,1}), 53u}, {IPv4({8,8,8,8}), 53u}};
    DNSCaptureMetadata second{{}, DNSTransport::tcp, {IPv4({10,0,0,1}), 1234u}, {IPv4({10,0,0,2}), 53u}};

    auto query_wire = queryHeader(1);
    question(query_wire, domain, 28);
    const CapturedDNSPacket query_packet{first, query_wire};
    auto query_result = normalizeDNSQuery(query_packet);
    const auto* observation = std::get_if<DNSQueryObservation>(&query_result);
    CHECK(observation != nullptr);
    CHECK(sameName(observation->name, Name{domain}));
    CHECK(observation->question_type == 28 && observation->question_class == 1);
    CHECK(observation->captured_at == first.captured_at);
    CHECK(observation->transport == DNSTransport::udp);
    auto non_query = query_packet;
    non_query.payload[2] = 0x29; // UPDATE opcode, QR clear.
    CHECK(std::get<DNSObservationSkip>(normalizeDNSQuery(non_query)) ==
          DNSObservationSkip::unsupported_opcode);
    CHECK(std::get<IPv4>(observation->source.address) == IPv4({127,0,0,1}));

    const CapturedDNSPacket empty_query{first, queryHeader(0)};
    CHECK(std::get<DNSObservationSkip>(normalizeDNSQuery(empty_query)) ==
          DNSObservationSkip::no_questions);
    auto multi_question_wire = queryHeader(2);
    question(multi_question_wire, domain);
    question(multi_question_wire, domain, 28);
    const CapturedDNSPacket multi_question{first, multi_question_wire};
    CHECK(std::get<DNSObservationSkip>(normalizeDNSQuery(multi_question)) ==
          DNSObservationSkip::multiple_questions);
    const CapturedDNSPacket malformed_query{first, Bytes{0}};
    const auto malformed_result = normalizeDNSQuery(malformed_query);
    const auto* parse_error = std::get_if<ParseError>(&malformed_result);
    CHECK(parse_error != nullptr && parse_error->code == ErrorCode::truncated);

    CHECK(collector.ingest(payload, first) == EnqueueStatus::queued);
    CHECK(collector.ingest(payload, second) == EnqueueStatus::queued);
    CHECK(collector.ingest(payload, second) == EnqueueStatus::queue_full);
    CHECK(collector.droppedCount() == 1);
    payload[0] = 99;

    auto first_packet = collector.tryPop();
    CHECK(first_packet.has_value());
    CHECK(first_packet->metadata.transport == DNSTransport::udp);
    CHECK(first_packet->payload == Bytes({1,2,3,4}));

    auto second_packet = collector.tryPop();
    CHECK(second_packet.has_value());
    CHECK(second_packet->metadata.transport == DNSTransport::tcp);
    CHECK(!collector.tryPop().has_value());

    DNSTrafficCollector zero_capacity({.queue_capacity = 0});
    CHECK(zero_capacity.ingest(Bytes{}, first) == EnqueueStatus::queued);
    CHECK(zero_capacity.ingest(Bytes{}, first) == EnqueueStatus::queue_full);
    CHECK(zero_capacity.droppedCount() == 1);
    CHECK(zero_capacity.tryPop().has_value());

    DNSTrafficCollector size_limited;
    const Bytes max_payload(65535, 0);
    CHECK(size_limited.ingest(max_payload, first) == EnqueueStatus::queued);
    auto max_packet = size_limited.tryPop();
    CHECK(max_packet.has_value());
    CHECK(max_packet->payload.size() == max_payload.size());

    const Bytes oversized_payload(65536, 0);
    CHECK(size_limited.ingest(oversized_payload, first) == EnqueueStatus::payload_too_large);
    CHECK(size_limited.droppedCount() == 1);
    CHECK(!size_limited.tryPop().has_value());

    DNSTrafficCollector byte_limited({.queue_capacity = 4, .max_queued_payload_bytes = 5});
    CHECK(byte_limited.ingest(Bytes{1,2,3}, first) == EnqueueStatus::queued);
    CHECK(byte_limited.ingest(Bytes{4,5}, first) == EnqueueStatus::queued);
    CHECK(byte_limited.ingest(Bytes{6}, first) == EnqueueStatus::byte_limit_reached);
    CHECK(byte_limited.droppedCount() == 1);
    auto three_byte_packet = byte_limited.tryPop();
    CHECK(three_byte_packet.has_value());
    CHECK(three_byte_packet->payload.size() == 3);
    CHECK(byte_limited.ingest(Bytes{6}, first) == EnqueueStatus::queued);
    auto two_byte_packet = byte_limited.tryPop();
    CHECK(two_byte_packet.has_value());
    CHECK(two_byte_packet->payload == Bytes({4,5}));
    auto one_byte_packet = byte_limited.tryPop();
    CHECK(one_byte_packet.has_value());
    CHECK(one_byte_packet->payload == Bytes({6}));
    CHECK(!byte_limited.tryPop().has_value());

    DNSTrafficCollector zero_byte_limit({.max_queued_payload_bytes = 0});
    CHECK(zero_byte_limit.ingest(Bytes{}, first) == EnqueueStatus::queued);
    CHECK(zero_byte_limit.ingest(Bytes{1}, first) == EnqueueStatus::byte_limit_reached);
    CHECK(zero_byte_limit.droppedCount() == 1);

    auto response_wire = header(1,1);
    question(response_wire, domain);
    record(response_wire, 1, {192,0,2,1}, {0xc0,12});
    const CapturedDNSPacket response_packet{first, response_wire};
    CHECK(std::get<DNSObservationSkip>(normalizeDNSQuery(response_packet)) ==
          DNSObservationSkip::response);
    auto response = valid(response_wire);
    response.answers[0].ttl = 60;
    DNSTrafficCollector answer_cache;
    CHECK(answer_cache.cacheResponse(response));
    auto oversized_response = response;
    oversized_response.answers[0].data = Bytes(16 * 1024 * 1024, 0);
    CHECK(!answer_cache.cacheResponse(oversized_response));
    oversized_response.answers[0].data = TXT{std::vector<Bytes>(20000)};
    CHECK(!answer_cache.cacheResponse(oversized_response));
    oversized_response.answers[0].data = Name{Bytes(20000, 0)};
    CHECK(!answer_cache.cacheResponse(oversized_response));
    CHECK(answer_cache.lookup(response.questions.front()).has_value());
    Question case_variant{Name{{3,'w','W','W',7,'E','X','A','M','P','L','E',0}},1,1};
    auto cached_answers = answer_cache.lookup(case_variant);
    CHECK(cached_answers.has_value() && cached_answers->size() == 1);
    CHECK(answer_cache.lookup(Question{Name{{1,'x',0}},1,1}) == std::nullopt);
    auto failed_response = response;
    failed_response.header.rcode = 3;
    CHECK(!answer_cache.cacheResponse(failed_response));
    failed_response = response;
    failed_response.answers[0].ttl = 0x80000000u;
    CHECK(!answer_cache.cacheResponse(failed_response));
    failed_response = response;
    failed_response.answers[0].ttl = 0;
    CHECK(!answer_cache.cacheResponse(failed_response));

    DNSTrafficCollector draining;
    CHECK(draining.ingest(Bytes{7,8}, first) == EnqueueStatus::queued);
    draining.close();
    auto drained_packet = draining.waitPop();
    CHECK(drained_packet.has_value());
    CHECK(drained_packet->payload == Bytes({7,8}));
    CHECK(!draining.waitPop().has_value());
    CHECK(draining.ingest(Bytes{}, first) == EnqueueStatus::closed);
    CHECK(draining.droppedCount() == 1);

    DNSTrafficCollector wake_on_close;
    std::optional<CapturedDNSPacket> closed_result;
    std::jthread waiting_consumer([&] {
        closed_result = wake_on_close.waitPop();
    });
    wake_on_close.close();
    waiting_consumer.join();
    CHECK(!closed_result.has_value());

    constexpr std::size_t producer_count = 4;
    constexpr std::size_t packets_per_producer = 1000;
    std::atomic<std::size_t> accepted{0};
    std::atomic<std::size_t> popped{0};
    DNSTrafficCollector concurrent({
        .queue_capacity = 64,
        .max_queued_payload_bytes = 64
    });
    std::vector<std::jthread> producers;
    producers.reserve(producer_count);

    for (std::size_t producer = 0; producer < producer_count; ++producer) {
        producers.emplace_back([&, producer] {
            const Bytes packet{static_cast<std::uint8_t>(producer)};
            for (std::size_t i = 0; i < packets_per_producer; ++i) {
                if (concurrent.ingest(packet, first) == EnqueueStatus::queued) {
                    accepted.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    std::jthread consumer([&] {
        while (concurrent.waitPop()) {
            popped.fetch_add(1, std::memory_order_relaxed);
        }
    });

    for (auto& producer : producers) {
        producer.join();
    }
    concurrent.close();
    consumer.join();

    const auto attempted = producer_count * packets_per_producer;
    CHECK(accepted.load() == popped.load());
    CHECK(accepted.load() + concurrent.droppedCount() == attempted);
    CHECK(!concurrent.tryPop().has_value());
}
void domainLists() {
    DNSQueryObservation observation{
        .name = Name{domain},
        .question_type = 1,
        .question_class = 1,
        .captured_at = {},
        .transport = DNSTransport::udp,
        .source = {IPv4({127,0,0,1}), 1234}
    };
    DNSDomainListsConfig config{
        .enabled = false,
        .allowed = {},
        .denied = {Name{domain}}
    };
    CHECK(!validateDNSDomainListsConfig(config));
    auto result = evaluateDNSDomainLists(observation, config);
    auto* assessment = std::get_if<DNSDomainListAssessment>(&result);
    CHECK(assessment != nullptr && !assessment->denied);

    config.enabled = true;
    config.allowed.clear();
    config.denied.clear();
    CHECK(!validateDNSDomainListsConfig(config));
    result = evaluateDNSDomainLists(observation, config);
    assessment = std::get_if<DNSDomainListAssessment>(&result);
    CHECK(assessment != nullptr && !assessment->allowed && !assessment->denied);

    config.allowed = {Name{{3,'w','W','W',7,'E','X','A','M','P','L','E',0}}};
    config.denied = {Name{domain}};
    result = evaluateDNSDomainLists(observation, config);
    assessment = std::get_if<DNSDomainListAssessment>(&result);
    CHECK(assessment != nullptr);
    CHECK(assessment->allowed && assessment->denied);
    CHECK(assessment->allowed->confidence == 100);
    CHECK(assessment->denied->rule_version == 1);
    CHECK(assessment->denied->reason == "exact configured deny-list match");

    observation.name = Name{{1,'x',3,'w','w','w',7,'e','x','a','m','p','l','e',0}};
    result = evaluateDNSDomainLists(observation, config);
    assessment = std::get_if<DNSDomainListAssessment>(&result);
    CHECK(assessment != nullptr && !assessment->allowed && !assessment->denied);
    config.include_subdomains = true;
    result = evaluateDNSDomainLists(observation, config);
    assessment = std::get_if<DNSDomainListAssessment>(&result);
    CHECK(assessment != nullptr && assessment->allowed && assessment->denied);
    CHECK(assessment->denied->reason == "subdomain configured deny-list match");

    observation.name = Name{{10,'n','o','t','e','x','a','m','p','l','e',3,'c','o','m',0}};
    result = evaluateDNSDomainLists(observation, config);
    assessment = std::get_if<DNSDomainListAssessment>(&result);
    CHECK(assessment != nullptr && !assessment->allowed && !assessment->denied);

    config.denied.push_back(Name{{3,'b','a','d'}});
    CHECK(validateDNSDomainListsConfig(config) ==
          DNSDomainListError::invalid_name);
    result = evaluateDNSDomainLists(observation, config);
    assessment = std::get_if<DNSDomainListAssessment>(&result);
    CHECK(assessment != nullptr && !assessment->denied);
    config.denied.clear();
    observation.name = Name{{1,'x'}};
    result = evaluateDNSDomainLists(observation, config);
    CHECK(std::get_if<DNSDomainListError>(&result) != nullptr);

    observation.name = Name{domain};
    config.allowed.assign(max_domain_list_entries, Name{domain});
    config.denied.clear();
    CHECK(!validateDNSDomainListsConfig(config));
    result = evaluateDNSDomainLists(observation, config);
    assessment = std::get_if<DNSDomainListAssessment>(&result);
    CHECK(assessment != nullptr && assessment->allowed);
    config.denied.push_back(Name{domain});
    CHECK(validateDNSDomainListsConfig(config) ==
          DNSDomainListError::too_many_entries);
    result = evaluateDNSDomainLists(observation, config);
    CHECK(std::get_if<DNSDomainListError>(&result) != nullptr);
    config.allowed.push_back(Name{domain});
    CHECK(validateDNSDomainListsConfig(config) ==
          DNSDomainListError::too_many_entries);
    result = evaluateDNSDomainLists(observation, config);
    CHECK(std::get_if<DNSDomainListError>(&result) != nullptr);
}
void queryRate() {
    DNSQueryObservation observation{
        .name = Name{domain},
        .question_type = 1,
        .question_class = 1,
        .captured_at = {},
        .transport = DNSTransport::udp,
        .source = {IPv4({127,0,0,1}), 1234}
    };
    DNSQueryRateMonitor disabled;
    auto result = disabled.observe(observation);
    auto* assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());

    DNSQueryRateMonitor invalid_config({
        .enabled = true,
        .max_tracked_keys = 0
    });
    CHECK(validateDNSQueryRateConfig({
        .enabled = true,
        .max_tracked_keys = 0
    }) == DNSQueryRateError::invalid_config);
    result = invalid_config.observe(observation);
    CHECK(std::get_if<DNSQueryRateError>(&result) != nullptr);
    CHECK(std::get<DNSQueryRateError>(result) == DNSQueryRateError::invalid_config);
    CHECK(validateDNSQueryRateConfig({
        .enabled = true,
        .query_threshold = 1
    }) == DNSQueryRateError::invalid_config);

    DNSQueryRateMonitor max_keys({
        .enabled = true,
        .max_tracked_keys = max_dns_query_rate_keys
    });
    CHECK(!validateDNSQueryRateConfig({
        .enabled = true,
        .max_tracked_keys = max_dns_query_rate_keys
    }));
    result = max_keys.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());
    DNSQueryRateMonitor too_many_keys({
        .enabled = true,
        .max_tracked_keys = max_dns_query_rate_keys + 1
    });
    CHECK(validateDNSQueryRateConfig({
        .enabled = true,
        .max_tracked_keys = max_dns_query_rate_keys + 1
    }) == DNSQueryRateError::invalid_config);
    result = too_many_keys.observe(observation);
    CHECK(std::get_if<DNSQueryRateError>(&result) != nullptr);
    CHECK(std::get<DNSQueryRateError>(result) == DNSQueryRateError::invalid_config);

    DNSQueryRateMonitor max_window({
        .enabled = true,
        .window = std::chrono::seconds{max_dns_query_rate_window_seconds}
    });
    CHECK(!validateDNSQueryRateConfig({
        .enabled = true,
        .window = std::chrono::seconds{max_dns_query_rate_window_seconds}
    }));
    result = max_window.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());
    DNSQueryRateMonitor too_long_window({
        .enabled = true,
        .window = std::chrono::seconds{max_dns_query_rate_window_seconds + 1}
    });
    CHECK(validateDNSQueryRateConfig({
        .enabled = true,
        .window = std::chrono::seconds{max_dns_query_rate_window_seconds + 1}
    }) == DNSQueryRateError::invalid_config);
    result = too_long_window.observe(observation);
    CHECK(std::get_if<DNSQueryRateError>(&result) != nullptr);
    CHECK(std::get<DNSQueryRateError>(result) == DNSQueryRateError::invalid_config);
    DNSQueryRateMonitor empty_window({
        .enabled = true,
        .window = std::chrono::seconds{0}
    });
    CHECK(validateDNSQueryRateConfig({
        .enabled = true,
        .window = std::chrono::seconds{0}
    }) == DNSQueryRateError::invalid_config);
    result = empty_window.observe(observation);
    CHECK(std::get_if<DNSQueryRateError>(&result) != nullptr);
    CHECK(std::get<DNSQueryRateError>(result) == DNSQueryRateError::invalid_config);

    DNSQueryRateMonitor monitor({
        .enabled = true,
        .max_tracked_keys = 1,
        .query_threshold = 3,
        .window = std::chrono::seconds{60}
    });
    result = monitor.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());
    result = monitor.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());
    result = monitor.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && assessment->has_value());
    CHECK((*assessment)->query_count == 3 && (*assessment)->threshold == 3);
    CHECK((*assessment)->confidence == 50 && (*assessment)->rule_version == 1);
    CHECK((*assessment)->reason == "query count reached configured threshold");
    result = monitor.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());

    observation.name = Name{{1,'x',0}};
    result = monitor.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());
    observation.name = Name{domain};
    result = monitor.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());
    result = monitor.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());
    result = monitor.observe(observation);
    assessment = std::get_if<std::optional<DNSQueryRateAssessment>>(&result);
    CHECK(assessment != nullptr && assessment->has_value());

    observation.name = Name{{1,'x'}};
    result = monitor.observe(observation);
    CHECK(std::get_if<DNSQueryRateError>(&result) != nullptr);
    CHECK(std::get<DNSQueryRateError>(result) == DNSQueryRateError::invalid_observation);
}
void labelHeuristic() {
    DNSQueryObservation observation{
        .name = Name{domain},
        .question_type = 1,
        .question_class = 1,
        .captured_at = {},
        .transport = DNSTransport::udp,
        .source = {IPv4({127,0,0,1}), 1234}
    };
    auto result = evaluateDNSLabelLength(observation);
    auto* assessment =
        std::get_if<std::optional<DNSLabelHeuristicAssessment>>(&result);
    CHECK(assessment != nullptr && !assessment->has_value());

    Bytes long_name{50};
    long_name.insert(long_name.end(), 50, 'a');
    long_name.push_back(0);
    observation.name = Name{std::move(long_name)};
    result = evaluateDNSLabelLength(observation, {
        .enabled = true,
        .label_length_threshold = 50
    });
    assessment = std::get_if<std::optional<DNSLabelHeuristicAssessment>>(&result);
    CHECK(assessment != nullptr && assessment->has_value());
    CHECK((*assessment)->observed_label_length == 50);
    CHECK((*assessment)->confidence == 25 && (*assessment)->rule_version == 1);
    CHECK((*assessment)->reason ==
          "DNS label length met configured anomaly threshold");

    result = evaluateDNSLabelLength(observation, {
        .enabled = true,
        .label_length_threshold = 64
    });
    CHECK(std::get_if<DNSLabelHeuristicError>(&result) != nullptr);
    observation.name = Name{{1,'x'}};
    result = evaluateDNSLabelLength(observation, {
        .enabled = true,
        .label_length_threshold = 50
    });
    CHECK(std::get_if<DNSLabelHeuristicError>(&result) != nullptr);
}
void malformed() {
    auto bad_data = [](unsigned type, const Bytes& data) {
        auto p = header(0,2);
        record(p,type,data);
        record(p,1,{1,2,3,4});
        invalid(p,ErrorCode::invalid_rdata);
    };
    bad_data(1,{1,2,3}); bad_data(1,Bytes(5));
    bad_data(28,Bytes(15)); bad_data(16,{}); bad_data(16,{2,'a'});
    bad_data(15,{0}); bad_data(15,{0,1,0,1});
    bad_data(6,Bytes(21)); bad_data(6,Bytes(23));
    bad_data(2,{0xc0}); bad_data(5,{1,'x'}); bad_data(12,{0,0});
    auto empty_txt = header(0,1);
    record(empty_txt,16,{});
    CHECK(invalid(empty_txt,ErrorCode::invalid_rdata).offset == empty_txt.size());
    auto p = header(0,1);
    record(p,65000,{0});
    p.pop_back();
    invalid(p,ErrorCode::truncated);
    p = header(0,0); p.push_back(0);
    CHECK(invalid(p,ErrorCode::trailing_data).offset == 12);
}
void limits() {
    auto bounded = header(1,1,0,1);
    question(bounded,domain);
    record(bounded,16,{0,1,'a'},{0xc0,12});
    const auto additional = bounded.size();
    record(bounded,16,{0},{0xc0,12});
    CHECK(std::holds_alternative<DNSMessage>(parseDNSMessageBounded(bounded,{}, {2,3})));
    auto hops = std::get<ParseError>(parseDNSMessageBounded(bounded,{}, {1,3}));
    CHECK(hops.code == ErrorCode::resource_limit && hops.offset == additional);
    auto txt = std::get<ParseError>(parseDNSMessageBounded(bounded,{}, {2,2}));
    CHECK(txt.code == ErrorCode::resource_limit && txt.offset == bounded.size()-1);
    auto plain = header(1,0);
    question(plain,domain);
    CHECK(std::holds_alternative<DNSMessage>(parseDNSMessageBounded(plain,{}, {0,0})));
    auto p = header(0,1);
    record(p,65000,Bytes(65535-23,0xab));
    CHECK(valid(p).answers[0].rdlength == 65535-23);
    ParseLimits l; l.message_bytes = 65534;
    invalid(p,ErrorCode::resource_limit,l);
    p.push_back(0);
    invalid(p,ErrorCode::resource_limit);
    invalid(header(65,0),ErrorCode::resource_limit);
    invalid(header(0,1000,1000,49),ErrorCode::resource_limit);
    invalid(header(0,2048),ErrorCode::truncated);
    // The largest TXT payload that fits a single root-owned record.
    Bytes chunks(65535-23,0);
    p = header(0,1);
    record(p,16,chunks);
    auto message = valid(p);
    const auto& strings = std::get<TXT>(message.answers[0].data).strings;
    CHECK(strings.size() == chunks.size());
    CHECK(std::all_of(strings.begin(), strings.end(), [](const Bytes& s) { return s.empty(); }));
    p.back() = 1;
    CHECK(invalid(p,ErrorCode::invalid_rdata).offset == p.size());
}
}
int main(int argc, char** argv) {
    if (argc < 2) return 2;
    try {
        std::string_view group = argv[1];
        if (group=="captures" && argc==3) captures(argv[2]);
        else if (argc != 2) return 2;
        else if (group=="errors") errorNames();
        else if (group=="header") headers();
        else if (group=="names") names();
        else if (group=="records") records();
        else if (group=="traffic") trafficCollector();
        else if (group=="policy") domainLists();
        else if (group=="rate") queryRate();
        else if (group=="heuristic") labelHeuristic();
        else if (group=="malformed") malformed();
        else if (group=="limits") limits();
        else if (group=="edns") edns();
        else return 2;
    } catch (const std::exception& e) {
        std::cerr << argv[1] << ": " << e.what() << '\n';
        return 1;
    }
    return 0;
}
