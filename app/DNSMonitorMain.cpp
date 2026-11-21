#include "dnsguard/DNSProxy.hpp"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <condition_variable>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winevt.h>

namespace {
constexpr wchar_t channel[] = L"Microsoft-Windows-DNS-Client/Operational";
std::atomic<bool> stopping{false};
BOOL WINAPI onControl(DWORD code) {
    if (code == CTRL_C_EVENT || code == CTRL_BREAK_EVENT || code == CTRL_CLOSE_EVENT) {
        stopping.store(true); return TRUE;
    }
    return FALSE;
}
struct EventHandle {
    EVT_HANDLE value{};
    ~EventHandle() { if (value) EvtClose(value); }
    EventHandle() = default;
    explicit EventHandle(EVT_HANDLE h) : value(h) {}
    EventHandle(const EventHandle&) = delete;
    EventHandle& operator=(const EventHandle&) = delete;
    EventHandle(EventHandle&& other) noexcept : value(std::exchange(other.value,nullptr)) {}
    EventHandle& operator=(EventHandle&& other) noexcept {
        if (value) EvtClose(value);
        value = std::exchange(other.value,nullptr);
        return *this;
    }
};
bool nameFromWindows(std::wstring_view text, dnsguard::Name& name) {
    if (!text.empty() && text.back() == L'.') text.remove_suffix(1);
    if (text.empty() || text.size() > 253) return false;
    for (std::size_t pos = 0; pos < text.size();) {
        const auto end = text.find(L'.',pos);
        const auto len = (end == text.npos ? text.size() : end) - pos;
        if (len == 0 || len > 63) return false;
        name.wire.push_back(static_cast<std::uint8_t>(len));
        for (std::size_t i = 0; i < len; ++i) {
            const auto c = text[pos+i];
            if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                  (c >= L'0' && c <= L'9') || c == L'-' || c == L'_')) return false;
            name.wire.push_back(static_cast<std::uint8_t>(c));
        }
        if (end == text.npos) break;
        pos = end+1;
    }
    name.wire.push_back(0);
    return dnsguard::sameName(name,name);
}
std::optional<std::wstring> field(EVT_HANDLE event, EVT_HANDLE context) {
    DWORD bytes = 0, count = 0;
    if (EvtRender(context,event,EvtRenderEventValues,0,nullptr,&bytes,&count) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes > 65536) return std::nullopt;
    std::vector<std::max_align_t> storage((bytes + sizeof(std::max_align_t)-1)/sizeof(std::max_align_t));
    if (!EvtRender(context,event,EvtRenderEventValues,
                   static_cast<DWORD>(storage.size()*sizeof(std::max_align_t)),storage.data(),&bytes,&count) || count != 1)
        return std::nullopt;
    const auto& v = *reinterpret_cast<const EVT_VARIANT*>(storage.data());
    switch (v.Type & EVT_VARIANT_TYPE_MASK) {
    case EvtVarTypeString: return v.StringVal ? std::optional<std::wstring>(v.StringVal) : std::nullopt;
    case EvtVarTypeUInt16: return std::to_wstring(v.UInt16Val);
    case EvtVarTypeUInt32: return std::to_wstring(v.UInt32Val);
    case EvtVarTypeInt32: return std::to_wstring(v.Int32Val);
    default: return std::nullopt;
    }
}
EventHandle pathContext(const wchar_t* path) {
    return EventHandle(EvtCreateRenderContext(1,&path,EvtRenderContextValues));
}
bool decimal(std::wstring_view value) {
    return !value.empty() && std::all_of(value.begin(),value.end(),
        [](wchar_t c) { return c >= L'0' && c <= L'9'; });
}
struct Pending {
    std::wstring name, type, status, pid;
};
struct MonitorState {
    EventHandle name, type, status, pid;
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<Pending> pending;
    std::uint64_t dropped = 0;
    DWORD error = 0;
};
DWORD WINAPI onEvent(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE event) {
    auto& state = *static_cast<MonitorState*>(context);
    try {
        if (action == EvtSubscribeActionError) {
            std::lock_guard lock(state.mutex);
            state.error = static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(event));
            state.ready.notify_one();
            return 0;
        }
        const auto name = field(event,state.name.value);
        const auto type = field(event,state.type.value);
        auto status = field(event,state.status.value).value_or(L"unknown");
        auto pid = field(event,state.pid.value).value_or(L"unknown");
        if (!name || !type || name->size() > 253 || type->size() > 5 ||
            status.size() > 32 || pid.size() > 20) {
            std::lock_guard lock(state.mutex); ++state.dropped; return 0;
        }
        if (!decimal(status)) status = L"unknown";
        if (!decimal(pid)) pid = L"unknown";
        Pending item{*name,*type,std::move(status),std::move(pid)};
        std::lock_guard lock(state.mutex);
        if (state.pending.size() == 256) ++state.dropped;
        else { state.pending.push_back(std::move(item)); state.ready.notify_one(); }
    } catch (...) {
        std::lock_guard lock(state.mutex);
        ++state.dropped;
    }
    return 0;
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) { std::cerr << "Usage: dns_monitor CONFIG\n"; return 2; }
    try {
        const auto config = dnsguard::loadProxyConfig(argv[1]);
        std::wcout << std::unitbuf;
        EventHandle channelConfig(EvtOpenChannelConfig(nullptr,channel,0));
        if (!channelConfig.value) throw std::runtime_error("cannot read DNS Client channel configuration");
        DWORD size = 0;
        EVT_VARIANT enabled{};
        if (!EvtGetChannelConfigProperty(channelConfig.value,EvtChannelConfigEnabled,0,
                                         sizeof(enabled),&enabled,&size) || !enabled.BooleanVal)
            throw std::runtime_error("DNS Client Operational channel is disabled or inaccessible");
        MonitorState state;
        state.name = pathContext(L"Event/EventData/Data[@Name='QueryName']");
        state.type = pathContext(L"Event/EventData/Data[@Name='QueryType']");
        state.status = pathContext(L"Event/EventData/Data[@Name='QueryStatus']");
        state.pid = pathContext(L"Event/System/Execution/@ProcessID");
        if (!state.name.value || !state.type.value || !state.status.value || !state.pid.value)
            throw std::runtime_error("cannot create DNS event render contexts");
        EventHandle subscription(EvtSubscribe(nullptr,nullptr,channel,
            L"*[System[(EventID=3008)]]",nullptr,&state,onEvent,EvtSubscribeToFutureEvents));
        if (!subscription.value) throw std::runtime_error("DNS Client event subscription unavailable; check Operational channel and permissions");
        if (!SetConsoleCtrlHandler(onControl,TRUE)) throw std::runtime_error("cannot install stop handler");
        std::uint64_t seen = 0, blocked = 0, skipped = 0;
        while (!stopping.load()) {
            Pending item;
            {
                std::unique_lock lock(state.mutex);
                state.ready.wait_for(lock,std::chrono::milliseconds(250),[&]{return !state.pending.empty() || state.error;});
                if (state.error) throw std::runtime_error("DNS event subscription lost: " + std::to_string(state.error));
                if (state.pending.empty()) continue;
                item = std::move(state.pending.front());
                state.pending.pop_front();
            }
                const auto& qname = item.name;
                const auto& qtype = item.type;
                dnsguard::Name domain;
                if (!nameFromWindows(qname,domain)) { ++skipped; continue; }
                unsigned number = 0;
                if (qtype.empty() || qtype.size() > 5) { ++skipped; continue; }
                std::string asciiType;
                for (wchar_t c : qtype) {
                    if (c < L'0' || c > L'9') { asciiType.clear(); break; }
                    asciiType.push_back(static_cast<char>(c));
                }
                const auto parsed = std::from_chars(asciiType.data(),asciiType.data()+asciiType.size(),number);
                if (asciiType.empty() || parsed.ec != std::errc{} || parsed.ptr != asciiType.data()+asciiType.size() || number > 65535) {
                    ++skipped; continue;
                }
                dnsguard::DNSQueryObservation observation{};
                observation.name = std::move(domain);
                observation.question_type = static_cast<std::uint16_t>(number);
                observation.question_class = 1;
                observation.captured_at = std::chrono::system_clock::now();
                const auto result = dnsguard::evaluateDNSDomainLists(observation,config.lists);
                if (!std::holds_alternative<dnsguard::DNSDomainListAssessment>(result)) { ++skipped; continue; }
                const auto& assessment = std::get<dnsguard::DNSDomainListAssessment>(result);
                const bool denied = assessment.denied && !assessment.allowed;
                ++seen; if (denied) ++blocked;
                const auto timeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    observation.captured_at.time_since_epoch()).count();
                std::wcout << L"time_unix_ms=" << timeMs << L" domain=" << qname << L" type=" << qtype
                           << L" status=" << item.status
                           << L" pid=" << item.pid
                           << L" list=" << (denied ? L"DENY" : L"allow") << L'\n';
                if (seen % 100 == 0) std::wcout << L"seen=" << seen << L" denied=" << blocked << L" skipped=" << skipped << L'\n';
        }
        std::lock_guard lock(state.mutex);
        std::wcout << L"seen=" << seen << L" denied=" << blocked << L" skipped=" << skipped << L" dropped=" << state.dropped << L'\n';
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
