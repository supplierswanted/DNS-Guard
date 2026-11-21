#include "dnsguard/DNSProxy.hpp"
#include <atomic>
#include <chrono>
#include <csignal>
#include <exception>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string_view>
#include <thread>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace {
static_assert(std::atomic<bool>::is_always_lock_free);
std::atomic<bool> signal_stop{false};
std::atomic<bool> control_stop{false};
#ifndef _WIN32
void signalHandler(int) { signal_stop.store(true,std::memory_order_relaxed); }
#endif

#ifdef _WIN32
constexpr wchar_t service_name[] = L"RogerfabDNSGuard";
SERVICE_STATUS_HANDLE status_handle = nullptr;
SERVICE_STATUS last_status{};
std::mutex status_mutex;
std::filesystem::path service_config;

void reportStatus(DWORD state, DWORD error = NO_ERROR) {
    std::lock_guard lock(status_mutex);
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = state == SERVICE_RUNNING
        ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    status.dwWin32ExitCode = error;
    status.dwServiceSpecificExitCode = error == ERROR_SERVICE_SPECIFIC_ERROR ? 1 : 0;
    status.dwWaitHint = state == SERVICE_STOP_PENDING ? 30000 : 0;
    last_status = status;
    SetServiceStatus(status_handle, &status);
}

DWORD WINAPI serviceControl(DWORD control, DWORD, void*, void*) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        control_stop.store(true, std::memory_order_relaxed);
        return NO_ERROR;
    }
    if (control == SERVICE_CONTROL_INTERROGATE) {
        std::lock_guard lock(status_mutex);
        if (last_status.dwCurrentState) SetServiceStatus(status_handle, &last_status);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

BOOL WINAPI consoleControl(DWORD control) {
    if (control == CTRL_C_EVENT || control == CTRL_BREAK_EVENT ||
        control == CTRL_CLOSE_EVENT || control == CTRL_SHUTDOWN_EVENT) {
        control_stop.store(true, std::memory_order_relaxed);
        return TRUE;
    }
    return FALSE;
}
#endif

int serve(const std::filesystem::path& path, bool as_service) {
    try {
        dnsguard::DNSProxy proxy(dnsguard::loadProxyConfig(path));
        // Construction binds both listeners before readiness is reported.
#ifdef _WIN32
        if (as_service) reportStatus(SERVICE_RUNNING);
#else
        (void)as_service;
#endif
        std::cout << "DNS Guard listening" << std::endl;
        std::exception_ptr error;
        std::atomic<bool> finished{false};
        std::jthread worker([&](std::stop_token stop) {
            try { proxy.run(stop); }
            catch (...) { error = std::current_exception(); }
            finished.store(true, std::memory_order_release);
        });
        while (!finished.load(std::memory_order_acquire) && !signal_stop.load(std::memory_order_relaxed) &&
               !control_stop.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
#ifdef _WIN32
        if (as_service) reportStatus(SERVICE_STOP_PENDING);
#endif
        worker.request_stop();
        worker.join();
        if (error) std::rethrow_exception(error);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "DNS Guard stopped: " << error.what() << '\n';
        return 1;
    }
}

#ifdef _WIN32
void WINAPI serviceMain(DWORD, wchar_t**) {
    status_handle = RegisterServiceCtrlHandlerExW(service_name, serviceControl, nullptr);
    if (!status_handle) return;
    reportStatus(SERVICE_START_PENDING);
    const auto result = serve(service_config, true);
    reportStatus(SERVICE_STOPPED, result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}
#endif
}

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring_view(argv[2]) == L"--service") {
        service_config = argv[1];
        SERVICE_TABLE_ENTRYW table[] = {
            {const_cast<wchar_t*>(service_name), serviceMain}, {nullptr, nullptr}};
        if (!StartServiceCtrlDispatcherW(table)) {
            std::cerr << "Cannot connect to Windows Service Control Manager\n";
            return 1;
        }
        return 0;
    }
    if (argc != 2) {
        std::cerr << "Usage: dns_guard CONFIG [--service]\n";
        return 2;
    }
    if (!SetConsoleCtrlHandler(consoleControl, TRUE)) return 1;
    return serve(argv[1], false);
}
#else
int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: dns_guard CONFIG\n";
        return 2;
    }
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    return serve(argv[1], false);
}
#endif
