#pragma once
#include <cstddef>
#include <string_view>

namespace dnsguard {
enum class ErrorCode {
    truncated, invalid_label, invalid_pointer, name_too_long,
    invalid_rdata, resource_limit, trailing_data, allocation_failure,
    invalid_header
};

[[nodiscard]] constexpr std::string_view errorCodeName(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::truncated: return "truncated";
        case ErrorCode::invalid_label: return "invalid_label";
        case ErrorCode::invalid_pointer: return "invalid_pointer";
        case ErrorCode::name_too_long: return "name_too_long";
        case ErrorCode::invalid_rdata: return "invalid_rdata";
        case ErrorCode::resource_limit: return "resource_limit";
        case ErrorCode::trailing_data: return "trailing_data";
        case ErrorCode::allocation_failure: return "allocation_failure";
        case ErrorCode::invalid_header: return "invalid_header";
    }
    return "unknown";
}
struct ParseError {
    ErrorCode code;
    std::size_t offset; // Packet-relative. Allocation failure has no location (0).
};
}
