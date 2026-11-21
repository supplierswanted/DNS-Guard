#include "ParserInternal.hpp"

namespace dnsguard::detail {
Name Names::decode(Cursor& input) {
    Cursor walk = input;
    std::size_t segment_start = input.pos;
    std::size_t hops = 0;
    Name result;
    // Copy literal labels together, only after validating the segment.
    auto append_segment = [&](std::size_t end) {
        auto labels = walk.packet.subspan(segment_start, end - segment_start);
        result.wire.insert(result.wire.end(), labels.begin(), labels.end());
    };
    for (;;) {
        const auto at = walk.pos;
        const auto tag = walk.byte();
        if (hops == 0 && at < boundaries.size()) boundaries.set(at);
        if ((tag & 0xc0) == 0xc0) {
            const std::size_t target = ((tag & 63u) << 8) | walk.byte();
            // Every jump leads to a previously parsed suffix wholly before
            // this segment. This excludes cycles, header bytes and label interiors.
            if (target >= segment_start || !boundaries[target])
                throw ParseError{ErrorCode::invalid_pointer, at};
            if (hops == max_hops || remaining_hops == 0)
                throw ParseError{ErrorCode::resource_limit, at};
            --remaining_hops;
            append_segment(at);
            if (hops++ == 0) input.pos = walk.pos;
            walk.end = segment_start;
            walk.pos = segment_start = target;
            continue;
        }
        if (tag > 63) throw ParseError{ErrorCode::invalid_label, at};
        if (result.wire.size() + (walk.pos - segment_start) + tag > 255)
            throw ParseError{ErrorCode::name_too_long, at};
        if (tag == 0) {
            append_segment(walk.pos);
            if (hops == 0) input.pos = walk.pos;
            return result;
        }
        walk.take(tag);
    }
}

Question readQuestion(Cursor& input, Names& names) {
    return {names.decode(input), input.u16(), input.u16()};
}
}
