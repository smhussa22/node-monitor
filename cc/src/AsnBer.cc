// related headers
#include "AsnBer.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <format>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor::AsnBer
{

    namespace
    {

        // append one OID arc using BER's variable-length base-128 with continuation-bit encoding.
        // arc 0 emits a single zero byte; larger values emit big-endian base-128 digits with the high
        // bit set on every byte except the final one
        void append_arc(std::vector<std::uint8_t>& out, std::uint32_t v)
        {

            if (v == 0u)
            {
                out.push_back(0u);
                return;
            }

            // collect base-128 digits least significant first; then emit in reverse with continuation
            std::uint8_t digits[5] { 0u };
            std::size_t n { 0uz };
            while (v > 0u && n < 5uz)
            {
                digits[n++] = static_cast<std::uint8_t>(v & 0x7Fu);
                v >>= 7u;
            }
            for (std::size_t i { n }; i > 0uz; --i)
            {
                std::uint8_t d { digits[i - 1uz] };
                if (i > 1uz) d |= 0x80u;
                out.push_back(d);
            }

        }

        // pull one OID arc from the buffer using the same variable-length encoding. advances cursor
        std::optional<std::uint32_t> read_arc(const std::uint8_t* data, std::size_t len, std::size_t& cursor)
        {

            std::uint32_t v { 0u };
            std::size_t consumed { 0uz };
            while (cursor < len)
            {
                std::uint8_t b { data[cursor++] };
                v = (v << 7u) | static_cast<std::uint32_t>(b & 0x7Fu);
                ++consumed;
                if ((b & 0x80u) == 0u) return v;
                if (consumed > 5uz) return std::nullopt;
            }
            return std::nullopt;

        }

    }

    std::string oid_to_string(const Oid& arcs)
    {

        std::string out { };
        for (std::size_t i { 0uz }; i < arcs.size(); ++i)
        {
            if (i > 0uz) out.push_back('.');
            out.append(std::to_string(arcs[i]));
        }
        return out;

    }

    std::optional<Oid> oid_from_string(const std::string& s)
    {

        if (s.empty()) return std::nullopt;

        Oid out { };
        std::size_t start { 0uz };
        for (std::size_t i { 0uz }; i <= s.size(); ++i)
        {
            if (i == s.size() || s[i] == '.')
            {
                if (i == start) return std::nullopt;
                std::uint32_t v { 0u };
                for (std::size_t j { start }; j < i; ++j)
                {
                    if (s[j] < '0' || s[j] > '9') return std::nullopt;
                    v = v * 10u + static_cast<std::uint32_t>(s[j] - '0');
                }
                out.push_back(v);
                start = i + 1uz;
            }
        }
        return out;

    }

    int compare_oids(const Oid& a, const Oid& b)
    {

        std::size_t n { a.size() < b.size() ? a.size() : b.size() };
        for (std::size_t i { 0uz }; i < n; ++i)
        {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        if (a.size() < b.size()) return -1;
        if (a.size() > b.size()) return 1;
        return 0;

    }

    bool is_descendant(const Oid& child, const Oid& prefix)
    {

        if (child.size() <= prefix.size()) return false;
        for (std::size_t i { 0uz }; i < prefix.size(); ++i)
        {
            if (child[i] != prefix[i]) return false;
        }
        return true;

    }

    std::vector<std::uint8_t> encode_length(std::size_t n)
    {

        std::vector<std::uint8_t> out { };

        // short form: single byte, value n; valid only for n < 128
        if (n < 128uz)
        {
            out.push_back(static_cast<std::uint8_t>(n));
            return out;
        }

        // long form: 0x80 | k, followed by k bytes of big-endian length
        std::uint8_t bytes[8] { 0u };
        std::size_t i { 0uz };
        std::size_t tmp { n };
        while (tmp > 0uz && i < 8uz)
        {
            bytes[i++] = static_cast<std::uint8_t>(tmp & 0xFFu);
            tmp >>= 8u;
        }
        out.push_back(static_cast<std::uint8_t>(0x80u | i));
        for (std::size_t j { i }; j > 0uz; --j) out.push_back(bytes[j - 1uz]);
        return out;

    }

    std::vector<std::uint8_t> encode_tlv(std::uint8_t tag, const std::vector<std::uint8_t>& contents)
    {

        std::vector<std::uint8_t> out { };
        out.reserve(contents.size() + 8uz);
        out.push_back(tag);
        auto len_bytes { encode_length(contents.size()) };
        out.insert(out.end(), len_bytes.begin(), len_bytes.end());
        out.insert(out.end(), contents.begin(), contents.end());
        return out;

    }

    std::vector<std::uint8_t> encode_integer(std::int64_t v)
    {

        // emit minimal twos-complement big-endian bytes. for unsigned-looking positive values that
        // would set the sign bit we prepend a 0x00 padding byte
        std::uint8_t bytes[10] { 0u };
        std::size_t n { 0uz };
        std::int64_t x { v };

        if (x == 0)
        {
            bytes[n++] = 0u;
        }
        else if (x > 0)
        {
            while (x > 0)
            {
                bytes[n++] = static_cast<std::uint8_t>(x & 0xFF);
                x >>= 8;
            }
            // top bit of the highest byte must be 0 for a positive integer; pad with 0x00 if it isn't
            if ((bytes[n - 1uz] & 0x80u) != 0u) bytes[n++] = 0u;
        }
        else
        {
            while (true)
            {
                std::uint8_t b { static_cast<std::uint8_t>(x & 0xFF) };
                bytes[n++] = b;
                std::int64_t shifted { x >> 8 };
                if (shifted == -1 && (b & 0x80u) != 0u) break;
                x = shifted;
            }
        }

        std::vector<std::uint8_t> contents { };
        contents.reserve(n);
        for (std::size_t i { n }; i > 0uz; --i) contents.push_back(bytes[i - 1uz]);
        return encode_tlv(k_tag_integer, contents);

    }

    std::vector<std::uint8_t> encode_octet_string(const std::string& s)
    {

        std::vector<std::uint8_t> contents { s.begin(), s.end() };
        return encode_tlv(k_tag_octet_string, contents);

    }

    std::vector<std::uint8_t> encode_null()
    {

        return std::vector<std::uint8_t> { k_tag_null, 0u };

    }

    std::vector<std::uint8_t> encode_oid(const Oid& arcs)
    {

        std::vector<std::uint8_t> contents { };

        // first two arcs pack into a single byte: arc0 * 40 + arc1. arc0 is required to be 0, 1, or 2;
        // we tolerate any value and emit it raw rather than throwing
        if (arcs.size() < 2uz)
        {
            for (auto a : arcs) append_arc(contents, a);
        }
        else
        {
            std::uint32_t packed { arcs[0] * 40u + arcs[1] };
            append_arc(contents, packed);
            for (std::size_t i { 2uz }; i < arcs.size(); ++i) append_arc(contents, arcs[i]);
        }

        return encode_tlv(k_tag_oid, contents);

    }

    std::vector<std::uint8_t> encode_sequence(const std::vector<std::uint8_t>& contents)
    {

        return encode_tlv(k_tag_sequence, contents);

    }

    namespace
    {

        // helper: encode an unsigned 32 with optional 0x00 padding so the top bit doesn't look negative
        std::vector<std::uint8_t> encode_uint32_contents(std::uint32_t v)
        {

            std::uint8_t bytes[5] { 0u };
            std::size_t n { 0uz };
            if (v == 0u)
            {
                bytes[n++] = 0u;
            }
            else
            {
                while (v > 0u)
                {
                    bytes[n++] = static_cast<std::uint8_t>(v & 0xFFu);
                    v >>= 8u;
                }
                // unsigned values keep a leading 0 if the high bit is set, since BER integer-style fields
                // would otherwise be interpreted as negative
                if ((bytes[n - 1uz] & 0x80u) != 0u) bytes[n++] = 0u;
            }

            std::vector<std::uint8_t> out { };
            out.reserve(n);
            for (std::size_t i { n }; i > 0uz; --i) out.push_back(bytes[i - 1uz]);
            return out;

        }

    }

    std::vector<std::uint8_t> encode_counter32(std::uint32_t v)
    {

        return encode_tlv(k_tag_counter32, encode_uint32_contents(v));

    }

    std::vector<std::uint8_t> encode_gauge32(std::uint32_t v)
    {

        return encode_tlv(k_tag_gauge32, encode_uint32_contents(v));

    }

    std::vector<std::uint8_t> encode_time_ticks(std::uint32_t v)
    {

        return encode_tlv(k_tag_time_ticks, encode_uint32_contents(v));

    }

    std::vector<std::uint8_t> encode_ip_address(std::uint32_t addr)
    {

        std::vector<std::uint8_t> contents {
            static_cast<std::uint8_t>((addr >> 24) & 0xFFu),
            static_cast<std::uint8_t>((addr >> 16) & 0xFFu),
            static_cast<std::uint8_t>((addr >> 8) & 0xFFu),
            static_cast<std::uint8_t>(addr & 0xFFu),
        };
        return encode_tlv(k_tag_ip_address, contents);

    }

    std::optional<ParsedTlv> parse_tlv(const std::uint8_t* data, std::size_t len, std::size_t offset)
    {

        if (data == nullptr || offset >= len) return std::nullopt;

        ParsedTlv out { };
        out.m_tag = data[offset];
        std::size_t pos { offset + 1uz };
        if (pos >= len) return std::nullopt;

        std::uint8_t first_length_byte { data[pos++] };
        if ((first_length_byte & 0x80u) == 0u)
        {
            // short form
            out.m_value_length = static_cast<std::size_t>(first_length_byte);
        }
        else
        {
            // long form: lower 7 bits give the byte count of the big-endian length that follows
            std::size_t k { static_cast<std::size_t>(first_length_byte & 0x7Fu) };
            if (k == 0uz || k > 4uz) return std::nullopt; // 0x80 (indefinite form) isn't used by DER/BER strict
            if (pos + k > len) return std::nullopt;
            std::size_t value_len { 0uz };
            for (std::size_t i { 0uz }; i < k; ++i) value_len = (value_len << 8u) | static_cast<std::size_t>(data[pos++]);
            out.m_value_length = value_len;
        }

        out.m_value_offset = pos;
        if (pos + out.m_value_length > len) return std::nullopt;
        out.m_total_size = (pos - offset) + out.m_value_length;
        return out;

    }

    std::optional<std::int64_t> parse_integer_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len)
    {

        if (offset + value_len > len) return std::nullopt;
        if (value_len == 0uz) return 0;
        if (value_len > 8uz) return std::nullopt;

        std::int64_t v { 0 };
        // sign-extend from the high bit of the first byte
        if ((data[offset] & 0x80u) != 0u) v = -1;
        for (std::size_t i { 0uz }; i < value_len; ++i) v = (v << 8) | static_cast<std::int64_t>(data[offset + i]);
        return v;

    }

    std::optional<std::string> parse_octet_string_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len)
    {

        if (offset + value_len > len) return std::nullopt;
        return std::string { reinterpret_cast<const char*>(data + offset), value_len };

    }

    std::optional<Oid> parse_oid_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len)
    {

        if (offset + value_len > len) return std::nullopt;
        if (value_len == 0uz) return Oid { };

        Oid out { };

        // unpack the first byte into two arcs: arc0 = byte / 40, arc1 = byte % 40 (but only when arc0 < 2)
        std::size_t cursor { offset };
        auto first { read_arc(data, offset + value_len, cursor) };
        if (!first.has_value()) return std::nullopt;

        std::uint32_t packed { *first };
        if (packed < 80u)
        {
            out.push_back(packed / 40u);
            out.push_back(packed % 40u);
        }
        else
        {
            out.push_back(2u);
            out.push_back(packed - 80u);
        }

        while (cursor < offset + value_len)
        {
            auto a { read_arc(data, offset + value_len, cursor) };
            if (!a.has_value()) return std::nullopt;
            out.push_back(*a);
        }

        return out;

    }

    std::optional<std::uint32_t> parse_uint32_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len)
    {

        if (offset + value_len > len) return std::nullopt;
        if (value_len == 0uz) return 0u;
        if (value_len > 5uz) return std::nullopt;

        std::uint32_t v { 0u };
        for (std::size_t i { 0uz }; i < value_len; ++i) v = (v << 8u) | static_cast<std::uint32_t>(data[offset + i]);
        return v;

    }

    std::optional<std::uint64_t> parse_uint64_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len)
    {

        if (offset + value_len > len) return std::nullopt;
        if (value_len == 0uz) return 0uz;
        if (value_len > 9uz) return std::nullopt;

        std::uint64_t v { 0u };
        for (std::size_t i { 0uz }; i < value_len; ++i) v = (v << 8u) | static_cast<std::uint64_t>(data[offset + i]);
        return v;

    }

}
