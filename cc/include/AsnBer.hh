#ifndef NODE_MONITOR_ASN_BER_HH
#define NODE_MONITOR_ASN_BER_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor::AsnBer
{

    // universal types we encode / decode for SNMP
    constexpr std::uint8_t k_tag_integer       { 0x02 }; // signed twos-complement integer
    constexpr std::uint8_t k_tag_octet_string  { 0x04 }; // bytes
    constexpr std::uint8_t k_tag_null          { 0x05 }; // empty placeholder; used in GET varbind values
    constexpr std::uint8_t k_tag_oid           { 0x06 }; // object identifier
    constexpr std::uint8_t k_tag_sequence      { 0x30 }; // constructed sequence

    // SNMP application-class types (top bits 01)
    constexpr std::uint8_t k_tag_ip_address    { 0x40 }; // 4-byte ipv4 address
    constexpr std::uint8_t k_tag_counter32     { 0x41 }; // unsigned 32-bit increasing counter
    constexpr std::uint8_t k_tag_gauge32       { 0x42 }; // unsigned 32-bit gauge / Unsigned32
    constexpr std::uint8_t k_tag_time_ticks    { 0x43 }; // hundredths of a second
    constexpr std::uint8_t k_tag_opaque        { 0x44 }; // wrapped raw bytes
    constexpr std::uint8_t k_tag_counter64     { 0x46 }; // unsigned 64-bit counter

    // SNMP v2c exception markers used in response varbinds
    constexpr std::uint8_t k_tag_no_such_object   { 0x80 };
    constexpr std::uint8_t k_tag_no_such_instance { 0x81 };
    constexpr std::uint8_t k_tag_end_of_mib_view  { 0x82 };

    // SNMP PDU tags (context-specific constructed, top bits 10)
    constexpr std::uint8_t k_tag_get_request      { 0xA0 };
    constexpr std::uint8_t k_tag_get_next_request { 0xA1 };
    constexpr std::uint8_t k_tag_response         { 0xA2 };
    constexpr std::uint8_t k_tag_set_request      { 0xA3 };
    constexpr std::uint8_t k_tag_get_bulk_request { 0xA5 };
    constexpr std::uint8_t k_tag_inform_request   { 0xA6 };
    constexpr std::uint8_t k_tag_trap_v2          { 0xA7 };

    // an OID is a sequence of arcs; we store them in host form (an integer per arc) and convert to BER's
    // packed first-two-arcs + variable-length-base-128 form only at encode time
    using Oid = std::vector<std::uint32_t>;

    // dotted-string helpers; round-trip via human-readable forms for logs and the dashboard
    std::string oid_to_string(const Oid& arcs);
    std::optional<Oid> oid_from_string(const std::string& s);

    // strict lexicographic ordering on the arc sequence; same as how SNMP defines OID order
    int compare_oids(const Oid& a, const Oid& b);

    // true when `child` falls strictly inside the `prefix` subtree (child's first |prefix| arcs match)
    bool is_descendant(const Oid& child, const Oid& prefix);

    // ---- encoders --------------------------------------------------------------------------------------

    // BER-encode the length field; short form (1 byte) for n < 128, long form otherwise
    std::vector<std::uint8_t> encode_length(std::size_t n);

    // wrap arbitrary contents in a tag+length envelope; works for primitive and constructed tags
    std::vector<std::uint8_t> encode_tlv(std::uint8_t tag, const std::vector<std::uint8_t>& contents);

    std::vector<std::uint8_t> encode_integer(std::int64_t v);
    std::vector<std::uint8_t> encode_octet_string(const std::string& s);
    std::vector<std::uint8_t> encode_null();
    std::vector<std::uint8_t> encode_oid(const Oid& arcs);
    std::vector<std::uint8_t> encode_sequence(const std::vector<std::uint8_t>& contents);
    std::vector<std::uint8_t> encode_counter32(std::uint32_t v);
    std::vector<std::uint8_t> encode_gauge32(std::uint32_t v);
    std::vector<std::uint8_t> encode_time_ticks(std::uint32_t v);
    std::vector<std::uint8_t> encode_ip_address(std::uint32_t addr);

    // ---- decoders --------------------------------------------------------------------------------------

    // one parsed TLV header: the tag, the offset where the value bytes start in the original buffer, the
    // length of the value, and the total bytes consumed by this TLV (tag + length-field + value)
    struct ParsedTlv
    {

        std::uint8_t m_tag { 0 };           // BER tag byte
        std::size_t m_value_offset { 0 };   // offset into the original buffer where the value begins
        std::size_t m_value_length { 0 };   // length of the value in bytes
        std::size_t m_total_size { 0 };     // tag + length-field + value, in bytes

    };

    // parse one TLV header starting at offset; returns nullopt on malformed (truncated, bad long-form
    // length, or value beyond the buffer)
    std::optional<ParsedTlv> parse_tlv(const std::uint8_t* data, std::size_t len, std::size_t offset);

    // typed value parsers; expect (data, total_buffer_len, offset_of_value, value_length)
    std::optional<std::int64_t> parse_integer_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len);
    std::optional<std::string> parse_octet_string_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len);
    std::optional<Oid> parse_oid_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len);
    std::optional<std::uint32_t> parse_uint32_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len);
    std::optional<std::uint64_t> parse_uint64_value(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t value_len);

}

#endif // NODE_MONITOR_ASN_BER_HH
