#ifndef NODE_MONITOR_SNMP_MESSAGE_HH
#define NODE_MONITOR_SNMP_MESSAGE_HH

// related headers
#include "AsnBer.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // a varbind's value is one of a small set of typed alternatives plus the v2c exception markers.
    // we collapse the unsigned 32-bit types (Counter32, Gauge32, TimeTicks) into a single uint32 variant
    // and tag them on the outer struct via m_tag for round-tripping. exception markers are encoded as
    // their own tag values with no associated content
    struct SnmpVarbind
    {

        AsnBer::Oid m_oid { };                       // owner OID
        std::uint8_t m_value_tag { AsnBer::k_tag_null }; // BER tag of the value
        std::variant<std::monostate, std::int64_t, std::string, std::uint32_t, std::uint64_t, AsnBer::Oid> m_value { }; // typed payload

    };

    // PDU body shared by GetRequest / GetNextRequest / Response. error-status / error-index are 0 in
    // outgoing GETs; servers set them on the response when something goes wrong
    struct SnmpPdu
    {

        std::uint8_t m_pdu_tag { AsnBer::k_tag_get_request }; // GetRequest / GetNextRequest / Response
        std::int32_t m_request_id { 0 };                      // echoed in the matching Response
        std::int32_t m_error_status { 0 };                    // 0 = noError; see RFC 3416
        std::int32_t m_error_index { 0 };                     // 1-based index of the offending varbind
        std::vector<SnmpVarbind> m_varbinds { };              // request: name + NULL; response: name + value

    };

    // top-level SNMP message: version + community + PDU
    struct SnmpMessage
    {

        std::int32_t m_version { 1 };  // 0 = v1, 1 = v2c
        std::string m_community { };   // shared-secret string in plaintext; v1 / v2c only
        SnmpPdu m_pdu { };             // wrapped PDU

    };

    // serialize a full SnmpMessage to BER bytes ready for UDP send
    std::vector<std::uint8_t> encode_snmp(const SnmpMessage& msg);

    // parse a UDP datagram into an SnmpMessage; returns nullopt on malformed input
    std::optional<SnmpMessage> decode_snmp(const std::uint8_t* data, std::size_t len);

}

#endif // NODE_MONITOR_SNMP_MESSAGE_HH
