#ifndef NODE_MONITOR_DNS_PACKET_HH
#define NODE_MONITOR_DNS_PACKET_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // RFC 1035 record types; we implement A and PTR fully, and parse other types as opaque rdata so we can
    // round-trip them without losing information
    enum class DnsType : std::uint16_t
    {

        A     = 1,   // ipv4 address
        NS    = 2,   // authoritative name server
        CNAME = 5,   // canonical name alias
        SOA   = 6,   // start of authority
        PTR   = 12,  // reverse lookup pointer
        MX    = 15,  // mail exchanger
        TXT   = 16,  // free-form text
        AAAA  = 28,  // ipv6 address

    };

    // class field; "IN" (Internet) is the only one anyone uses in practice
    enum class DnsClass : std::uint16_t
    {

        IN = 1,

    };

    // standard RFC 1035 response codes set in the lower 4 bits of the header flags
    enum class DnsRcode : std::uint8_t
    {

        NoError  = 0, // query handled successfully
        FormErr  = 1, // query was malformed
        ServFail = 2, // internal failure
        NxDomain = 3, // queried name does not exist
        NotImpl  = 4, // query type not implemented
        Refused  = 5, // server refuses to answer (e.g. outside our zone)

    };

    // standard message opcode set in bits 11..14 of the header flags; standard Query is the only one we serve
    enum class DnsOpcode : std::uint8_t
    {

        Query   = 0,
        IQuery  = 1,
        Status  = 2,
        Notify  = 4,
        Update  = 5,

    };

    // 12-byte fixed header (RFC 1035 section 4.1.1). all multi-byte fields are big-endian on the wire.
    // m_flags packs QR(1) | Opcode(4) | AA(1) | TC(1) | RD(1) | RA(1) | Z(3) | RCODE(4)
    struct DnsHeader
    {

        std::uint16_t m_id { 0 };       // transaction id; echoed by the server in the response
        std::uint16_t m_flags { 0 };    // packed flag bits (see above)
        std::uint16_t m_qdcount { 0 };  // question count
        std::uint16_t m_ancount { 0 };  // answer record count
        std::uint16_t m_nscount { 0 };  // authority record count
        std::uint16_t m_arcount { 0 };  // additional record count

    };

    // one entry in the question section; m_name is the fully-decoded dotted name without the trailing dot
    struct DnsQuestion
    {

        std::string m_name { };                // e.g. "collector.node-monitor.local"
        DnsType m_qtype { DnsType::A };        // query type (A / PTR / etc.)
        DnsClass m_qclass { DnsClass::IN };    // query class; almost always IN

    };

    // one resource record; m_rdata is the raw rdata bytes encoded per type (4 bytes for A, encoded name
    // for PTR/NS/CNAME, etc.). decoders for typed access can be added as needed
    struct DnsRR
    {

        std::string m_name { };                // owner name
        DnsType m_type { DnsType::A };         // record type
        DnsClass m_class { DnsClass::IN };     // record class; almost always IN
        std::uint32_t m_ttl { 300 };           // cache lifetime in seconds; defaults to 5 minutes
        std::vector<std::uint8_t> m_rdata { }; // type-specific payload (raw bytes)

    };

    // a fully-decoded DNS message; the four sections after the header
    struct DnsPacket
    {

        DnsHeader m_header { };                       // 12-byte header
        std::vector<DnsQuestion> m_questions { };     // question section
        std::vector<DnsRR> m_answers { };             // answer section
        std::vector<DnsRR> m_authority { };           // authority section
        std::vector<DnsRR> m_additional { };          // additional section

    };

    // flag bit packers / unpackers; small helpers so callers don't have to remember the layout
    void set_qr(DnsHeader& h, bool is_response);
    void set_opcode(DnsHeader& h, DnsOpcode op);
    void set_aa(DnsHeader& h, bool authoritative);
    void set_rd(DnsHeader& h, bool recursion_desired);
    void set_ra(DnsHeader& h, bool recursion_available);
    void set_rcode(DnsHeader& h, DnsRcode rc);
    bool get_qr(const DnsHeader& h);
    DnsOpcode get_opcode(const DnsHeader& h);
    bool get_rd(const DnsHeader& h);
    DnsRcode get_rcode(const DnsHeader& h);

    // encode a 4-byte ipv4 (host byte order) into the 4-byte rdata an A record carries
    std::vector<std::uint8_t> encode_a_rdata(std::uint32_t addr);

    // decode A rdata back to a host-byte-order uint32; returns 0 on malformed
    std::uint32_t decode_a_rdata(const std::vector<std::uint8_t>& rdata);

    // encode a dotted name (e.g. "host.example.com") into wire-format labels; never emits a compression
    // pointer because encoders MAY skip compression per RFC 1035 (decoders MUST handle it)
    std::vector<std::uint8_t> encode_name_uncompressed(const std::string& name);

    // build the "<reversed-octets>.in-addr.arpa" name used in PTR queries for an ipv4 address
    std::string ipv4_to_arpa(std::uint32_t addr);

    // decode a wire-format DNS message. returns nullopt on malformed input (bad length, malformed labels,
    // compression-pointer loops, truncated rdata, etc.). the decoder transparently follows compression
    // pointers with a hop limit so adversarial packets can't loop us
    std::optional<DnsPacket> decode_dns(const std::uint8_t* data, std::size_t len);

    // serialize a DNS message; emits header + four sections. names are written uncompressed for simplicity
    std::vector<std::uint8_t> encode_dns(const DnsPacket& packet);

}

#endif // NODE_MONITOR_DNS_PACKET_HH
