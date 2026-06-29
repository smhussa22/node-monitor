#ifndef NODE_MONITOR_NETFLOW_V5_PACKET_HH
#define NODE_MONITOR_NETFLOW_V5_PACKET_HH

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

    // RFC 3954 / Cisco NetFlow v5 fixed wire-format constants. one UDP datagram = 24-byte header
    // followed by up to 30 fixed-size 48-byte flow records. all multi-byte fields are big-endian
    constexpr std::size_t k_netflow_v5_header_size { 24uz };
    constexpr std::size_t k_netflow_v5_record_size { 48uz };
    constexpr std::size_t k_netflow_v5_max_records { 30uz };
    constexpr std::uint16_t k_netflow_v5_version { 5u };

    // 24-byte fixed header that every v5 datagram opens with
    struct NetflowV5Header
    {

        std::uint16_t m_version { 5u };           // protocol version; always 5 here
        std::uint16_t m_count { 0u };             // number of records that follow; 1..30
        std::uint32_t m_sys_uptime_ms { 0u };     // ms since the exporter booted
        std::uint32_t m_unix_secs { 0u };         // epoch seconds at the moment of export
        std::uint32_t m_unix_nsecs { 0u };        // residual nanoseconds component
        std::uint32_t m_flow_sequence { 0u };     // monotonic counter across all flows from this exporter
        std::uint8_t m_engine_type { 0u };        // type of exporter engine
        std::uint8_t m_engine_id { 0u };          // id of the engine within the exporter
        std::uint16_t m_sampling { 0u };          // top 2 bits = mode, bottom 14 = interval; we send 0

    };

    // 48-byte fixed flow record. IP addresses are kept in host byte order in this struct and converted
    // to big-endian at encode time — matches the convention the rest of the project uses
    struct NetflowV5Record
    {

        std::uint32_t m_src_addr { 0u };          // source ipv4 (host byte order)
        std::uint32_t m_dst_addr { 0u };          // destination ipv4 (host byte order)
        std::uint32_t m_next_hop { 0u };          // next-hop ipv4 (we set 0)
        std::uint16_t m_input { 0u };             // SNMP ifIndex of input interface
        std::uint16_t m_output { 0u };            // SNMP ifIndex of output interface
        std::uint32_t m_packets { 0u };           // dPkts — number of packets in this flow
        std::uint32_t m_octets { 0u };            // dOctets — total bytes in this flow
        std::uint32_t m_first_ms { 0u };          // sys_uptime at flow start
        std::uint32_t m_last_ms { 0u };           // sys_uptime at flow end
        std::uint16_t m_src_port { 0u };          // source TCP/UDP port; 0 for ICMP
        std::uint16_t m_dst_port { 0u };          // destination TCP/UDP port
        std::uint8_t m_pad1 { 0u };               // explicit padding to keep field alignment honest
        std::uint8_t m_tcp_flags { 0u };          // cumulative OR of TCP flags seen during the flow
        std::uint8_t m_protocol { 0u };           // IP protocol number (1=ICMP, 6=TCP, 17=UDP)
        std::uint8_t m_tos { 0u };                // IP Type of Service byte
        std::uint16_t m_src_as { 0u };            // BGP AS number of source; 0 if unknown
        std::uint16_t m_dst_as { 0u };            // BGP AS number of destination; 0 if unknown
        std::uint8_t m_src_mask { 0u };           // prefix length of source network
        std::uint8_t m_dst_mask { 0u };           // prefix length of destination network
        std::uint16_t m_pad2 { 0u };              // explicit padding

    };

    // a fully decoded v5 datagram: header + N records (count == records.size())
    struct NetflowV5Packet
    {

        NetflowV5Header m_header { };             // 24-byte header
        std::vector<NetflowV5Record> m_records { }; // 1..30 records

    };

    // serialize one v5 datagram to bytes ready for sendto(). emits big-endian for every field per the
    // wire format. caller is responsible for keeping the record count <= 30 (no internal cap; we just
    // trust the count field)
    std::vector<std::uint8_t> encode_netflow_v5(const NetflowV5Packet& packet);

    // decode a UDP datagram into a v5 packet. returns nullopt on any of: bad version, malformed length,
    // count above the spec maximum, or truncated record section. strict by design so malformed input
    // gets counted as a drop rather than silently producing partial flows
    std::optional<NetflowV5Packet> decode_netflow_v5(const std::uint8_t* data, std::size_t len);

    // convert an IP protocol number to a short string for the existing AclEngine + flows-table schema
    // ("TCP" / "UDP" / "ICMP" / fallback decimal)
    std::string netflow_protocol_name(std::uint8_t proto);

    // host-byte-order ipv4 -> "a.b.c.d" for the existing flows-table schema
    std::string netflow_ipv4_to_dotted(std::uint32_t addr);

}

#endif // NODE_MONITOR_NETFLOW_V5_PACKET_HH
