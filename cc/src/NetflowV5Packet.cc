// related headers
#include "NetflowV5Packet.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    namespace
    {

        // big-endian readers / writers; same idiom as the other binary codecs in the project
        void write_be16(std::vector<std::uint8_t>& out, std::uint16_t v)
        {

            out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
            out.push_back(static_cast<std::uint8_t>(v & 0xFFu));

        }

        void write_be32(std::vector<std::uint8_t>& out, std::uint32_t v)
        {

            out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
            out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
            out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
            out.push_back(static_cast<std::uint8_t>(v & 0xFFu));

        }

        std::uint16_t read_be16(const std::uint8_t* p) noexcept
        {

            return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | static_cast<std::uint16_t>(p[1]));

        }

        std::uint32_t read_be32(const std::uint8_t* p) noexcept
        {

            return (static_cast<std::uint32_t>(p[0]) << 24)
                 | (static_cast<std::uint32_t>(p[1]) << 16)
                 | (static_cast<std::uint32_t>(p[2]) << 8)
                 |  static_cast<std::uint32_t>(p[3]);

        }

    }

    std::vector<std::uint8_t> encode_netflow_v5(const NetflowV5Packet& packet)
    {

        std::vector<std::uint8_t> out { };
        out.reserve(k_netflow_v5_header_size + packet.m_records.size() * k_netflow_v5_record_size);

        // 24-byte header
        write_be16(out, packet.m_header.m_version);
        write_be16(out, static_cast<std::uint16_t>(packet.m_records.size()));
        write_be32(out, packet.m_header.m_sys_uptime_ms);
        write_be32(out, packet.m_header.m_unix_secs);
        write_be32(out, packet.m_header.m_unix_nsecs);
        write_be32(out, packet.m_header.m_flow_sequence);
        out.push_back(packet.m_header.m_engine_type);
        out.push_back(packet.m_header.m_engine_id);
        write_be16(out, packet.m_header.m_sampling);

        // N × 48-byte records
        for (const auto& r : packet.m_records)
        {

            write_be32(out, r.m_src_addr);
            write_be32(out, r.m_dst_addr);
            write_be32(out, r.m_next_hop);
            write_be16(out, r.m_input);
            write_be16(out, r.m_output);
            write_be32(out, r.m_packets);
            write_be32(out, r.m_octets);
            write_be32(out, r.m_first_ms);
            write_be32(out, r.m_last_ms);
            write_be16(out, r.m_src_port);
            write_be16(out, r.m_dst_port);
            out.push_back(r.m_pad1);
            out.push_back(r.m_tcp_flags);
            out.push_back(r.m_protocol);
            out.push_back(r.m_tos);
            write_be16(out, r.m_src_as);
            write_be16(out, r.m_dst_as);
            out.push_back(r.m_src_mask);
            out.push_back(r.m_dst_mask);
            write_be16(out, r.m_pad2);

        }

        return out;

    }

    std::optional<NetflowV5Packet> decode_netflow_v5(const std::uint8_t* data, std::size_t len)
    {

        if (data == nullptr || len < k_netflow_v5_header_size) return std::nullopt;

        NetflowV5Packet pkt { };

        pkt.m_header.m_version = read_be16(data + 0);
        if (pkt.m_header.m_version != k_netflow_v5_version) return std::nullopt;

        pkt.m_header.m_count = read_be16(data + 2);
        if (pkt.m_header.m_count == 0u || pkt.m_header.m_count > k_netflow_v5_max_records) return std::nullopt;

        pkt.m_header.m_sys_uptime_ms = read_be32(data + 4);
        pkt.m_header.m_unix_secs = read_be32(data + 8);
        pkt.m_header.m_unix_nsecs = read_be32(data + 12);
        pkt.m_header.m_flow_sequence = read_be32(data + 16);
        pkt.m_header.m_engine_type = data[20];
        pkt.m_header.m_engine_id = data[21];
        pkt.m_header.m_sampling = read_be16(data + 22);

        std::size_t expected_total { k_netflow_v5_header_size + static_cast<std::size_t>(pkt.m_header.m_count) * k_netflow_v5_record_size };
        if (len < expected_total) return std::nullopt;

        pkt.m_records.reserve(pkt.m_header.m_count);
        for (std::uint16_t i { 0u }; i < pkt.m_header.m_count; ++i)
        {

            std::size_t off { k_netflow_v5_header_size + static_cast<std::size_t>(i) * k_netflow_v5_record_size };
            NetflowV5Record r { };
            r.m_src_addr  = read_be32(data + off + 0);
            r.m_dst_addr  = read_be32(data + off + 4);
            r.m_next_hop  = read_be32(data + off + 8);
            r.m_input     = read_be16(data + off + 12);
            r.m_output    = read_be16(data + off + 14);
            r.m_packets   = read_be32(data + off + 16);
            r.m_octets    = read_be32(data + off + 20);
            r.m_first_ms  = read_be32(data + off + 24);
            r.m_last_ms   = read_be32(data + off + 28);
            r.m_src_port  = read_be16(data + off + 32);
            r.m_dst_port  = read_be16(data + off + 34);
            r.m_pad1      = data[off + 36];
            r.m_tcp_flags = data[off + 37];
            r.m_protocol  = data[off + 38];
            r.m_tos       = data[off + 39];
            r.m_src_as    = read_be16(data + off + 40);
            r.m_dst_as    = read_be16(data + off + 42);
            r.m_src_mask  = data[off + 44];
            r.m_dst_mask  = data[off + 45];
            r.m_pad2      = read_be16(data + off + 46);
            pkt.m_records.push_back(r);

        }

        return pkt;

    }

    std::string netflow_protocol_name(std::uint8_t proto)
    {

        switch (proto)
        {
            case 1u:  return "ICMP";
            case 6u:  return "TCP";
            case 17u: return "UDP";
            default:  return std::to_string(proto);
        }

    }

    std::string netflow_ipv4_to_dotted(std::uint32_t addr)
    {

        return std::format("{}.{}.{}.{}", (addr >> 24) & 0xFFu, (addr >> 16) & 0xFFu, (addr >> 8) & 0xFFu, addr & 0xFFu);

    }

}
