// related headers
#include "NetflowV5Packet.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <vector>

// 3rd party headers
#include <gtest/gtest.h>

// project headers

using namespace NodeMonitor;

namespace
{

    NetflowV5Packet make_packet(std::uint16_t count = 1u)
    {

        NetflowV5Packet pkt { };
        pkt.m_header.m_version       = k_netflow_v5_version;
        pkt.m_header.m_count         = count;
        pkt.m_header.m_unix_secs     = 1700000000u;
        pkt.m_header.m_unix_nsecs    = 500000000u;
        pkt.m_header.m_flow_sequence = 42u;

        for (std::uint16_t i { 0u }; i < count; ++i)
        {

            NetflowV5Record rec { };
            rec.m_src_addr = (10u << 24u) | (0u << 16u) | (0u << 8u) | (1u + i);
            rec.m_dst_addr = 0x08080808u;
            rec.m_src_port = 50000u + i;
            rec.m_dst_port = 53u;
            rec.m_protocol = 17u;   // UDP
            rec.m_packets  = 10u;
            rec.m_octets   = 1000u;
            pkt.m_records.push_back(rec);

        }

        return pkt;

    }

}

// a single-record packet must survive encode → decode with every field intact
TEST(NetflowV5, EncodeDecodeRoundtrip_SingleRecord)
{

    NetflowV5Packet original { make_packet(1u) };
    std::vector<std::uint8_t> wire { encode_netflow_v5(original) };
    auto decoded { decode_netflow_v5(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->m_header.m_version, k_netflow_v5_version);
    EXPECT_EQ(decoded->m_header.m_count, 1u);
    EXPECT_EQ(decoded->m_header.m_unix_secs, 1700000000u);
    EXPECT_EQ(decoded->m_header.m_flow_sequence, 42u);

    ASSERT_EQ(decoded->m_records.size(), 1uz);
    EXPECT_EQ(decoded->m_records[0].m_dst_port, 53u);
    EXPECT_EQ(decoded->m_records[0].m_protocol, 17u);
    EXPECT_EQ(decoded->m_records[0].m_packets, 10u);
    EXPECT_EQ(decoded->m_records[0].m_octets, 1000u);

}

// a max-records packet (30 records) must round-trip without truncation
TEST(NetflowV5, EncodeDecodeRoundtrip_MaxRecords)
{

    NetflowV5Packet original { make_packet(static_cast<std::uint16_t>(k_netflow_v5_max_records)) };
    std::vector<std::uint8_t> wire { encode_netflow_v5(original) };
    auto decoded { decode_netflow_v5(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->m_header.m_count, k_netflow_v5_max_records);
    EXPECT_EQ(decoded->m_records.size(), k_netflow_v5_max_records);

}

// IP addresses must survive the host-to-network-to-host byte order transformation
TEST(NetflowV5, IpAddressByteOrder)
{

    NetflowV5Packet original { make_packet(1u) };
    original.m_records[0].m_src_addr = (192u << 24u) | (168u << 16u) | (1u << 8u) | 100u;
    original.m_records[0].m_dst_addr = (8u << 24u) | (8u << 16u) | (8u << 8u) | 8u;

    std::vector<std::uint8_t> wire { encode_netflow_v5(original) };
    auto decoded { decode_netflow_v5(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->m_records[0].m_src_addr, original.m_records[0].m_src_addr);
    EXPECT_EQ(decoded->m_records[0].m_dst_addr, original.m_records[0].m_dst_addr);

}

// a buffer shorter than the minimum header size must return nullopt
TEST(NetflowV5, DecodeTooShort)
{

    std::vector<std::uint8_t> tiny(k_netflow_v5_header_size - 1uz, 0x00u);
    EXPECT_FALSE(decode_netflow_v5(tiny.data(), tiny.size()).has_value());

}

// a datagram with version != 5 must be rejected
TEST(NetflowV5, DecodeBadVersion)
{

    NetflowV5Packet original { make_packet(1u) };
    std::vector<std::uint8_t> wire { encode_netflow_v5(original) };
    // version is the first 2 bytes, big-endian; overwrite with 9
    wire[0] = 0x00u;
    wire[1] = 0x09u;
    EXPECT_FALSE(decode_netflow_v5(wire.data(), wire.size()).has_value());

}

// a datagram claiming more than 30 records must be rejected
TEST(NetflowV5, DecodeCountExceedsMax)
{

    NetflowV5Packet original { make_packet(1u) };
    std::vector<std::uint8_t> wire { encode_netflow_v5(original) };
    // count is bytes 2..3 big-endian; set to 31
    wire[2] = 0x00u;
    wire[3] = 0x1Fu;
    EXPECT_FALSE(decode_netflow_v5(wire.data(), wire.size()).has_value());

}

// encoded wire size must equal header + count * record
TEST(NetflowV5, WireSize)
{

    for (std::uint16_t n { 1u }; n <= 5u; ++n)
    {

        NetflowV5Packet pkt { make_packet(n) };
        auto wire { encode_netflow_v5(pkt) };
        std::size_t expected { k_netflow_v5_header_size + static_cast<std::size_t>(n) * k_netflow_v5_record_size };
        EXPECT_EQ(wire.size(), expected);

    }

}

// netflow_protocol_name must return human-readable strings for known protocol numbers
TEST(NetflowV5, ProtocolName)
{

    EXPECT_EQ(netflow_protocol_name(6u),   "TCP");
    EXPECT_EQ(netflow_protocol_name(17u),  "UDP");
    EXPECT_EQ(netflow_protocol_name(1u),   "ICMP");
    // unknown protocol falls back to decimal representation
    EXPECT_EQ(netflow_protocol_name(132u), "132");

}

// netflow_ipv4_to_dotted must format the host-byte-order address correctly
TEST(NetflowV5, Ipv4ToDotted)
{

    std::uint32_t ip { (10u << 24u) | (42u << 16u) | 5u };
    EXPECT_EQ(netflow_ipv4_to_dotted(ip), "10.42.0.5");

}
