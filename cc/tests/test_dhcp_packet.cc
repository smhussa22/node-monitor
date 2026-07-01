// related headers
#include "DhcpPacket.hh"

// c sys headers

// cpp stdlib headers
#include <array>
#include <cstdint>
#include <vector>

// 3rd party headers
#include <gtest/gtest.h>

// project headers

using namespace NodeMonitor;

namespace
{

    // build a minimal valid DISCOVER — encode it so tests can decode from real wire bytes
    DhcpPacket make_discover(std::uint32_t xid = 0xDEADBEEFu)
    {

        DhcpPacket pkt { };
        pkt.m_op = k_bootp_request;
        pkt.m_xid = xid;
        pkt.m_chaddr[0] = 0x02u;
        pkt.m_chaddr[1] = 0xAAu;
        pkt.m_chaddr[2] = 0xBBu;
        pkt.m_chaddr[3] = 0xCCu;
        pkt.m_chaddr[4] = 0xDDu;
        pkt.m_chaddr[5] = 0xEEu;
        pkt.m_options.push_back({ static_cast<std::uint8_t>(DhcpOptionCode::MessageType), { static_cast<std::uint8_t>(DhcpMessageType::Discover) } });
        return pkt;

    }

}

// a DISCOVER encoded and then decoded must produce the same field values
TEST(DhcpPacket, EncodeDecodeRoundtrip)
{

    DhcpPacket original { make_discover() };
    std::vector<std::uint8_t> wire { encode_dhcp(original) };
    auto decoded { decode_dhcp(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->m_op, k_bootp_request);
    EXPECT_EQ(decoded->m_xid, 0xDEADBEEFu);
    EXPECT_EQ(decoded->m_chaddr[0], 0x02u);
    EXPECT_EQ(decoded->m_chaddr[1], 0xAAu);
    EXPECT_EQ(decoded->m_chaddr[5], 0xEEu);

}

// option 53 must survive the roundtrip as DISCOVER
TEST(DhcpPacket, MessageTypeDiscover)
{

    DhcpPacket original { make_discover() };
    std::vector<std::uint8_t> wire { encode_dhcp(original) };
    auto decoded { decode_dhcp(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    auto type { get_message_type(*decoded) };
    ASSERT_TRUE(type.has_value());
    EXPECT_EQ(*type, DhcpMessageType::Discover);

}

// get_message_type returns nullopt when option 53 is absent
TEST(DhcpPacket, MessageTypeMissingOption)
{

    DhcpPacket pkt { };
    pkt.m_op = k_bootp_request;
    pkt.m_xid = 0x1u;
    // no MessageType option
    std::vector<std::uint8_t> wire { encode_dhcp(pkt) };
    auto decoded { decode_dhcp(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    EXPECT_FALSE(get_message_type(*decoded).has_value());

}

// all six DORA-plus message types round-trip correctly
TEST(DhcpPacket, AllMessageTypesRoundtrip)
{

    const std::array<DhcpMessageType, 6uz> types {
        DhcpMessageType::Offer,
        DhcpMessageType::Request,
        DhcpMessageType::Ack,
        DhcpMessageType::Nak,
        DhcpMessageType::Release,
        DhcpMessageType::Inform,
    };

    for (auto msg_type : types)
    {

        DhcpPacket pkt { };
        pkt.m_op = k_bootp_request;
        pkt.m_options.push_back({ static_cast<std::uint8_t>(DhcpOptionCode::MessageType), { static_cast<std::uint8_t>(msg_type) } });
        std::vector<std::uint8_t> wire { encode_dhcp(pkt) };
        auto decoded { decode_dhcp(wire.data(), wire.size()) };
        ASSERT_TRUE(decoded.has_value());
        auto t { get_message_type(*decoded) };
        ASSERT_TRUE(t.has_value());
        EXPECT_EQ(*t, msg_type);

    }

}

// a buffer shorter than the DHCP minimum must return nullopt
TEST(DhcpPacket, DecodeTooShort)
{

    std::vector<std::uint8_t> tiny(k_dhcp_header_size - 1uz, 0x00u);
    EXPECT_FALSE(decode_dhcp(tiny.data(), tiny.size()).has_value());

}

// a correctly-sized buffer with a wrong magic cookie must return nullopt
TEST(DhcpPacket, DecodeBadMagicCookie)
{

    DhcpPacket original { make_discover() };
    std::vector<std::uint8_t> wire { encode_dhcp(original) };

    // corrupt the cookie bytes (offset 236..239)
    wire[236] = 0xFFu;
    wire[237] = 0xFFu;
    wire[238] = 0xFFu;
    wire[239] = 0xFFu;

    EXPECT_FALSE(decode_dhcp(wire.data(), wire.size()).has_value());

}

// get_option retrieves value bytes for a present option
TEST(DhcpPacket, GetOptionPresent)
{

    DhcpPacket pkt { make_discover() };
    std::vector<std::uint8_t> wire { encode_dhcp(pkt) };
    auto decoded { decode_dhcp(wire.data(), wire.size()) };
    ASSERT_TRUE(decoded.has_value());

    auto opt { get_option(*decoded, DhcpOptionCode::MessageType) };
    ASSERT_TRUE(opt.has_value());
    EXPECT_EQ(opt->size(), 1uz);
    EXPECT_EQ((*opt)[0], static_cast<std::uint8_t>(DhcpMessageType::Discover));

}

// get_option returns nullopt for an option not in the packet
TEST(DhcpPacket, GetOptionAbsent)
{

    DhcpPacket pkt { make_discover() };
    std::vector<std::uint8_t> wire { encode_dhcp(pkt) };
    auto decoded { decode_dhcp(wire.data(), wire.size()) };
    ASSERT_TRUE(decoded.has_value());

    EXPECT_FALSE(get_option(*decoded, DhcpOptionCode::RequestedIp).has_value());

}

// mac_pack followed by mac_unpack must reproduce the original 6 bytes
TEST(DhcpPacket, MacPackUnpackRoundtrip)
{

    std::array<std::uint8_t, 16uz> chaddr { };
    chaddr[0] = 0x02u;
    chaddr[1] = 0xAAu;
    chaddr[2] = 0xBBu;
    chaddr[3] = 0xCCu;
    chaddr[4] = 0xDDu;
    chaddr[5] = 0xEEu;

    std::uint64_t packed { mac_pack(chaddr) };
    auto unpacked { mac_unpack(packed) };

    EXPECT_EQ(unpacked[0], 0x02u);
    EXPECT_EQ(unpacked[1], 0xAAu);
    EXPECT_EQ(unpacked[2], 0xBBu);
    EXPECT_EQ(unpacked[3], 0xCCu);
    EXPECT_EQ(unpacked[4], 0xDDu);
    EXPECT_EQ(unpacked[5], 0xEEu);

}

// mac_to_string must produce the canonical colon-separated hex form
TEST(DhcpPacket, MacToString)
{

    std::array<std::uint8_t, 16uz> chaddr { };
    chaddr[0] = 0x02u;
    chaddr[1] = 0xAAu;
    chaddr[2] = 0xBBu;
    chaddr[3] = 0xCCu;
    chaddr[4] = 0xDDu;
    chaddr[5] = 0xEEu;
    std::uint64_t packed { mac_pack(chaddr) };
    EXPECT_EQ(mac_to_string(packed), "02:aa:bb:cc:dd:ee");

}

// ipv4_to_dotted must produce the human-readable dotted-quad string
TEST(DhcpPacket, Ipv4ToDotted)
{

    // 10.42.0.7 in host byte order
    std::uint32_t addr { (10u << 24u) | (42u << 16u) | 7u };
    EXPECT_EQ(ipv4_to_dotted(addr), "10.42.0.7");

}

// encoded DHCP packet must be at least 300 bytes (many clients expect this minimum)
TEST(DhcpPacket, EncodedMinimumSize)
{

    DhcpPacket pkt { make_discover() };
    std::vector<std::uint8_t> wire { encode_dhcp(pkt) };
    EXPECT_GE(wire.size(), 300uz);

}

// yiaddr and requested-ip option must survive the roundtrip for an ACK
TEST(DhcpPacket, AckYiaddrRoundtrip)
{

    DhcpPacket ack { };
    ack.m_op = k_bootp_reply;
    ack.m_xid = 0xCAFEu;
    ack.m_yiaddr = (10u << 24u) | (42u << 16u) | 5u;
    ack.m_options.push_back({ static_cast<std::uint8_t>(DhcpOptionCode::MessageType), { static_cast<std::uint8_t>(DhcpMessageType::Ack) } });

    std::vector<std::uint8_t> wire { encode_dhcp(ack) };
    auto decoded { decode_dhcp(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->m_yiaddr, ack.m_yiaddr);
    EXPECT_EQ(decoded->m_xid, 0xCAFEu);

}
