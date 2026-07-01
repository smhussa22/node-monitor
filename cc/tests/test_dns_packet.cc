// related headers
#include "DnsPacket.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <string>
#include <vector>

// 3rd party headers
#include <gtest/gtest.h>

// project headers

using namespace NodeMonitor;

namespace
{

    // build a standard A query for a given name
    DnsPacket make_query(const std::string& name, DnsType qtype = DnsType::A)
    {

        DnsPacket pkt { };
        pkt.m_header.m_id = 0x1234u;
        set_qr(pkt.m_header, false);
        set_rd(pkt.m_header, true);
        pkt.m_header.m_qdcount = 1u;
        DnsQuestion q { };
        q.m_name = name;
        q.m_qtype = qtype;
        q.m_qclass = DnsClass::IN;
        pkt.m_questions.push_back(q);
        return pkt;

    }

    // build a response that carries one A record
    DnsPacket make_response(const std::string& name, std::uint32_t ip)
    {

        DnsPacket pkt { make_query(name) };
        set_qr(pkt.m_header, true);
        set_aa(pkt.m_header, true);
        pkt.m_header.m_ancount = 1u;
        DnsRR rr { };
        rr.m_name = name;
        rr.m_type = DnsType::A;
        rr.m_class = DnsClass::IN;
        rr.m_ttl = 300u;
        rr.m_rdata = encode_a_rdata(ip);
        pkt.m_answers.push_back(rr);
        return pkt;

    }

}

// a query packet must round-trip through encode → decode
TEST(DnsPacket, QueryRoundtrip)
{

    DnsPacket original { make_query("collector.node-monitor.local") };
    std::vector<std::uint8_t> wire { encode_dns(original) };
    auto decoded { decode_dns(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->m_header.m_id, 0x1234u);
    EXPECT_FALSE(get_qr(decoded->m_header));
    EXPECT_TRUE(get_rd(decoded->m_header));
    ASSERT_EQ(decoded->m_questions.size(), 1uz);
    EXPECT_EQ(decoded->m_questions[0].m_name, "collector.node-monitor.local");
    EXPECT_EQ(decoded->m_questions[0].m_qtype, DnsType::A);

}

// a response with an A record must round-trip
TEST(DnsPacket, ResponseRoundtrip)
{

    std::uint32_t ip { (10u << 24u) | (42u << 16u) | 7u };
    DnsPacket original { make_response("router-1.node-monitor.local", ip) };
    std::vector<std::uint8_t> wire { encode_dns(original) };
    auto decoded { decode_dns(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(get_qr(decoded->m_header));
    ASSERT_EQ(decoded->m_answers.size(), 1uz);
    EXPECT_EQ(decoded->m_answers[0].m_type, DnsType::A);
    EXPECT_EQ(decode_a_rdata(decoded->m_answers[0].m_rdata), ip);

}

// decode must return nullopt for an empty buffer
TEST(DnsPacket, DecodeTooShort)
{

    std::vector<std::uint8_t> empty { };
    EXPECT_FALSE(decode_dns(empty.data(), empty.size()).has_value());

    std::vector<std::uint8_t> tiny(5uz, 0x00u);
    EXPECT_FALSE(decode_dns(tiny.data(), tiny.size()).has_value());

}

// QR bit toggle round-trips
TEST(DnsPacket, HeaderFlagsQr)
{

    DnsHeader h { };
    set_qr(h, false);
    EXPECT_FALSE(get_qr(h));
    set_qr(h, true);
    EXPECT_TRUE(get_qr(h));

}

// RCODE field round-trips for all standard codes
TEST(DnsPacket, HeaderFlagsRcode)
{

    const DnsRcode codes[] {
        DnsRcode::NoError,
        DnsRcode::FormErr,
        DnsRcode::ServFail,
        DnsRcode::NxDomain,
        DnsRcode::NotImpl,
        DnsRcode::Refused,
    };

    for (auto rc : codes)
    {

        DnsHeader h { };
        set_rcode(h, rc);
        EXPECT_EQ(get_rcode(h), rc);

    }

}

// AA flag must be independent of QR and RCODE bits
TEST(DnsPacket, HeaderFlagsAa)
{

    DnsHeader h { };
    set_qr(h, true);
    set_rcode(h, DnsRcode::NoError);
    set_aa(h, true);
    EXPECT_TRUE(get_qr(h));
    EXPECT_EQ(get_rcode(h), DnsRcode::NoError);

}

// encode_a_rdata + decode_a_rdata must be mutual inverses
TEST(DnsPacket, ARdataRoundtrip)
{

    std::uint32_t ip { (192u << 24u) | (168u << 16u) | (1u << 8u) | 100u };
    auto rdata { encode_a_rdata(ip) };
    ASSERT_EQ(rdata.size(), 4uz);
    EXPECT_EQ(decode_a_rdata(rdata), ip);

}

// decode_a_rdata on a wrong-length buffer must return 0
TEST(DnsPacket, ARdataMalformed)
{

    std::vector<std::uint8_t> bad { 0x0Au, 0x00u };  // only 2 bytes
    EXPECT_EQ(decode_a_rdata(bad), 0u);

}

// ipv4_to_arpa must produce the correct reversed-octets PTR query name
TEST(DnsPacket, Ipv4ToArpa)
{

    // 192.168.1.100 → "100.1.168.192.in-addr.arpa"
    std::uint32_t ip { (192u << 24u) | (168u << 16u) | (1u << 8u) | 100u };
    EXPECT_EQ(ipv4_to_arpa(ip), "100.1.168.192.in-addr.arpa");

}

// a PTR query and response must round-trip
TEST(DnsPacket, PtrQueryRoundtrip)
{

    std::uint32_t ip { (10u << 24u) | (42u << 16u) | 3u };
    std::string arpa { ipv4_to_arpa(ip) };
    DnsPacket q { make_query(arpa, DnsType::PTR) };
    std::vector<std::uint8_t> wire { encode_dns(q) };
    auto decoded { decode_dns(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->m_questions.size(), 1uz);
    EXPECT_EQ(decoded->m_questions[0].m_qtype, DnsType::PTR);
    EXPECT_EQ(decoded->m_questions[0].m_name, arpa);

}

// a packet with multiple questions must survive the roundtrip
TEST(DnsPacket, MultipleQuestions)
{

    DnsPacket pkt { };
    pkt.m_header.m_id = 0xABCDu;
    pkt.m_header.m_qdcount = 2u;
    set_qr(pkt.m_header, false);

    DnsQuestion q1 { };
    q1.m_name = "host-a.node-monitor.local";
    q1.m_qtype = DnsType::A;
    q1.m_qclass = DnsClass::IN;

    DnsQuestion q2 { };
    q2.m_name = "host-b.node-monitor.local";
    q2.m_qtype = DnsType::AAAA;
    q2.m_qclass = DnsClass::IN;

    pkt.m_questions.push_back(q1);
    pkt.m_questions.push_back(q2);

    std::vector<std::uint8_t> wire { encode_dns(pkt) };
    auto decoded { decode_dns(wire.data(), wire.size()) };

    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->m_questions.size(), 2uz);
    EXPECT_EQ(decoded->m_questions[0].m_name, "host-a.node-monitor.local");
    EXPECT_EQ(decoded->m_questions[1].m_name, "host-b.node-monitor.local");
    EXPECT_EQ(decoded->m_questions[1].m_qtype, DnsType::AAAA);

}

// transaction ID 0 and transaction ID 0xFFFF both round-trip without collision
TEST(DnsPacket, TransactionIdBoundaries)
{

    for (std::uint16_t id : { std::uint16_t { 0u }, std::uint16_t { 0xFFFFu } })
    {

        DnsPacket pkt { make_query("test.local") };
        pkt.m_header.m_id = id;
        std::vector<std::uint8_t> wire { encode_dns(pkt) };
        auto decoded { decode_dns(wire.data(), wire.size()) };
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded->m_header.m_id, id);

    }

}
