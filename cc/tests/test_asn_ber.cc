// related headers
#include "AsnBer.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <string>
#include <vector>

// 3rd party headers
#include <gtest/gtest.h>

// project headers

using namespace NodeMonitor::AsnBer;

// ============================================================
//  Integer encode / decode
// ============================================================

// positive single-byte integer: tag 0x02, length 1, value 0x2A
TEST(AsnBer, EncodeInteger_Positive)
{

    auto encoded { encode_integer(42) };
    ASSERT_EQ(encoded.size(), 3uz);
    EXPECT_EQ(encoded[0], k_tag_integer);
    EXPECT_EQ(encoded[1], 0x01u);
    EXPECT_EQ(encoded[2], 0x2Au);

}

// zero: tag 0x02, length 1, value 0x00
TEST(AsnBer, EncodeInteger_Zero)
{

    auto encoded { encode_integer(0) };
    ASSERT_EQ(encoded.size(), 3uz);
    EXPECT_EQ(encoded[2], 0x00u);

}

// negative -1 in two's complement: single byte 0xFF
TEST(AsnBer, EncodeInteger_NegativeOne)
{

    auto encoded { encode_integer(-1) };
    ASSERT_EQ(encoded.size(), 3uz);
    EXPECT_EQ(encoded[2], 0xFFu);

}

// 127 fits in 1 byte; 128 needs a leading zero byte to keep the sign bit clear
TEST(AsnBer, EncodeInteger_127vs128)
{

    auto e127 { encode_integer(127) };
    auto e128 { encode_integer(128) };
    EXPECT_EQ(e127[1], 0x01u);  // length 1
    EXPECT_EQ(e128[1], 0x02u);  // length 2 (needs leading 0x00)
    EXPECT_EQ(e128[2], 0x00u);
    EXPECT_EQ(e128[3], 0x80u);

}

// ============================================================
//  Octet string encode / decode
// ============================================================

// encode + parse must reproduce the original string exactly
TEST(AsnBer, EncodeDecodeOctetString)
{

    const std::string s { "public" };
    auto encoded { encode_octet_string(s) };

    ASSERT_GE(encoded.size(), 2uz);
    EXPECT_EQ(encoded[0], k_tag_octet_string);

    auto tlv { parse_tlv(encoded.data(), encoded.size(), 0uz) };
    ASSERT_TRUE(tlv.has_value());
    auto decoded { parse_octet_string_value(encoded.data(), encoded.size(), tlv->m_value_offset, tlv->m_value_length) };
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, s);

}

// empty string must encode and decode without errors
TEST(AsnBer, OctetStringEmpty)
{

    auto encoded { encode_octet_string("") };
    ASSERT_EQ(encoded.size(), 2uz);
    EXPECT_EQ(encoded[1], 0x00u);

}

// ============================================================
//  Null
// ============================================================

// encode_null must produce exactly 2 bytes: tag + zero length
TEST(AsnBer, EncodeNull)
{

    auto encoded { encode_null() };
    ASSERT_EQ(encoded.size(), 2uz);
    EXPECT_EQ(encoded[0], k_tag_null);
    EXPECT_EQ(encoded[1], 0x00u);

}

// ============================================================
//  OID encode / decode
// ============================================================

// sysDescr OID 1.3.6.1.2.1.1.1.0 must encode to the canonical BER bytes
TEST(AsnBer, EncodeOid_SysDescr)
{

    Oid oid { 1u, 3u, 6u, 1u, 2u, 1u, 1u, 1u, 0u };
    auto encoded { encode_oid(oid) };

    EXPECT_EQ(encoded[0], k_tag_oid);
    // first two arcs: 1*40 + 3 = 43 = 0x2B
    auto tlv { parse_tlv(encoded.data(), encoded.size(), 0uz) };
    ASSERT_TRUE(tlv.has_value());
    EXPECT_EQ(encoded[tlv->m_value_offset], 0x2Bu);

}

// oid_to_string and oid_from_string must be mutual inverses
TEST(AsnBer, OidStringRoundtrip)
{

    Oid original { 1u, 3u, 6u, 1u, 2u, 1u, 1u, 5u, 0u };
    std::string s { oid_to_string(original) };
    EXPECT_EQ(s, "1.3.6.1.2.1.1.5.0");

    auto parsed { oid_from_string(s) };
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, original);

}

// oid_from_string on a malformed string must return nullopt
TEST(AsnBer, OidFromStringInvalid)
{

    EXPECT_FALSE(oid_from_string("").has_value());
    EXPECT_FALSE(oid_from_string("not.a.number").has_value());

}

// encode → parse_oid_value must round-trip the full arc sequence
TEST(AsnBer, EncodeDecodeOidRoundtrip)
{

    Oid original { 1u, 3u, 6u, 1u, 4u, 1u, 9u, 9u, 41u };
    auto encoded { encode_oid(original) };
    auto tlv { parse_tlv(encoded.data(), encoded.size(), 0uz) };
    ASSERT_TRUE(tlv.has_value());
    auto decoded { parse_oid_value(encoded.data(), encoded.size(), tlv->m_value_offset, tlv->m_value_length) };
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, original);

}

// ============================================================
//  is_descendant and compare_oids
// ============================================================

TEST(AsnBer, IsDescendant)
{

    Oid prefix { 1u, 3u, 6u, 1u };
    Oid child  { 1u, 3u, 6u, 1u, 2u, 1u };
    Oid sibling{ 1u, 3u, 6u, 2u };

    EXPECT_TRUE(is_descendant(child, prefix));
    EXPECT_FALSE(is_descendant(sibling, prefix));
    EXPECT_FALSE(is_descendant(prefix, prefix));  // must be strictly inside

}

TEST(AsnBer, CompareOids)
{

    Oid a { 1u, 3u, 6u, 1u };
    Oid b { 1u, 3u, 6u, 2u };
    Oid c { 1u, 3u, 6u, 1u };

    EXPECT_LT(compare_oids(a, b), 0);
    EXPECT_GT(compare_oids(b, a), 0);
    EXPECT_EQ(compare_oids(a, c), 0);

}

// ============================================================
//  TLV parsing
// ============================================================

// short-form length (<128) must parse with the correct offsets
TEST(AsnBer, ParseTlv_ShortForm)
{

    // manually crafted: INTEGER, length 1, value 42
    std::vector<std::uint8_t> buf { k_tag_integer, 0x01u, 0x2Au };
    auto tlv { parse_tlv(buf.data(), buf.size(), 0uz) };
    ASSERT_TRUE(tlv.has_value());
    EXPECT_EQ(tlv->m_tag, k_tag_integer);
    EXPECT_EQ(tlv->m_value_length, 1uz);
    EXPECT_EQ(tlv->m_value_offset, 2uz);
    EXPECT_EQ(tlv->m_total_size, 3uz);

}

// long-form length (>=128) using 2-byte length field
TEST(AsnBer, ParseTlv_LongForm)
{

    // tag + 0x82 (long form, 2 length bytes) + 0x01 + 0x00 (value length = 256) + 256 zero bytes
    std::vector<std::uint8_t> buf { };
    buf.push_back(k_tag_octet_string);
    buf.push_back(0x82u);   // long form, 2 bytes follow
    buf.push_back(0x01u);
    buf.push_back(0x00u);   // length = 256
    buf.resize(buf.size() + 256uz, 0x00u);

    auto tlv { parse_tlv(buf.data(), buf.size(), 0uz) };
    ASSERT_TRUE(tlv.has_value());
    EXPECT_EQ(tlv->m_value_length, 256uz);

}

// a truncated buffer must return nullopt
TEST(AsnBer, ParseTlv_Truncated)
{

    // tag present but no length byte
    std::vector<std::uint8_t> buf { k_tag_integer };
    EXPECT_FALSE(parse_tlv(buf.data(), buf.size(), 0uz).has_value());

}

// ============================================================
//  Application-class encoders
// ============================================================

TEST(AsnBer, EncodeCounter32)
{

    auto encoded { encode_counter32(0xDEADBEEFu) };
    EXPECT_EQ(encoded[0], k_tag_counter32);

}

TEST(AsnBer, EncodeTimeTicks)
{

    auto encoded { encode_time_ticks(12345u) };
    EXPECT_EQ(encoded[0], k_tag_time_ticks);

}

TEST(AsnBer, EncodeIpAddress)
{

    // 10.42.0.1 in host byte order
    std::uint32_t addr { (10u << 24u) | (42u << 16u) | 1u };
    auto encoded { encode_ip_address(addr) };
    EXPECT_EQ(encoded[0], k_tag_ip_address);
    // value must be 4 bytes big-endian: 10, 42, 0, 1
    ASSERT_EQ(encoded.size(), 6uz);  // tag + length(4) + 4 bytes
    EXPECT_EQ(encoded[2], 10u);
    EXPECT_EQ(encoded[3], 42u);
    EXPECT_EQ(encoded[4], 0u);
    EXPECT_EQ(encoded[5], 1u);

}
