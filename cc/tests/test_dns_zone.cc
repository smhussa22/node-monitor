// related headers
#include "DnsZone.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <string>

// 3rd party headers
#include <gtest/gtest.h>

// project headers

using namespace NodeMonitor;

namespace
{

    constexpr std::uint32_t k_ip_a { (10u << 24u) | (42u << 16u) | 1u };  // 10.42.0.1
    constexpr std::uint32_t k_ip_b { (10u << 24u) | (42u << 16u) | 2u };  // 10.42.0.2

    DnsZone make_zone()
    {

        return DnsZone { "node-monitor.local" };

    }

}

// bind then lookup_a must return the bound IP
TEST(DnsZone, BindAndLookupA)
{

    DnsZone zone { make_zone() };
    zone.bind("router-1", k_ip_a, "dhcp");

    auto result { zone.lookup_a("router-1.node-monitor.local") };
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, k_ip_a);

}

// lookup_a for an unbound name must return nullopt
TEST(DnsZone, LookupAMissing)
{

    DnsZone zone { make_zone() };
    EXPECT_FALSE(zone.lookup_a("ghost.node-monitor.local").has_value());

}

// forward lookup must be case-insensitive per RFC 1035
TEST(DnsZone, LookupACaseInsensitive)
{

    DnsZone zone { make_zone() };
    zone.bind("Router-1", k_ip_a, "static");

    EXPECT_TRUE(zone.lookup_a("router-1.node-monitor.local").has_value());
    EXPECT_TRUE(zone.lookup_a("ROUTER-1.NODE-MONITOR.LOCAL").has_value());
    EXPECT_TRUE(zone.lookup_a("rOuTeR-1.nOdE-mOnItOr.LoCAl").has_value());

}

// bind then lookup_ptr must return the FQDN for the corresponding arpa name
TEST(DnsZone, BindAndLookupPtr)
{

    DnsZone zone { make_zone() };
    zone.bind("router-1", k_ip_a, "static");

    // 10.42.0.1 → "1.0.42.10.in-addr.arpa"
    auto result { zone.lookup_ptr("1.0.42.10.in-addr.arpa") };
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "router-1.node-monitor.local");

}

// lookup_ptr for an unbound IP must return nullopt
TEST(DnsZone, LookupPtrMissing)
{

    DnsZone zone { make_zone() };
    EXPECT_FALSE(zone.lookup_ptr("99.0.42.10.in-addr.arpa").has_value());

}

// lookup_aaaa synthesizes an IPv4-mapped IPv6 rdata (16 bytes) from the bound A record
TEST(DnsZone, LookupAaaaIpv4Mapped)
{

    DnsZone zone { make_zone() };
    zone.bind("host-1", k_ip_a, "dhcp");

    auto result { zone.lookup_aaaa("host-1.node-monitor.local") };
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 16uz);

    // RFC 4291 §2.5.5.2 IPv4-mapped prefix: ::ffff:a.b.c.d
    // bytes 0..9 = 0x00, bytes 10..11 = 0xFF, bytes 12..15 = IPv4 big-endian
    for (std::size_t i { 0uz }; i < 10uz; ++i) EXPECT_EQ((*result)[i], 0x00u);
    EXPECT_EQ((*result)[10], 0xFFu);
    EXPECT_EQ((*result)[11], 0xFFu);
    EXPECT_EQ((*result)[12], 10u);
    EXPECT_EQ((*result)[13], 42u);
    EXPECT_EQ((*result)[14], 0u);
    EXPECT_EQ((*result)[15], 1u);

}

// unbind must remove both the forward and reverse entries
TEST(DnsZone, UnbindClearsBothDirections)
{

    DnsZone zone { make_zone() };
    zone.bind("router-1", k_ip_a, "dhcp");
    zone.unbind("router-1");

    EXPECT_FALSE(zone.lookup_a("router-1.node-monitor.local").has_value());
    EXPECT_FALSE(zone.lookup_ptr("1.0.42.10.in-addr.arpa").has_value());
    EXPECT_EQ(zone.entry_count(), 0uz);

}

// rebinding to a new IP must update the reverse map and remove the old reverse entry
TEST(DnsZone, RebindUpdatesReverse)
{

    DnsZone zone { make_zone() };
    zone.bind("router-1", k_ip_a, "dhcp");
    zone.bind("router-1", k_ip_b, "dhcp");  // rebind to different IP

    EXPECT_FALSE(zone.lookup_ptr("1.0.42.10.in-addr.arpa").has_value());  // old IP gone
    auto fwd { zone.lookup_a("router-1.node-monitor.local") };
    ASSERT_TRUE(fwd.has_value());
    EXPECT_EQ(*fwd, k_ip_b);

}

// covers returns true for names inside the zone, false for names outside
TEST(DnsZone, Covers)
{

    DnsZone zone { make_zone() };
    EXPECT_TRUE(zone.covers("host.node-monitor.local"));
    EXPECT_TRUE(zone.covers("HOST.NODE-MONITOR.LOCAL"));
    EXPECT_FALSE(zone.covers("host.example.com"));
    EXPECT_FALSE(zone.covers("node-monitor.local.evil.com"));

}

// snapshot returns one entry per bound name
TEST(DnsZone, Snapshot)
{

    DnsZone zone { make_zone() };
    zone.bind("a", k_ip_a, "static");
    zone.bind("b", k_ip_b, "dhcp");

    auto entries { zone.snapshot() };
    EXPECT_EQ(entries.size(), 2uz);

    // check that both entries are present (order not guaranteed)
    bool found_a { false };
    bool found_b { false };
    for (const auto& e : entries)
    {

        if (e.m_fqdn == "a.node-monitor.local" && e.m_ip == k_ip_a) found_a = true;
        if (e.m_fqdn == "b.node-monitor.local" && e.m_ip == k_ip_b) found_b = true;

    }
    EXPECT_TRUE(found_a);
    EXPECT_TRUE(found_b);

}

// unbinding a name that was never bound must not crash
TEST(DnsZone, UnbindNonExistent)
{

    DnsZone zone { make_zone() };
    EXPECT_NO_THROW(zone.unbind("phantom"));
    EXPECT_EQ(zone.entry_count(), 0uz);

}
