// related headers
#include "DhcpPool.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>

// 3rd party headers
#include <gtest/gtest.h>

// project headers

using namespace NodeMonitor;

namespace
{

    // 10.42.0.0/29: network=.0, broadcast=.7, gateway=.1 → 5 usable IPs (.2 .. .6)
    constexpr std::uint32_t k_net     { (10u << 24u) | (42u << 16u) };
    constexpr std::uint32_t k_gateway { k_net | 1u };
    constexpr std::uint32_t k_dns     { k_net | 1u };
    constexpr std::uint8_t  k_prefix  { 29u };

    DhcpPool make_pool()
    {

        return DhcpPool { k_net, k_prefix, k_gateway, k_dns, std::chrono::seconds { 3600 } };

    }

    // tiny /30 for exhaustion tests: .0 network, .3 broadcast, .1 gateway → 1 usable IP (.2)
    constexpr std::uint32_t k_net30 { (10u << 24u) | (99u << 16u) };
    constexpr std::uint32_t k_gw30  { k_net30 | 1u };

    DhcpPool make_tiny_pool()
    {

        return DhcpPool { k_net30, 30u, k_gw30, k_gw30, std::chrono::seconds { 60 } };

    }

}

// newly constructed pool with /29 must expose the right counts
TEST(DhcpPool, InitialCounts)
{

    DhcpPool pool { make_pool() };
    EXPECT_EQ(pool.total_count(), 5uz);
    EXPECT_EQ(pool.free_count(), 5uz);
    EXPECT_EQ(pool.in_use_count(), 0uz);

}

// allocate hands out IPs sequentially from the free list
TEST(DhcpPool, SequentialAllocation)
{

    DhcpPool pool { make_pool() };
    std::uint32_t first { pool.allocate(0u) };
    std::uint32_t second { pool.allocate(0u) };

    EXPECT_NE(first, 0u);
    EXPECT_NE(second, 0u);
    EXPECT_NE(first, second);
    EXPECT_EQ(pool.free_count(), 3uz);
    EXPECT_EQ(pool.in_use_count(), 2uz);

}

// allocate honors the client's preferred IP when it is still free
TEST(DhcpPool, PreferredIpHonored)
{

    DhcpPool pool { make_pool() };
    std::uint32_t preferred { k_net | 4u };  // 10.42.0.4 — inside the /29 scope
    std::uint32_t got { pool.allocate(preferred) };

    EXPECT_EQ(got, preferred);
    EXPECT_EQ(pool.in_use_count(), 1uz);

}

// allocate ignores the preferred IP when it is already in-use and gives the next free one
TEST(DhcpPool, PreferredIpInUseFallback)
{

    DhcpPool pool { make_pool() };
    std::uint32_t preferred { k_net | 2u };
    pool.allocate(preferred);  // take it

    std::uint32_t got { pool.allocate(preferred) };
    EXPECT_NE(got, 0u);
    EXPECT_NE(got, preferred);  // should have fallen back

}

// release returns an IP to the free list so it can be reallocated
TEST(DhcpPool, ReleaseAndReallocate)
{

    DhcpPool pool { make_pool() };
    std::uint32_t ip { pool.allocate(0u) };
    ASSERT_NE(ip, 0u);

    pool.release(ip);
    EXPECT_EQ(pool.in_use_count(), 0uz);

    // the released IP must eventually come back out (pool may not give it first, so just verify it allocates something)
    std::uint32_t reacquired { pool.allocate(ip) };
    EXPECT_EQ(reacquired, ip);

}

// when all IPs are taken, allocate must return 0 (pool exhausted)
TEST(DhcpPool, Exhaustion)
{

    DhcpPool pool { make_tiny_pool() };  // only 1 usable IP
    std::uint32_t first { pool.allocate(0u) };
    EXPECT_NE(first, 0u);

    std::uint32_t none { pool.allocate(0u) };
    EXPECT_EQ(none, 0u);

}

// mark_in_use prevents the IP from being handed out by allocate
TEST(DhcpPool, MarkInUse)
{

    DhcpPool pool { make_pool() };
    std::uint32_t target { k_net | 3u };
    pool.mark_in_use(target);

    // target must not appear in subsequent allocations
    std::uint32_t a { pool.allocate(0u) };
    std::uint32_t b { pool.allocate(0u) };
    std::uint32_t c { pool.allocate(0u) };
    std::uint32_t d { pool.allocate(0u) };  // 4 of the 5 usable IPs (one was marked in-use)

    EXPECT_NE(a, target);
    EXPECT_NE(b, target);
    EXPECT_NE(c, target);
    EXPECT_NE(d, target);

}

// accessors for pool configuration must return the values given at construction
TEST(DhcpPool, Accessors)
{

    DhcpPool pool { make_pool() };
    EXPECT_EQ(pool.network(), k_net);
    EXPECT_EQ(pool.gateway(), k_gateway);
    EXPECT_EQ(pool.dns(), k_dns);
    EXPECT_EQ(pool.lease_duration(), std::chrono::seconds { 3600 });

}

// gateway IP must not be returned by allocate since it is reserved
TEST(DhcpPool, GatewayNotAllocated)
{

    DhcpPool pool { make_pool() };
    for (std::size_t i { 0uz }; i < 5uz; ++i)
    {

        std::uint32_t ip { pool.allocate(0u) };
        EXPECT_NE(ip, k_gateway);

    }

}

// construction with an out-of-range prefix must throw
TEST(DhcpPool, InvalidPrefixThrows)
{

    EXPECT_THROW(DhcpPool(k_net, 0u, k_gateway, k_dns, std::chrono::seconds { 3600 }), std::invalid_argument);
    EXPECT_THROW(DhcpPool(k_net, 31u, k_gateway, k_dns, std::chrono::seconds { 3600 }), std::invalid_argument);

}
