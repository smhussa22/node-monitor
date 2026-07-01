// related headers
#include "MetricCache.hh"
#include "Metric.hh"

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <chrono>
#include <cstddef>
#include <string>
#include <thread>
#include <vector>

// 3rd party headers
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

// project headers

using namespace NodeMonitor;

namespace
{

    Metric make_metric(const std::string& hostname, double cpu = 50.0, double memory = 60.0, const std::string& vendor = "cisco")
    {

        Metric m { };
        m.m_hostname  = hostname;
        m.m_vendor    = vendor;
        m.m_cpu       = cpu;
        m.m_memory    = memory;
        m.m_timestamp = std::chrono::system_clock::now();
        m.m_payload   = ::nlohmann::json { { "health_status", "healthy" } };
        return m;

    }

}

// update then get must return the stored metric
TEST(MetricCache, UpdateAndGet)
{

    MetricCache cache { };
    cache.update(make_metric("router-1", 55.0, 70.0));

    auto result { cache.get("router-1") };
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->m_hostname, "router-1");
    EXPECT_DOUBLE_EQ(result->m_cpu, 55.0);
    EXPECT_DOUBLE_EQ(result->m_memory, 70.0);

}

// get on an unknown hostname must return nullopt
TEST(MetricCache, GetMissing)
{

    MetricCache cache { };
    EXPECT_FALSE(cache.get("ghost").has_value());

}

// a second update for the same hostname must overwrite the first
TEST(MetricCache, UpdateOverwrites)
{

    MetricCache cache { };
    cache.update(make_metric("router-1", 10.0));
    cache.update(make_metric("router-1", 99.0));

    auto result { cache.get("router-1") };
    ASSERT_TRUE(result.has_value());
    EXPECT_DOUBLE_EQ(result->m_cpu, 99.0);
    EXPECT_EQ(cache.size(), 1uz);

}

// get_all must return every cached metric
TEST(MetricCache, GetAll)
{

    MetricCache cache { };
    cache.update(make_metric("router-1"));
    cache.update(make_metric("switch-1"));
    cache.update(make_metric("firewall-1"));

    auto all { cache.get_all() };
    EXPECT_EQ(all.size(), 3uz);

}

// size must track the number of distinct hostnames
TEST(MetricCache, Size)
{

    MetricCache cache { };
    EXPECT_EQ(cache.size(), 0uz);
    cache.update(make_metric("a"));
    cache.update(make_metric("b"));
    EXPECT_EQ(cache.size(), 2uz);
    cache.update(make_metric("a"));  // overwrite, not add
    EXPECT_EQ(cache.size(), 2uz);

}

// clear must remove all entries
TEST(MetricCache, Clear)
{

    MetricCache cache { };
    cache.update(make_metric("router-1"));
    cache.update(make_metric("router-2"));
    cache.clear();

    EXPECT_EQ(cache.size(), 0uz);
    EXPECT_FALSE(cache.get("router-1").has_value());

}

// concurrent updates from multiple threads must not data-race and must converge to consistent state
TEST(MetricCache, ThreadSafeConcurrentUpdates)
{

    MetricCache cache { };
    constexpr std::size_t k_threads    { 8uz };
    constexpr std::size_t k_hostnames  { 4uz };
    constexpr std::size_t k_iterations { 500uz };

    std::vector<std::thread> threads { };
    threads.reserve(k_threads);

    for (std::size_t t { 0uz }; t < k_threads; ++t)
    {

        threads.emplace_back([&cache, t]()
        {

            for (std::size_t i { 0uz }; i < k_iterations; ++i)
            {

                std::string host { "host-" + std::to_string(i % k_hostnames) };
                cache.update(make_metric(host, static_cast<double>(t), static_cast<double>(i)));

            }

        });

    }

    for (auto& t : threads) t.join();

    // after all threads finish, each hostname must be present exactly once
    EXPECT_EQ(cache.size(), k_hostnames);
    for (std::size_t h { 0uz }; h < k_hostnames; ++h)
    {

        std::string host { "host-" + std::to_string(h) };
        EXPECT_TRUE(cache.get(host).has_value());

    }

}

// concurrent get and update from different threads must not crash
TEST(MetricCache, ThreadSafeGetDuringUpdate)
{

    MetricCache cache { };
    cache.update(make_metric("target", 0.0));

    std::atomic<bool> stop { false };
    std::vector<std::thread> threads { };

    // writer thread continuously updates
    threads.emplace_back([&cache, &stop]()
    {

        double cpu { 0.0 };
        while (!stop.load(std::memory_order_relaxed))
        {

            cache.update(make_metric("target", cpu));
            cpu = (cpu + 1.0);
            if (cpu > 100.0) cpu = 0.0;

        }

    });

    // reader threads continuously get
    for (std::size_t i { 0uz }; i < 4uz; ++i)
    {

        threads.emplace_back([&cache, &stop]()
        {

            while (!stop.load(std::memory_order_relaxed))
            {

                auto r { cache.get("target") };
                (void)r;  // just verify it doesn't crash

            }

        });

    }

    std::this_thread::sleep_for(std::chrono::milliseconds { 100 });
    stop.store(true, std::memory_order_relaxed);
    for (auto& t : threads) t.join();

    EXPECT_TRUE(cache.get("target").has_value());

}
