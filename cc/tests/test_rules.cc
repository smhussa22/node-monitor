// related headers
#include "Rule.hh"
#include "Metric.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <string>
#include <vector>

// 3rd party headers
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

// project headers

using namespace NodeMonitor;

namespace
{

    // build a metric with explicit cpu / memory and an optional health_status in the payload
    Metric make_metric(const std::string& hostname, double cpu, double memory,
                        const std::string& vendor = "cisco",
                        const std::string& health_status = "healthy",
                        std::chrono::system_clock::time_point ts = std::chrono::system_clock::now())
    {

        Metric m { };
        m.m_hostname  = hostname;
        m.m_vendor    = vendor;
        m.m_cpu       = cpu;
        m.m_memory    = memory;
        m.m_timestamp = ts;
        m.m_payload   = ::nlohmann::json { { "health_status", health_status } };
        return m;

    }

    TickContext make_ctx(const std::vector<Metric>& metrics, std::chrono::system_clock::time_point now = std::chrono::system_clock::now())
    {

        return TickContext { metrics, now, nullptr };

    }

}

// ============================================================
//  extract_numeric
// ============================================================

// top-level "cpu" field must be extracted directly
TEST(ExtractNumeric, CpuField)
{

    Metric m { make_metric("h", 75.5, 60.0) };
    auto val { extract_numeric(m, "cpu") };
    ASSERT_TRUE(val.has_value());
    EXPECT_DOUBLE_EQ(*val, 75.5);

}

// top-level "memory" field must be extracted directly
TEST(ExtractNumeric, MemoryField)
{

    Metric m { make_metric("h", 10.0, 88.3) };
    auto val { extract_numeric(m, "memory") };
    ASSERT_TRUE(val.has_value());
    EXPECT_DOUBLE_EQ(*val, 88.3);

}

// a JSON pointer into m_payload must resolve to the embedded number
TEST(ExtractNumeric, JsonPointerField)
{

    Metric m { };
    m.m_hostname = "h";
    m.m_cpu      = 0.0;
    m.m_memory   = 0.0;
    m.m_payload  = ::nlohmann::json { { "bgp_peers", 2 } };

    auto val { extract_numeric(m, "/bgp_peers") };
    ASSERT_TRUE(val.has_value());
    EXPECT_DOUBLE_EQ(*val, 2.0);

}

// a missing JSON pointer field must return nullopt without throwing
TEST(ExtractNumeric, MissingField)
{

    Metric m { make_metric("h", 0.0, 0.0) };
    EXPECT_FALSE(extract_numeric(m, "/nonexistent").has_value());

}

// a non-numeric JSON field must return nullopt
TEST(ExtractNumeric, NonNumericField)
{

    Metric m { };
    m.m_payload = ::nlohmann::json { { "status", "up" } };
    EXPECT_FALSE(extract_numeric(m, "/status").has_value());

}

// ============================================================
//  ThresholdRule
// ============================================================

// cpu > 80 must fire for devices above the threshold and not for those below
TEST(ThresholdRule, CpuAboveThresholdFires)
{

    ThresholdRule rule { "high_cpu", "cpu", ">", 80.0, std::chrono::seconds { 0 }, "critical" };

    std::vector<Metric> metrics {
        make_metric("router-1", 90.0, 50.0),  // above
        make_metric("router-2", 70.0, 50.0),  // below
    };
    auto ctx { make_ctx(metrics) };
    auto triggers { rule.tick(ctx) };

    ASSERT_EQ(triggers.size(), 1uz);
    EXPECT_EQ(triggers[0].m_hostname, "router-1");

}

// cpu <= threshold must produce no triggers
TEST(ThresholdRule, CpuBelowThresholdNoFire)
{

    ThresholdRule rule { "high_cpu", "cpu", ">", 80.0, std::chrono::seconds { 0 }, "critical" };
    std::vector<Metric> metrics { make_metric("r", 80.0, 0.0) };  // exactly at threshold
    auto ctx { make_ctx(metrics) };
    EXPECT_TRUE(rule.tick(ctx).empty());

}

// vendor_filter must restrict evaluation to only the matching vendor
TEST(ThresholdRule, VendorFilter)
{

    ThresholdRule rule { "juniper_mem", "memory", ">", 70.0, std::chrono::seconds { 0 }, "warning", "juniper" };

    std::vector<Metric> metrics {
        make_metric("cisco-1", 0.0, 90.0, "cisco"),     // high memory, wrong vendor
        make_metric("juniper-1", 0.0, 90.0, "juniper"),  // high memory, right vendor
    };
    auto ctx { make_ctx(metrics) };
    auto triggers { rule.tick(ctx) };

    ASSERT_EQ(triggers.size(), 1uz);
    EXPECT_EQ(triggers[0].m_hostname, "juniper-1");

}

// a metric without the queried field must not produce a trigger
TEST(ThresholdRule, MissingFieldNoFire)
{

    ThresholdRule rule { "bgp_check", "/bgp_peers", "<", 2.0, std::chrono::seconds { 0 }, "critical" };
    // metric payload has no bgp_peers
    std::vector<Metric> metrics { make_metric("r", 0.0, 0.0) };
    auto ctx { make_ctx(metrics) };
    EXPECT_TRUE(rule.tick(ctx).empty());

}

// multiple metrics above the threshold must each produce a separate trigger
TEST(ThresholdRule, MultipleDevicesFire)
{

    ThresholdRule rule { "high_cpu", "cpu", ">=", 90.0, std::chrono::seconds { 0 }, "critical" };
    std::vector<Metric> metrics {
        make_metric("a", 90.0, 0.0),
        make_metric("b", 95.0, 0.0),
        make_metric("c", 89.9, 0.0),
    };
    auto ctx { make_ctx(metrics) };
    auto triggers { rule.tick(ctx) };
    EXPECT_EQ(triggers.size(), 2uz);

}

// rule metadata accessors must return values given at construction
TEST(ThresholdRule, Accessors)
{

    ThresholdRule rule { "test_rule", "cpu", ">", 50.0, std::chrono::seconds { 30 }, "warning" };
    EXPECT_EQ(rule.name(), "test_rule");
    EXPECT_EQ(rule.severity(), "warning");
    EXPECT_EQ(rule.sustained_for(), std::chrono::seconds { 30 });

}

// ============================================================
//  OfflineRule
// ============================================================

// a metric timestamped in the past beyond the threshold must fire
TEST(OfflineRule, StaleMetricFires)
{

    OfflineRule rule { "device_offline", std::chrono::seconds { 60 }, "critical" };

    auto stale_ts { std::chrono::system_clock::now() - std::chrono::seconds { 120 } };
    std::vector<Metric> metrics { make_metric("router-1", 0.0, 0.0, "cisco", "healthy", stale_ts) };

    auto ctx { make_ctx(metrics) };
    auto triggers { rule.tick(ctx) };

    ASSERT_EQ(triggers.size(), 1uz);
    EXPECT_EQ(triggers[0].m_hostname, "router-1");

}

// a freshly-received metric must not trigger the offline rule
TEST(OfflineRule, FreshMetricNoFire)
{

    OfflineRule rule { "device_offline", std::chrono::seconds { 60 }, "critical" };
    std::vector<Metric> metrics { make_metric("router-1", 0.0, 0.0) };  // timestamped now
    auto ctx { make_ctx(metrics) };
    EXPECT_TRUE(rule.tick(ctx).empty());

}

// multiple stale devices must each produce a separate trigger
TEST(OfflineRule, MultipleOfflineDevices)
{

    OfflineRule rule { "device_offline", std::chrono::seconds { 30 }, "critical" };
    auto stale { std::chrono::system_clock::now() - std::chrono::seconds { 60 } };

    std::vector<Metric> metrics {
        make_metric("a", 0.0, 0.0, "cisco", "healthy", stale),
        make_metric("b", 0.0, 0.0, "cisco", "healthy", stale),
        make_metric("c", 0.0, 0.0),  // fresh
    };
    auto ctx { make_ctx(metrics) };
    auto triggers { rule.tick(ctx) };
    EXPECT_EQ(triggers.size(), 2uz);

}

// OfflineRule's sustained_for must always return 0 (the age check IS the duration)
TEST(OfflineRule, SustainedForIsZero)
{

    OfflineRule rule { "offline", std::chrono::seconds { 60 }, "critical" };
    EXPECT_EQ(rule.sustained_for(), std::chrono::seconds { 0 });

}

// ============================================================
//  StateChangeRule
// ============================================================

// a metric whose health_status matches the target must fire
TEST(StateChangeRule, MatchingStateFires)
{

    StateChangeRule rule { "degraded_device", "degraded", std::chrono::seconds { 0 }, "warning" };
    std::vector<Metric> metrics {
        make_metric("r1", 0.0, 0.0, "cisco", "degraded"),
        make_metric("r2", 0.0, 0.0, "cisco", "healthy"),
    };
    auto ctx { make_ctx(metrics) };
    auto triggers { rule.tick(ctx) };

    ASSERT_EQ(triggers.size(), 1uz);
    EXPECT_EQ(triggers[0].m_hostname, "r1");

}

// a metric whose health_status does not match must not fire
TEST(StateChangeRule, NonMatchingStateNoFire)
{

    StateChangeRule rule { "down_device", "down", std::chrono::seconds { 0 }, "critical" };
    std::vector<Metric> metrics { make_metric("r", 0.0, 0.0, "cisco", "healthy") };
    auto ctx { make_ctx(metrics) };
    EXPECT_TRUE(rule.tick(ctx).empty());

}

// an empty metric list must never fire any rule
TEST(Rules, EmptyMetricsNeverFire)
{

    ThresholdRule tr { "cpu", "cpu", ">", 0.0, std::chrono::seconds { 0 }, "critical" };
    OfflineRule   or_ { "offline", std::chrono::seconds { 0 }, "critical" };
    StateChangeRule sr { "state", "degraded", std::chrono::seconds { 0 }, "warning" };

    std::vector<Metric> empty { };
    auto ctx { make_ctx(empty) };

    EXPECT_TRUE(tr.tick(ctx).empty());
    EXPECT_TRUE(or_.tick(ctx).empty());
    EXPECT_TRUE(sr.tick(ctx).empty());

}
