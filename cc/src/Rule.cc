// related headers
#include "Rule.hh"

// c sys headers

// cpp stdlib headers
#include <cmath>
#include <format>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers

namespace NodeMonitor
{

    std::optional<double> extract_numeric(const Metric& metric, const std::string& field_path)
    {

        // top-level Metric fields are handled directly so we never need to materialize them into the json payload
        if (field_path == "cpu") return metric.m_cpu;
        if (field_path == "memory") return metric.m_memory;

        // anything else is a json pointer into m_payload; missing fields or wrong types return nullopt instead of throwing
        try
        {
            ::nlohmann::json::json_pointer ptr { field_path };
            if (!metric.m_payload.contains(ptr)) return std::nullopt;
            const auto& val { metric.m_payload.at(ptr) };
            if (val.is_number()) return val.get<double>();
        }
        catch (const std::exception&)
        {
            return std::nullopt;
        }
        return std::nullopt;

    }

    // helper used by ThresholdRule and RateOfChangeRule to keep the comparison logic in one place
    namespace
    {

        bool compare(double left, const std::string& op, double right)
        {

            if (op == ">") return left > right;
            if (op == "<") return left < right;
            if (op == ">=") return left >= right;
            if (op == "<=") return left <= right;
            if (op == "==") return left == right;
            if (op == "!=") return left != right;
            return false;

        }

    }

    // ----- ThresholdRule -----

    ThresholdRule::ThresholdRule(const std::string& name, const std::string& field_path, const std::string& op, double threshold, std::chrono::seconds sustained, const std::string& severity, const std::string& vendor_filter)
        : m_name { name }, m_field_path { field_path }, m_op { op }, m_threshold { threshold }, m_sustained { sustained }, m_severity { severity }, m_vendor_filter { vendor_filter }
    {

    }

    std::string ThresholdRule::name() const
    {

        return m_name;

    }

    std::string ThresholdRule::severity() const
    {

        return m_severity;

    }

    std::chrono::seconds ThresholdRule::sustained_for() const
    {

        return m_sustained;

    }

    std::vector<Trigger> ThresholdRule::tick(const TickContext& ctx) const
    {

        std::vector<Trigger> triggers { };
        for (const auto& metric : ctx.m_metrics)
        {
            if (!m_vendor_filter.empty() && metric.m_vendor != m_vendor_filter) continue;
            auto value { extract_numeric(metric, m_field_path) };
            if (!value.has_value()) continue;
            if (compare(*value, m_op, m_threshold))
                triggers.push_back({ metric.m_hostname, std::format("{} {} {} (got {:.2f})", m_field_path, m_op, m_threshold, *value) });
        }
        return triggers;

    }

    // ----- OfflineRule -----

    OfflineRule::OfflineRule(const std::string& name, std::chrono::seconds offline_threshold, const std::string& severity)
        : m_name { name }, m_offline_threshold { offline_threshold }, m_severity { severity }
    {

    }

    std::string OfflineRule::name() const
    {

        return m_name;

    }

    std::string OfflineRule::severity() const
    {

        return m_severity;

    }

    std::chrono::seconds OfflineRule::sustained_for() const
    {

        // offline detection already includes a time threshold so we fire as soon as the condition is true
        return std::chrono::seconds { 0 };

    }

    std::vector<Trigger> OfflineRule::tick(const TickContext& ctx) const
    {

        std::vector<Trigger> triggers { };
        for (const auto& metric : ctx.m_metrics)
        {
            auto age { ctx.m_now - metric.m_timestamp };
            if (age > m_offline_threshold)
            {
                auto seconds { std::chrono::duration_cast<std::chrono::seconds>(age).count() };
                triggers.push_back({ metric.m_hostname, std::format("no metric for {}s", seconds) });
            }
        }
        return triggers;

    }

    // ----- StateChangeRule -----

    StateChangeRule::StateChangeRule(const std::string& name, const std::string& target_state, std::chrono::seconds sustained, const std::string& severity)
        : m_name { name }, m_target_state { target_state }, m_sustained { sustained }, m_severity { severity }
    {

    }

    std::string StateChangeRule::name() const
    {

        return m_name;

    }

    std::string StateChangeRule::severity() const
    {

        return m_severity;

    }

    std::chrono::seconds StateChangeRule::sustained_for() const
    {

        return m_sustained;

    }

    std::vector<Trigger> StateChangeRule::tick(const TickContext& ctx) const
    {

        std::vector<Trigger> triggers { };
        for (const auto& metric : ctx.m_metrics)
        {
            auto state { metric.m_payload.value("health_status", std::string { }) };
            if (state == m_target_state)
                triggers.push_back({ metric.m_hostname, std::format("health_status={}", state) });
        }
        return triggers;

    }

    // ----- RateOfChangeRule -----

    RateOfChangeRule::RateOfChangeRule(const std::string& name, const std::string& field_path, double min_delta, std::chrono::seconds window, const std::string& severity)
        : m_name { name }, m_field_path { field_path }, m_min_delta { min_delta }, m_window { window }, m_severity { severity }
    {

    }

    std::string RateOfChangeRule::name() const
    {

        return m_name;

    }

    std::string RateOfChangeRule::severity() const
    {

        return m_severity;

    }

    std::chrono::seconds RateOfChangeRule::sustained_for() const
    {

        // the rate window itself is the sustained dimension; fire immediately on detection
        return std::chrono::seconds { 0 };

    }

    std::vector<Trigger> RateOfChangeRule::tick(const TickContext& ctx) const
    {

        std::vector<Trigger> triggers { };
        if (ctx.m_store == nullptr) return triggers;
        auto window_start { ctx.m_now - m_window };
        for (const auto& current : ctx.m_metrics)
        {
            auto current_val { extract_numeric(current, m_field_path) };
            if (!current_val.has_value()) continue;

            // pull history for this host across the window; query returns rows newest-first so the last entry is the oldest
            auto history { ctx.m_store->query(current.m_hostname, window_start, ctx.m_now) };
            if (history.empty()) continue;
            const auto& oldest { history.back() };
            auto baseline_val { extract_numeric(oldest, m_field_path) };
            if (!baseline_val.has_value()) continue;

            double delta { *current_val - *baseline_val };
            if (std::abs(delta) >= m_min_delta)
                triggers.push_back({ current.m_hostname, std::format("{} delta={:.1f} over {}s ({:.1f} -> {:.1f})", m_field_path, delta, m_window.count(), *baseline_val, *current_val) });
        }
        return triggers;

    }

    // ----- FlappingRule -----

    FlappingRule::FlappingRule(const std::string& name, std::uint32_t max_flips, std::chrono::seconds window, const std::string& severity)
        : m_name { name }, m_max_flips { max_flips }, m_window { window }, m_severity { severity }
    {

    }

    std::string FlappingRule::name() const
    {

        return m_name;

    }

    std::string FlappingRule::severity() const
    {

        return m_severity;

    }

    std::chrono::seconds FlappingRule::sustained_for() const
    {

        return std::chrono::seconds { 0 };

    }

    std::vector<Trigger> FlappingRule::tick(const TickContext& ctx) const
    {

        std::vector<Trigger> triggers { };
        if (ctx.m_store == nullptr) return triggers;
        auto window_start { ctx.m_now - m_window };
        for (const auto& current : ctx.m_metrics)
        {
            auto history { ctx.m_store->query(current.m_hostname, window_start, ctx.m_now) };
            if (history.size() < 2) continue;

            // walk oldest -> newest counting transitions in health_status
            std::string last_state { };
            std::uint32_t flips { 0 };
            for (auto it { history.rbegin() }; it != history.rend(); ++it)
            {
                auto state { it->m_payload.value("health_status", std::string { }) };
                if (!last_state.empty() && state != last_state) ++flips;
                last_state = state;
            }
            if (flips > m_max_flips)
                triggers.push_back({ current.m_hostname, std::format("health_status flipped {} times in {}s", flips, m_window.count()) });
        }
        return triggers;

    }

}
