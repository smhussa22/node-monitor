// related headers
#include "AclRateRule.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <format>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    AclRateRule::AclRateRule(const std::string& name, double threshold_per_sec, std::chrono::seconds sustained, const std::string& severity, std::shared_ptr<AclEngine> engine)
        : m_name { name }, m_threshold { threshold_per_sec }, m_sustained { sustained }, m_severity { severity }, m_engine { std::move(engine) }
    {

    }

    std::string AclRateRule::name() const
    {

        return m_name;

    }

    std::string AclRateRule::severity() const
    {

        return m_severity;

    }

    std::chrono::seconds AclRateRule::sustained_for() const
    {

        return m_sustained;

    }

    std::vector<Trigger> AclRateRule::tick(const TickContext& ctx) const
    {

        std::vector<Trigger> triggers { };
        if (m_engine == nullptr) return triggers;

        std::uint64_t current { m_engine->total_denies() + m_engine->implicit_denies() };

        std::lock_guard<std::mutex> lock { m_mutex };

        // first tick after construction just establishes the baseline; we need two samples to compute a rate
        if (!m_primed)
        {
            m_last_sample = current;
            m_last_at = ctx.m_now;
            m_primed = true;
            return triggers;
        }

        double elapsed_sec { std::chrono::duration<double>(ctx.m_now - m_last_at).count() };
        if (elapsed_sec <= 0.0) return triggers;

        std::uint64_t delta { current >= m_last_sample ? current - m_last_sample : 0uz };
        double rate { static_cast<double>(delta) / elapsed_sec };

        m_last_sample = current;
        m_last_at = ctx.m_now;

        // single virtual host so the incident table groups every deny-rate event under one hostname; this
        // keeps the alert page legible instead of fanning out one row per source ip
        if (rate > m_threshold)
            triggers.push_back({ "acl-engine", std::format("denied flows rate {:.1f}/sec exceeds threshold {:.1f}/sec", rate, m_threshold) });

        return triggers;

    }

}
