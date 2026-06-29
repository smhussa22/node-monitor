// related headers
#include "DnsNxdomainRule.hh"

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

    DnsNxdomainRule::DnsNxdomainRule(const std::string& name, double threshold_per_sec, std::chrono::seconds sustained, const std::string& severity, std::shared_ptr<DnsServer> server)
        : m_name { name }, m_threshold { threshold_per_sec }, m_sustained { sustained }, m_severity { severity }, m_server { std::move(server) }
    {

    }

    std::string DnsNxdomainRule::name() const
    {

        return m_name;

    }

    std::string DnsNxdomainRule::severity() const
    {

        return m_severity;

    }

    std::chrono::seconds DnsNxdomainRule::sustained_for() const
    {

        return m_sustained;

    }

    std::vector<Trigger> DnsNxdomainRule::tick(const TickContext& ctx) const
    {

        std::vector<Trigger> triggers { };
        if (m_server == nullptr) return triggers;

        std::uint64_t current { m_server->nxdomain_count() };

        std::lock_guard<std::mutex> lock { m_mutex };

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

        if (rate > m_threshold)
            triggers.push_back({ "dns-server", std::format("nxdomain rate {:.1f}/sec exceeds threshold {:.1f}/sec ({} new negatives in {:.1f}s)", rate, m_threshold, delta, elapsed_sec) });

        return triggers;

    }

}
