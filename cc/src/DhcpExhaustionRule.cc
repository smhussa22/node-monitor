// related headers
#include "DhcpExhaustionRule.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <format>
#include <string>
#include <utility>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    DhcpExhaustionRule::DhcpExhaustionRule(const std::string& name, double min_free_ratio, std::chrono::seconds sustained, const std::string& severity, std::shared_ptr<DhcpServer> server)
        : m_name { name }, m_min_free_ratio { min_free_ratio }, m_sustained { sustained }, m_severity { severity }, m_server { std::move(server) }
    {

    }

    std::string DhcpExhaustionRule::name() const
    {

        return m_name;

    }

    std::string DhcpExhaustionRule::severity() const
    {

        return m_severity;

    }

    std::chrono::seconds DhcpExhaustionRule::sustained_for() const
    {

        return m_sustained;

    }

    std::vector<Trigger> DhcpExhaustionRule::tick(const TickContext& /*ctx*/) const
    {

        std::vector<Trigger> triggers { };
        if (m_server == nullptr) return triggers;

        std::size_t total { m_server->total_count() };
        if (total == 0uz) return triggers;

        std::size_t free { m_server->free_count() };
        double ratio { static_cast<double>(free) / static_cast<double>(total) };

        if (ratio < m_min_free_ratio)
            triggers.push_back({ "dhcp-pool", std::format("free fraction {:.1f}% below threshold {:.1f}% ({} of {} addresses available)", ratio * 100.0, m_min_free_ratio * 100.0, free, total) });

        return triggers;

    }

}
