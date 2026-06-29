// related headers
#include "PortScanRule.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <format>
#include <string>
#include <vector>

// 3rd party headers

// project headers
#include "MetricStore.hh"

namespace NodeMonitor
{

    PortScanRule::PortScanRule(const std::string& name, std::uint32_t min_distinct_ports, std::chrono::seconds window, std::chrono::seconds sustained, const std::string& severity)
        : m_name { name }, m_min_distinct_ports { min_distinct_ports }, m_window { window }, m_sustained { sustained }, m_severity { severity }
    {

    }

    std::string PortScanRule::name() const
    {

        return m_name;

    }

    std::string PortScanRule::severity() const
    {

        return m_severity;

    }

    std::chrono::seconds PortScanRule::sustained_for() const
    {

        return m_sustained;

    }

    std::vector<Trigger> PortScanRule::tick(const TickContext& ctx) const
    {

        std::vector<Trigger> triggers { };
        if (ctx.m_store == nullptr) return triggers;

        // ask postgres for the offenders; the query is bounded by LIMIT 100 + the time window so it stays
        // cheap even at scale. emits one trigger per offending src_ip so the incident page lists them
        // individually rather than aggregating
        auto candidates { ctx.m_store->find_port_scan_sources(m_window, m_min_distinct_ports) };
        for (const auto& [src_ip, port_count] : candidates)
        {
            triggers.push_back({ src_ip, std::format("contacted {} distinct dst ports in the last {}s (threshold {})", port_count, m_window.count(), m_min_distinct_ports) });
        }
        return triggers;

    }

}
