#ifndef NODE_MONITOR_PORT_SCAN_RULE_HH
#define NODE_MONITOR_PORT_SCAN_RULE_HH

// related headers
#include "Rule.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // fires per src_ip that contacted at least m_min_distinct_ports unique dst_ports within m_window. the
    // classic horizontal-scan fingerprint; uses the existing flows table (populated by NetflowReceiver +
    // AclEngine) so no new wire path is needed. queries postgres on each tick via the store on TickContext
    class PortScanRule : public Rule
    {

    public:

        PortScanRule() = delete;
        PortScanRule(const std::string& name, std::uint32_t min_distinct_ports, std::chrono::seconds window, std::chrono::seconds sustained, const std::string& severity);
        ~PortScanRule() override = default;

        PortScanRule(const PortScanRule&) = delete;
        PortScanRule& operator=(const PortScanRule&) = delete;
        PortScanRule(PortScanRule&&) = delete;
        PortScanRule& operator=(PortScanRule&&) = delete;

        std::string name() const override;
        std::string severity() const override;
        std::chrono::seconds sustained_for() const override;
        std::vector<Trigger> tick(const TickContext& ctx) const override;

    private:

        std::string m_name { };                       // rule id persisted in the incidents table
        std::uint32_t m_min_distinct_ports { 50u };   // distinct-port threshold to declare a scan
        std::chrono::seconds m_window { 60 };         // look-back window for the COUNT DISTINCT query
        std::chrono::seconds m_sustained { 0 };       // hold time before AlertEngine fires
        std::string m_severity { };                   // info / warning / critical

    };

}

#endif // NODE_MONITOR_PORT_SCAN_RULE_HH
