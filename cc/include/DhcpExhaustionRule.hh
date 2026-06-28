#ifndef NODE_MONITOR_DHCP_EXHAUSTION_RULE_HH
#define NODE_MONITOR_DHCP_EXHAUSTION_RULE_HH

// related headers
#include "DhcpServer.hh"
#include "Rule.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <memory>
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // fires when the dhcp pool's free-address fraction drops below m_min_free_ratio. samples the server's
    // free_count() / total_count() at each tick rather than tracking per-event state, so the rule has no
    // moving pieces and is safe to register against a live DhcpServer. uses a sentinel hostname so the
    // incident table groups every exhaustion event under one row instead of fanning out per client
    class DhcpExhaustionRule : public Rule
    {

    public:

        DhcpExhaustionRule() = delete;
        DhcpExhaustionRule(const std::string& name, double min_free_ratio, std::chrono::seconds sustained, const std::string& severity, std::shared_ptr<DhcpServer> server);
        ~DhcpExhaustionRule() override = default;

        DhcpExhaustionRule(const DhcpExhaustionRule&) = delete;
        DhcpExhaustionRule& operator=(const DhcpExhaustionRule&) = delete;
        DhcpExhaustionRule(DhcpExhaustionRule&&) = delete;
        DhcpExhaustionRule& operator=(DhcpExhaustionRule&&) = delete;

        std::string name() const override;
        std::string severity() const override;
        std::chrono::seconds sustained_for() const override;
        std::vector<Trigger> tick(const TickContext& ctx) const override;

    private:

        std::string m_name { };                       // rule id persisted in the incidents table
        double m_min_free_ratio { 0.10 };             // fire when free / total < this (default 10%)
        std::chrono::seconds m_sustained { 0 };       // how long the low-free condition must hold to fire
        std::string m_severity { };                   // info / warning / critical
        std::shared_ptr<DhcpServer> m_server { };     // dhcp server we sample free / total from

    };

}

#endif // NODE_MONITOR_DHCP_EXHAUSTION_RULE_HH
