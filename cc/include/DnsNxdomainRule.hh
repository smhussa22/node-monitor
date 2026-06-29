#ifndef NODE_MONITOR_DNS_NXDOMAIN_RULE_HH
#define NODE_MONITOR_DNS_NXDOMAIN_RULE_HH

// related headers
#include "DnsServer.hh"
#include "Rule.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor

{

    // fires when the DnsServer's NXDOMAIN rate exceeds a threshold over the elapsed time between ticks.
    // useful as a security signal: a sudden burst of negative answers usually means either a misconfigured
    // client or a name-enumeration scan against our zone. uses the sentinel hostname "dns-server" so the
    // incident page groups all events under one row rather than fanning out per missing name
    class DnsNxdomainRule : public Rule
    {

    public:

        DnsNxdomainRule() = delete;
        DnsNxdomainRule(const std::string& name, double threshold_per_sec, std::chrono::seconds sustained, const std::string& severity, std::shared_ptr<DnsServer> server);
        ~DnsNxdomainRule() override = default;

        DnsNxdomainRule(const DnsNxdomainRule&) = delete;
        DnsNxdomainRule& operator=(const DnsNxdomainRule&) = delete;
        DnsNxdomainRule(DnsNxdomainRule&&) = delete;
        DnsNxdomainRule& operator=(DnsNxdomainRule&&) = delete;

        std::string name() const override;
        std::string severity() const override;
        std::chrono::seconds sustained_for() const override;
        std::vector<Trigger> tick(const TickContext& ctx) const override;

    private:

        std::string m_name { };                              // rule id persisted in the incidents table
        double m_threshold { 0.0 };                          // nxdomains per second threshold
        std::chrono::seconds m_sustained { 0 };              // hold time before AlertEngine actually fires
        std::string m_severity { };                          // info / warning / critical
        std::shared_ptr<DnsServer> m_server { };             // dns server we sample the counter from

        mutable std::mutex m_mutex { };                      // guards the baseline state below
        mutable std::uint64_t m_last_sample { 0 };           // previous tick's nxdomain_count snapshot
        mutable std::chrono::system_clock::time_point m_last_at { }; // wall clock at the previous tick
        mutable bool m_primed { false };                     // false until the first tick has produced a baseline

    };

}

#endif // NODE_MONITOR_DNS_NXDOMAIN_RULE_HH
