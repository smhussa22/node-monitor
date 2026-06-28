#ifndef NODE_MONITOR_ACL_RATE_RULE_HH
#define NODE_MONITOR_ACL_RATE_RULE_HH

// related headers
#include "AclEngine.hh"
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

    // fires when the rate of denied flows (per second) exceeds m_threshold; uses the AclEngine's monotonic
    // total_denies + implicit_denies counters and computes a rate between successive ticks. mutable state
    // is guarded by an internal mutex so AlertEngine's concurrent evaluate calls stay safe
    class AclRateRule : public Rule
    {

    public:

        AclRateRule() = delete;
        AclRateRule(const std::string& name, double threshold_per_sec, std::chrono::seconds sustained, const std::string& severity, std::shared_ptr<AclEngine> engine);
        ~AclRateRule() override = default;

        AclRateRule(const AclRateRule&) = delete;
        AclRateRule& operator=(const AclRateRule&) = delete;
        AclRateRule(AclRateRule&&) = delete;
        AclRateRule& operator=(AclRateRule&&) = delete;

        std::string name() const override;
        std::string severity() const override;
        std::chrono::seconds sustained_for() const override;
        std::vector<Trigger> tick(const TickContext& ctx) const override;

    private:

        std::string m_name { };                        // rule id persisted in the incidents table
        double m_threshold { 0.0 };                    // denied flows per second above which this rule triggers
        std::chrono::seconds m_sustained { 0 };        // how long the rate must hold to fire; used by AlertEngine
        std::string m_severity { };                    // info / warning / critical
        std::shared_ptr<AclEngine> m_engine { };       // engine we sample the denied flow counter from

        mutable std::mutex m_mutex { };                // guards the rolling state below from concurrent ticks
        mutable std::uint64_t m_last_sample { 0 };     // engine total_denies + implicit_denies at last tick
        mutable std::chrono::system_clock::time_point m_last_at { }; // wall clock at the last tick
        mutable bool m_primed { false };               // false until the first tick has produced a baseline

    };

}

#endif // NODE_MONITOR_ACL_RATE_RULE_HH
