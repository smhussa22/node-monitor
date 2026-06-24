#ifndef NODE_MONITOR_ALERT_ENGINE_HH
#define NODE_MONITOR_ALERT_ENGINE_HH

// related headers
#include "MetricCache.hh"
#include "MetricStore.hh"
#include "Rule.hh"

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // periodically evaluates registered Rules against the live MetricCache and writes incidents to MetricStore
    class AlertEngine
    {

    public:

        AlertEngine() = delete;
        AlertEngine(std::shared_ptr<MetricCache> cache, std::shared_ptr<MetricStore> store);
        ~AlertEngine() = default;

        AlertEngine(const AlertEngine&) = delete;
        AlertEngine& operator=(const AlertEngine&) = delete;
        AlertEngine(AlertEngine&&) = delete;
        AlertEngine& operator=(AlertEngine&&) = delete;

        // takes ownership of a Rule; thread-safe so rules can be added at any time
        void register_rule(std::unique_ptr<Rule> rule);

        // run one evaluation pass over every registered rule against the current cache snapshot
        void evaluate();

        // total alerts ever fired by this process; useful for smoke tests and dashboards
        std::uint64_t alert_count() const noexcept;

    private:

        // per-(rule, host) state tracking when the violation first started and whether we already fired
        struct ConditionTracker
        {

            std::chrono::system_clock::time_point m_holding_since { }; // first tick the violation was observed
            bool m_fired { false }; // true once an incident row has been written for this holding period
            std::string m_last_description { }; // most recent reason string; persisted in the incident details

        };

        // diff this tick's triggers against the previous holding map to fire new alerts and resolve cleared ones
        void process_triggers(const Rule& rule, const std::vector<Trigger>& triggers, std::chrono::system_clock::time_point now);

        // emit the alert to stdout and persist a row in the incidents table
        void fire_incident(const Rule& rule, const std::string& hostname, const std::string& description, std::chrono::system_clock::time_point now);

        // mark the active incident as resolved and emit a RESOLVED line to stdout
        void resolve_incident(const Rule& rule, const std::string& hostname, std::chrono::system_clock::time_point now);

        std::shared_ptr<MetricCache> m_cache { }; // source of "what is each host doing right now"
        std::shared_ptr<MetricStore> m_store { }; // optional postgres backend; null when persistence is off
        std::vector<std::unique_ptr<Rule>> m_rules { }; // registered rule set
        std::unordered_map<std::string, ConditionTracker> m_holding { }; // key = rule_name + "|" + hostname
        mutable std::mutex m_mutex { }; // guards m_rules and m_holding from concurrent evaluate/register
        std::atomic<std::uint64_t> m_alert_count { 0 }; // monotonic count of fired alerts

    };

}

#endif // NODE_MONITOR_ALERT_ENGINE_HH
