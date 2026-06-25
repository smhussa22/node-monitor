#ifndef NODE_MONITOR_RUNBOOK_ENGINE_HH
#define NODE_MONITOR_RUNBOOK_ENGINE_HH

// related headers
#include "Action.hh"
#include "K8sClient.hh"
#include "MetricStore.hh"

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers

namespace NodeMonitor
{

    // one runbook = a named bundle of Actions that runs together when a particular rule fires
    struct Runbook
    {

        std::string m_name { }; // human-readable id; persisted in the actions table
        std::string m_rule_name { }; // alert rule this runbook is subscribed to
        std::vector<std::unique_ptr<Action>> m_actions { }; // executed in order; one failure does not stop the rest
        std::chrono::seconds m_cooldown { 0 }; // suppress re-runs against the same host for this long
        std::uint32_t m_max_per_hour { 100 }; // hard cap on total runs of this runbook across all hosts per hour
        std::uint32_t m_circuit_failure_threshold { 3 }; // open the per-action-type circuit after this many consecutive failures

    };

    // subscribes to AlertEngine fire events and runs the matching Runbook's Actions, with safety rails
    class RunbookEngine
    {

    public:

        RunbookEngine() = delete;
        RunbookEngine(std::shared_ptr<K8sClient> k8s, std::shared_ptr<MetricStore> store);
        ~RunbookEngine() = default;

        RunbookEngine(const RunbookEngine&) = delete;
        RunbookEngine& operator=(const RunbookEngine&) = delete;
        RunbookEngine(RunbookEngine&&) = delete;
        RunbookEngine& operator=(RunbookEngine&&) = delete;

        // takes ownership of the runbook and indexes it by rule name; thread-safe
        void register_runbook(Runbook book);

        // called by AlertEngine::fire_incident; runs every runbook registered for this rule
        void on_alert_fired(const std::string& rule_name, const std::string& hostname, const ::nlohmann::json& details);

        // monotonic counters for the home page tiles
        std::uint64_t total_actions() const noexcept;
        std::uint64_t total_runs() const noexcept;

        // returns the configured runbooks for the dashboard /runbooks page
        std::vector<std::tuple<std::string, std::string, std::size_t, std::uint32_t, std::uint32_t>> describe_registered() const;

    private:

        // returns true and updates state when this (runbook, host) is allowed to fire, false to suppress
        bool check_and_record_cooldown(const Runbook& book, const std::string& hostname, std::chrono::system_clock::time_point now);

        // hourly rate limit; on success records the timestamp, on failure logs a suppressed audit row
        bool check_and_record_rate_limit(const Runbook& book, const std::string& hostname, std::chrono::system_clock::time_point now);

        // simple consecutive-failure circuit breaker per (runbook, action_type)
        bool circuit_is_open(const std::string& runbook_name, const std::string& action_type) const;
        void record_circuit_outcome(const std::string& runbook_name, const std::string& action_type, bool success);

        // persist a row in the actions audit table when a MetricStore is configured
        void log_action(const Runbook& book, const std::string& action_type, const std::string& hostname, const ActionResult& result, std::chrono::system_clock::time_point started, std::chrono::system_clock::time_point completed);

        std::shared_ptr<K8sClient> m_k8s { }; // optional; null forces actions into skip/dry-run paths
        std::shared_ptr<MetricStore> m_store { }; // optional; null disables audit table persistence
        std::vector<Runbook> m_runbooks { }; // owned in declaration order; index by name as needed

        mutable std::mutex m_mutex { }; // guards every map below + m_runbooks
        std::unordered_map<std::string, std::chrono::system_clock::time_point> m_cooldown_until { }; // key = runbook|hostname
        std::unordered_map<std::string, std::deque<std::chrono::system_clock::time_point>> m_recent_runs { }; // key = runbook
        std::unordered_map<std::string, std::uint32_t> m_circuit_failures { }; // key = runbook|action_type

        std::atomic<std::uint64_t> m_total_actions { 0 }; // every Action execution attempt, incl. suppressed
        std::atomic<std::uint64_t> m_total_runs { 0 }; // every on_alert_fired that matched a registered runbook

    };

}

#endif // NODE_MONITOR_RUNBOOK_ENGINE_HH
