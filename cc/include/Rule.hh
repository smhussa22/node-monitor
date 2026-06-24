#ifndef NODE_MONITOR_RULE_HH
#define NODE_MONITOR_RULE_HH

// related headers
#include "Metric.hh"
#include "MetricStore.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // one violation of a rule for a particular host on a single evaluation tick
    struct Trigger
    {

        std::string m_hostname { }; // the host the rule triggered on
        std::string m_description { }; // short human readable why this triggered

    };

    // everything a Rule needs to make its decision on one tick of the alert engine
    struct TickContext
    {

        const std::vector<Metric>& m_metrics; // snapshot of every host's latest metric
        std::chrono::system_clock::time_point m_now { }; // wall clock at the start of this tick
        std::shared_ptr<MetricStore> m_store { }; // optional postgres history; null when persistence is off

    };

    // base type for any alert rule; each Rule produces a list of Triggers per tick
    class Rule
    {

    public:

        Rule() = default;
        virtual ~Rule() = default;

        Rule(const Rule&) = delete;
        Rule& operator=(const Rule&) = delete;
        Rule(Rule&&) = delete;
        Rule& operator=(Rule&&) = delete;

        virtual std::string name() const = 0;
        virtual std::string severity() const = 0;
        virtual std::chrono::seconds sustained_for() const = 0;
        virtual std::vector<Trigger> tick(const TickContext& ctx) const = 0;

    };

    // extract a numeric value from either a top-level Metric field or a JSON pointer into m_payload;
    // returns nullopt if the field is missing or non-numeric
    std::optional<double> extract_numeric(const Metric& metric, const std::string& field_path);

    // generic "field op threshold" rule that handles the vast majority of useful alerts
    class ThresholdRule : public Rule
    {

    public:

        ThresholdRule() = delete;
        ThresholdRule(const std::string& name, const std::string& field_path, const std::string& op, double threshold, std::chrono::seconds sustained, const std::string& severity, const std::string& vendor_filter = "");
        ~ThresholdRule() override = default;

        ThresholdRule(const ThresholdRule&) = delete;
        ThresholdRule& operator=(const ThresholdRule&) = delete;
        ThresholdRule(ThresholdRule&&) = delete;
        ThresholdRule& operator=(ThresholdRule&&) = delete;

        std::string name() const override;
        std::string severity() const override;
        std::chrono::seconds sustained_for() const override;
        std::vector<Trigger> tick(const TickContext& ctx) const override;

    private:

        std::string m_name { }; // human-readable rule id used in alerts and the incidents table
        std::string m_field_path { }; // "cpu" / "memory" / "/bgp_peers" / json pointer into payload
        std::string m_op { }; // ">" "<" ">=" "<=" "==" "!="
        double m_threshold { 0.0 }; // value the field is compared against
        std::chrono::seconds m_sustained { 0 }; // how long the condition must hold to fire
        std::string m_severity { }; // info / warning / critical
        std::string m_vendor_filter { }; // optional; only apply to metrics with this vendor

    };

    // fires when a known device hasn't pushed a metric in m_offline_threshold seconds
    class OfflineRule : public Rule
    {

    public:

        OfflineRule() = delete;
        OfflineRule(const std::string& name, std::chrono::seconds offline_threshold, const std::string& severity);
        ~OfflineRule() override = default;

        OfflineRule(const OfflineRule&) = delete;
        OfflineRule& operator=(const OfflineRule&) = delete;
        OfflineRule(OfflineRule&&) = delete;
        OfflineRule& operator=(OfflineRule&&) = delete;

        std::string name() const override;
        std::string severity() const override;
        std::chrono::seconds sustained_for() const override;
        std::vector<Trigger> tick(const TickContext& ctx) const override;

    private:

        std::string m_name { }; // rule id
        std::chrono::seconds m_offline_threshold { 0 }; // declare offline when last metric is older than this
        std::string m_severity { };

    };

    // fires while the device's health_status equals a specific value
    class StateChangeRule : public Rule
    {

    public:

        StateChangeRule() = delete;
        StateChangeRule(const std::string& name, const std::string& target_state, std::chrono::seconds sustained, const std::string& severity);
        ~StateChangeRule() override = default;

        StateChangeRule(const StateChangeRule&) = delete;
        StateChangeRule& operator=(const StateChangeRule&) = delete;
        StateChangeRule(StateChangeRule&&) = delete;
        StateChangeRule& operator=(StateChangeRule&&) = delete;

        std::string name() const override;
        std::string severity() const override;
        std::chrono::seconds sustained_for() const override;
        std::vector<Trigger> tick(const TickContext& ctx) const override;

    private:

        std::string m_name { };
        std::string m_target_state { }; // value of health_status that the rule watches for
        std::chrono::seconds m_sustained { 0 };
        std::string m_severity { };

    };

    // fires when a numeric field changes by more than m_min_delta over m_window; needs MetricStore history
    class RateOfChangeRule : public Rule
    {

    public:

        RateOfChangeRule() = delete;
        RateOfChangeRule(const std::string& name, const std::string& field_path, double min_delta, std::chrono::seconds window, const std::string& severity);
        ~RateOfChangeRule() override = default;

        RateOfChangeRule(const RateOfChangeRule&) = delete;
        RateOfChangeRule& operator=(const RateOfChangeRule&) = delete;
        RateOfChangeRule(RateOfChangeRule&&) = delete;
        RateOfChangeRule& operator=(RateOfChangeRule&&) = delete;

        std::string name() const override;
        std::string severity() const override;
        std::chrono::seconds sustained_for() const override;
        std::vector<Trigger> tick(const TickContext& ctx) const override;

    private:

        std::string m_name { };
        std::string m_field_path { };
        double m_min_delta { 0.0 }; // absolute change required to fire (uses |delta|)
        std::chrono::seconds m_window { 0 }; // look back this far for the baseline value
        std::string m_severity { };

    };

    // fires when health_status flipped more than m_max_flips times within m_window; needs MetricStore history
    class FlappingRule : public Rule
    {

    public:

        FlappingRule() = delete;
        FlappingRule(const std::string& name, std::uint32_t max_flips, std::chrono::seconds window, const std::string& severity);
        ~FlappingRule() override = default;

        FlappingRule(const FlappingRule&) = delete;
        FlappingRule& operator=(const FlappingRule&) = delete;
        FlappingRule(FlappingRule&&) = delete;
        FlappingRule& operator=(FlappingRule&&) = delete;

        std::string name() const override;
        std::string severity() const override;
        std::chrono::seconds sustained_for() const override;
        std::vector<Trigger> tick(const TickContext& ctx) const override;

    private:

        std::string m_name { };
        std::uint32_t m_max_flips { 0 }; // number of state transitions in window before firing
        std::chrono::seconds m_window { 0 };
        std::string m_severity { };

    };

}

#endif // NODE_MONITOR_RULE_HH
