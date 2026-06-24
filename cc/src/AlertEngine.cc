// related headers
#include "AlertEngine.hh"

// c sys headers

// cpp stdlib headers
#include <format>
#include <print>
#include <unordered_set>
#include <utility>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers

namespace NodeMonitor
{

    AlertEngine::AlertEngine(std::shared_ptr<MetricCache> cache, std::shared_ptr<MetricStore> store)
        : m_cache { cache }, m_store { store }
    {

    }

    void AlertEngine::register_rule(std::unique_ptr<Rule> rule)
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        m_rules.push_back(std::move(rule));

    }

    void AlertEngine::evaluate()
    {

        auto metrics { m_cache->get_all() };
        auto now { std::chrono::system_clock::now() };
        TickContext ctx { metrics, now, m_store };

        std::lock_guard<std::mutex> lock { m_mutex };
        for (const auto& rule_ptr : m_rules)
        {
            auto triggers { rule_ptr->tick(ctx) };
            process_triggers(*rule_ptr, triggers, now);
        }

    }

    std::uint64_t AlertEngine::alert_count() const noexcept
    {

        return m_alert_count.load();

    }

    void AlertEngine::process_triggers(const Rule& rule, const std::vector<Trigger>& triggers, std::chrono::system_clock::time_point now)
    {

        // build the set of currently triggered hosts so we can detect which previously-active alerts have cleared
        std::unordered_set<std::string> triggered_hosts { };
        for (const auto& t : triggers) triggered_hosts.insert(t.m_hostname);

        // resolve any open trackers for this rule whose host no longer satisfies the condition
        std::string prefix { rule.name() + "|" };
        for (auto it { m_holding.begin() }; it != m_holding.end(); )
        {
            if (it->first.starts_with(prefix))
            {
                std::string hostname { it->first.substr(prefix.size()) };
                if (!triggered_hosts.contains(hostname))
                {
                    if (it->second.m_fired) resolve_incident(rule, hostname, now);
                    it = m_holding.erase(it);
                    continue;
                }
            }
            ++it;
        }

        // update trackers for hosts currently in violation; fire the alert once the sustained window has elapsed
        for (const auto& trigger : triggers)
        {
            std::string key { rule.name() + "|" + trigger.m_hostname };
            auto& tracker { m_holding[key] };
            if (tracker.m_holding_since == std::chrono::system_clock::time_point { }) tracker.m_holding_since = now;
            tracker.m_last_description = trigger.m_description;

            auto elapsed { now - tracker.m_holding_since };
            if (!tracker.m_fired && elapsed >= rule.sustained_for())
            {
                fire_incident(rule, trigger.m_hostname, trigger.m_description, now);
                tracker.m_fired = true;
            }
        }

    }

    void AlertEngine::fire_incident(const Rule& rule, const std::string& hostname, const std::string& description, std::chrono::system_clock::time_point now)
    {

        std::println("ALERT [{}] rule={} host={} {}", rule.severity(), rule.name(), hostname, description);
        m_alert_count.fetch_add(1uz);
        if (m_store == nullptr) return;

        ::nlohmann::json details { };
        details["description"] = description;
        details["severity"] = rule.severity();
        m_store->record_incident(rule.name(), hostname, rule.severity(), now, details);

    }

    void AlertEngine::resolve_incident(const Rule& rule, const std::string& hostname, std::chrono::system_clock::time_point now)
    {

        std::println("RESOLVED [{}] rule={} host={}", rule.severity(), rule.name(), hostname);
        if (m_store == nullptr) return;
        m_store->resolve_incident(rule.name(), hostname, now);

    }

}
