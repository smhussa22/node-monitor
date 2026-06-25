// related headers
#include "RunbookEngine.hh"

// c sys headers

// cpp stdlib headers
#include <print>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    RunbookEngine::RunbookEngine(std::shared_ptr<K8sClient> k8s, std::shared_ptr<MetricStore> store)
        : m_k8s { k8s }, m_store { store }
    {

    }

    void RunbookEngine::register_runbook(Runbook book)
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        std::println("[runbook] registered '{}' on rule '{}' with {} actions, cooldown {}s, max {}/hr",
                     book.m_name, book.m_rule_name, book.m_actions.size(), book.m_cooldown.count(), book.m_max_per_hour);
        m_runbooks.push_back(std::move(book));

    }

    void RunbookEngine::on_alert_fired(const std::string& rule_name, const std::string& hostname, const ::nlohmann::json& details)
    {

        auto now { std::chrono::system_clock::now() };
        std::lock_guard<std::mutex> lock { m_mutex };

        for (auto& book : m_runbooks)
        {
            if (book.m_rule_name != rule_name) continue;
            m_total_runs.fetch_add(1uz);

            // cooldown is per (runbook, host) so we don't restart the same pod every 10 seconds
            if (!check_and_record_cooldown(book, hostname, now))
            {
                std::println("[runbook] '{}' suppressed (cooldown) for host {}", book.m_name, hostname);
                ActionResult suppressed { "cooldown_suppressed", hostname, "within cooldown window", 0, false };
                log_action(book, "runbook", hostname, suppressed, now, now);
                continue;
            }

            // hourly cap protects against pathological alert storms running an action thousands of times
            if (!check_and_record_rate_limit(book, hostname, now))
            {
                std::println("[runbook] '{}' suppressed (rate limit reached)", book.m_name);
                ActionResult limited { "rate_limited", hostname, "hourly cap reached", 0, false };
                log_action(book, "runbook", hostname, limited, now, now);
                continue;
            }

            // build the shared context once; every Action in this runbook sees the same view
            ActionContext ctx { rule_name, hostname, details, m_k8s, now };

            for (auto& action_ptr : book.m_actions)
            {
                m_total_actions.fetch_add(1uz);
                std::string action_type { action_ptr->type() };

                // skip this action type if its circuit breaker tripped from too many consecutive failures
                if (circuit_is_open(book.m_name, action_type))
                {
                    std::println("[runbook] '{}' action {} skipped (circuit open)", book.m_name, action_type);
                    ActionResult open { "circuit_open", "", "circuit breaker open", 0, false };
                    log_action(book, action_type, hostname, open, now, now);
                    continue;
                }

                auto started { std::chrono::system_clock::now() };
                ActionResult result { };
                try
                {
                    result = action_ptr->execute(ctx);
                }
                catch (const std::exception& e)
                {
                    result.m_status = "failed";
                    result.m_error = e.what();
                    result.m_success = false;
                }
                auto completed { std::chrono::system_clock::now() };

                log_action(book, action_type, hostname, result, started, completed);
                record_circuit_outcome(book.m_name, action_type, result.m_success);
            }
        }

    }

    std::uint64_t RunbookEngine::total_actions() const noexcept
    {

        return m_total_actions.load();

    }

    std::uint64_t RunbookEngine::total_runs() const noexcept
    {

        return m_total_runs.load();

    }

    std::vector<std::tuple<std::string, std::string, std::size_t, std::uint32_t, std::uint32_t>> RunbookEngine::describe_registered() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        std::vector<std::tuple<std::string, std::string, std::size_t, std::uint32_t, std::uint32_t>> out { };
        out.reserve(m_runbooks.size());
        for (const auto& book : m_runbooks)
            out.emplace_back(book.m_name, book.m_rule_name, book.m_actions.size(), static_cast<std::uint32_t>(book.m_cooldown.count()), book.m_max_per_hour);
        return out;

    }

    bool RunbookEngine::check_and_record_cooldown(const Runbook& book, const std::string& hostname, std::chrono::system_clock::time_point now)
    {

        std::string key { book.m_name + "|" + hostname };
        auto it { m_cooldown_until.find(key) };
        if (it != m_cooldown_until.end() && now < it->second) return false;
        m_cooldown_until[key] = now + book.m_cooldown;
        return true;

    }

    bool RunbookEngine::check_and_record_rate_limit(const Runbook& book, const std::string& /*hostname*/, std::chrono::system_clock::time_point now)
    {

        auto& dq { m_recent_runs[book.m_name] };
        auto one_hour_ago { now - std::chrono::hours { 1 } };

        // discard timestamps older than the rolling window before checking the cap
        while (!dq.empty() && dq.front() < one_hour_ago) dq.pop_front();
        if (dq.size() >= book.m_max_per_hour) return false;
        dq.push_back(now);
        return true;

    }

    bool RunbookEngine::circuit_is_open(const std::string& runbook_name, const std::string& action_type) const
    {

        std::string key { runbook_name + "|" + action_type };
        auto it { m_circuit_failures.find(key) };
        if (it == m_circuit_failures.end()) return false;

        // find the corresponding runbook to read its threshold; if missing, default to 3
        std::uint32_t threshold { 3 };
        for (const auto& book : m_runbooks)
        {
            if (book.m_name == runbook_name)
            {
                threshold = book.m_circuit_failure_threshold;
                break;
            }
        }
        return it->second >= threshold;

    }

    void RunbookEngine::record_circuit_outcome(const std::string& runbook_name, const std::string& action_type, bool success)
    {

        std::string key { runbook_name + "|" + action_type };
        if (success) m_circuit_failures[key] = 0;
        else m_circuit_failures[key] += 1;

    }

    void RunbookEngine::log_action(const Runbook& book, const std::string& action_type, const std::string& hostname, const ActionResult& result, std::chrono::system_clock::time_point started, std::chrono::system_clock::time_point completed)
    {

        if (m_store == nullptr) return;
        m_store->record_action(book.m_name, book.m_rule_name, hostname, action_type, result.m_target, result.m_status, started, completed, result.m_error, result.m_response_code);

    }

}
