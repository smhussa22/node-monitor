#ifndef NODE_MONITOR_ACTION_HH
#define NODE_MONITOR_ACTION_HH

// related headers
#include "K8sClient.hh"

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers

namespace NodeMonitor
{

    // everything an Action needs to decide what to do for a particular alert firing
    struct ActionContext
    {

        std::string m_rule_name { }; // name of the rule that triggered the runbook
        std::string m_hostname { }; // device the alert fired against; may need substitution into selectors / urls
        ::nlohmann::json m_details { }; // the alert's details json (severity, description, etc.)
        std::shared_ptr<K8sClient> m_k8s { }; // shared k8s api client; null when no client is configured
        std::chrono::system_clock::time_point m_now { }; // wall clock at the moment the runbook was triggered

    };

    // outcome of executing a single Action; persisted to the actions audit table by RunbookEngine
    struct ActionResult
    {

        std::string m_status { }; // success | failed | dry_run | cooldown_suppressed | rate_limited | circuit_open | skipped
        std::string m_target { }; // what we acted on; pod name, deployment, webhook url, etc.
        std::string m_error { }; // human-readable failure detail when m_status is failed
        int m_response_code { 0 }; // http status from the k8s api when applicable; 0 otherwise
        bool m_success { false }; // convenience flag so the engine can branch quickly

    };

    // base type for any runbook action; subclasses implement type() + execute()
    class Action
    {

    public:

        Action() = default;
        virtual ~Action() = default;

        Action(const Action&) = delete;
        Action& operator=(const Action&) = delete;
        Action(Action&&) = delete;
        Action& operator=(Action&&) = delete;

        // short tag persisted in the actions table; e.g. "restart_pod"
        virtual std::string type() const = 0;

        // perform the action against ctx; returns ActionResult describing what happened
        virtual ActionResult execute(const ActionContext& ctx) = 0;

    };

    // simplest possible action; prints a message and returns success. handy for sketching runbooks before real
    // wiring is done and as a dry-run fallback
    class LogOnlyAction : public Action
    {

    public:

        LogOnlyAction() = delete;
        explicit LogOnlyAction(const std::string& message);
        ~LogOnlyAction() override = default;

        LogOnlyAction(const LogOnlyAction&) = delete;
        LogOnlyAction& operator=(const LogOnlyAction&) = delete;
        LogOnlyAction(LogOnlyAction&&) = delete;
        LogOnlyAction& operator=(LogOnlyAction&&) = delete;

        std::string type() const override;
        ActionResult execute(const ActionContext& ctx) override;

    private:

        std::string m_message { }; // log line printed verbatim with ${hostname}/${rule} substitution

    };

    // post a structured json alert summary to a webhook url; intentionally minimal — slack-compatible payload shape
    class WebhookNotifyAction : public Action
    {

    public:

        WebhookNotifyAction() = delete;
        explicit WebhookNotifyAction(const std::string& webhook_url);
        ~WebhookNotifyAction() override = default;

        WebhookNotifyAction(const WebhookNotifyAction&) = delete;
        WebhookNotifyAction& operator=(const WebhookNotifyAction&) = delete;
        WebhookNotifyAction(WebhookNotifyAction&&) = delete;
        WebhookNotifyAction& operator=(WebhookNotifyAction&&) = delete;

        std::string type() const override;
        ActionResult execute(const ActionContext& ctx) override;

    private:

        std::string m_webhook_url { }; // destination url; empty url drops through to a stdout-only log path

    };

    // restart one pod matching a label selector in the configured namespace
    class RestartPodAction : public Action
    {

    public:

        RestartPodAction() = delete;
        RestartPodAction(const std::string& ns, const std::string& label_selector);
        ~RestartPodAction() override = default;

        RestartPodAction(const RestartPodAction&) = delete;
        RestartPodAction& operator=(const RestartPodAction&) = delete;
        RestartPodAction(RestartPodAction&&) = delete;
        RestartPodAction& operator=(RestartPodAction&&) = delete;

        std::string type() const override;
        ActionResult execute(const ActionContext& ctx) override;

    private:

        std::string m_namespace { }; // kubernetes namespace; usually "default"
        std::string m_label_selector { }; // e.g. "app=simulator,vendor=cisco"

    };

    // scale a Deployment by a delta, clamped to [min, max], via the scale subresource
    class ScaleDeploymentAction : public Action
    {

    public:

        ScaleDeploymentAction() = delete;
        ScaleDeploymentAction(const std::string& ns, const std::string& deployment, std::int32_t delta, std::int32_t min_replicas, std::int32_t max_replicas);
        ~ScaleDeploymentAction() override = default;

        ScaleDeploymentAction(const ScaleDeploymentAction&) = delete;
        ScaleDeploymentAction& operator=(const ScaleDeploymentAction&) = delete;
        ScaleDeploymentAction(ScaleDeploymentAction&&) = delete;
        ScaleDeploymentAction& operator=(ScaleDeploymentAction&&) = delete;

        std::string type() const override;
        ActionResult execute(const ActionContext& ctx) override;

    private:

        std::string m_namespace { };
        std::string m_deployment { }; // Deployment name; e.g. "collector"
        std::int32_t m_delta { 0 }; // positive to scale up, negative to scale down
        std::int32_t m_min { 1 };
        std::int32_t m_max { 1 };

    };

}

#endif // NODE_MONITOR_ACTION_HH
