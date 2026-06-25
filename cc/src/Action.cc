// related headers
#include "Action.hh"

// c sys headers

// cpp stdlib headers
#include <cctype>
#include <format>
#include <iomanip>
#include <print>
#include <sstream>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    namespace
    {

        // small helper that replaces ${hostname} / ${rule} placeholders in a template string
        std::string substitute(const std::string& tmpl, const ActionContext& ctx)
        {

            std::string out { tmpl };
            auto replace_all { [&out](const std::string& needle, const std::string& replacement)
            {
                std::size_t pos { 0 };
                while ((pos = out.find(needle, pos)) != std::string::npos)
                {
                    out.replace(pos, needle.size(), replacement);
                    pos += replacement.size();
                }
            } };
            replace_all("${hostname}", ctx.m_hostname);
            replace_all("${rule}", ctx.m_rule_name);
            return out;

        }

        // percent-encode a single character if it needs it, otherwise emit it raw
        std::string url_encode(const std::string& s)
        {

            std::ostringstream out { };
            out.fill('0');
            out << std::hex;
            for (unsigned char c : s)
            {
                if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '=')
                    out << c;
                else
                    out << '%' << std::uppercase << std::setw(2) << static_cast<int>(c) << std::nouppercase;
            }
            return out.str();

        }

    }

    // ----- LogOnlyAction -----

    LogOnlyAction::LogOnlyAction(const std::string& message)
        : m_message { message }
    {

    }

    std::string LogOnlyAction::type() const
    {

        return "log_only";

    }

    ActionResult LogOnlyAction::execute(const ActionContext& ctx)
    {

        std::string rendered { substitute(m_message, ctx) };
        std::println("[runbook] {}", rendered);
        return ActionResult { "success", "log", "", 0, true };

    }

    // ----- WebhookNotifyAction -----

    WebhookNotifyAction::WebhookNotifyAction(const std::string& webhook_url)
        : m_webhook_url { webhook_url }
    {

    }

    std::string WebhookNotifyAction::type() const
    {

        return "webhook_notify";

    }

    ActionResult WebhookNotifyAction::execute(const ActionContext& ctx)
    {

        // build a slack-shaped payload but keep the path generic so any json webhook works
        ::nlohmann::json payload { };
        payload["text"] = std::format("[{}] alert {} on {}", ctx.m_details.value("severity", std::string { "?" }), ctx.m_rule_name, ctx.m_hostname);
        payload["rule"] = ctx.m_rule_name;
        payload["hostname"] = ctx.m_hostname;
        payload["details"] = ctx.m_details;

        // an empty url means "log only" — useful when you want the audit trail without a real slack hook
        if (m_webhook_url.empty())
        {
            std::println("[runbook] webhook (no url configured): {}", payload.dump());
            return ActionResult { "success", "log", "", 0, true };
        }

        // when we do have a url, route the request through the same k8s client so dry-run support is uniform.
        // it's an https POST with a plain bearer token; the client tolerates non-k8s endpoints fine.
        if (ctx.m_k8s == nullptr)
        {
            std::println("[runbook] webhook skipped (no k8s client): {}", payload.dump());
            return ActionResult { "skipped", m_webhook_url, "no k8s client", 0, false };
        }
        if (ctx.m_k8s->is_dry_run())
        {
            std::println("[runbook] webhook DRY-RUN -> {} body={}", m_webhook_url, payload.dump());
            return ActionResult { "dry_run", m_webhook_url, "", 0, true };
        }
        auto response { ctx.m_k8s->post(m_webhook_url, payload.dump()) };
        bool ok { response.m_status_code >= 200 && response.m_status_code < 300 };
        return ActionResult { ok ? "success" : "failed", m_webhook_url, response.m_error, static_cast<int>(response.m_status_code), ok };

    }

    // ----- RestartPodAction -----

    RestartPodAction::RestartPodAction(const std::string& ns, const std::string& label_selector)
        : m_namespace { ns }, m_label_selector { label_selector }
    {

    }

    std::string RestartPodAction::type() const
    {

        return "restart_pod";

    }

    ActionResult RestartPodAction::execute(const ActionContext& ctx)
    {

        if (ctx.m_k8s == nullptr)
        {
            std::println("[runbook] restart_pod skipped (no k8s client) ns={} selector={}", m_namespace, m_label_selector);
            return ActionResult { "skipped", "", "no k8s client", 0, false };
        }

        std::string selector { substitute(m_label_selector, ctx) };
        std::string list_path { std::format("/api/v1/namespaces/{}/pods?labelSelector={}", m_namespace, url_encode(selector)) };

        if (ctx.m_k8s->is_dry_run())
        {
            std::println("[runbook] restart_pod DRY-RUN ns={} selector={}", m_namespace, selector);
            return ActionResult { "dry_run", "ns=" + m_namespace + " selector=" + selector, "", 0, true };
        }

        // step 1: list pods matching the selector
        auto list_resp { ctx.m_k8s->get(list_path) };
        if (list_resp.m_status_code < 200 || list_resp.m_status_code >= 300)
            return ActionResult { "failed", selector, std::format("list pods failed: {}", list_resp.m_error), static_cast<int>(list_resp.m_status_code), false };

        ::nlohmann::json list_body { };
        try { list_body = ::nlohmann::json::parse(list_resp.m_body); }
        catch (const std::exception& e) { return ActionResult { "failed", selector, std::format("list parse: {}", e.what()), static_cast<int>(list_resp.m_status_code), false }; }

        const auto& items { list_body.value("items", ::nlohmann::json::array()) };
        if (items.empty())
            return ActionResult { "failed", selector, "no pods matched selector", static_cast<int>(list_resp.m_status_code), false };

        // step 2: delete the first matching pod
        std::string pod_name { items[0].value("/metadata/name"_json_pointer, std::string { }) };
        if (pod_name.empty())
            return ActionResult { "failed", selector, "first pod missing metadata.name", 0, false };

        std::string delete_path { std::format("/api/v1/namespaces/{}/pods/{}", m_namespace, pod_name) };
        auto del_resp { ctx.m_k8s->del(delete_path) };
        bool ok { del_resp.m_status_code >= 200 && del_resp.m_status_code < 300 };
        return ActionResult { ok ? "success" : "failed", pod_name, del_resp.m_error, static_cast<int>(del_resp.m_status_code), ok };

    }

    // ----- ScaleDeploymentAction -----

    ScaleDeploymentAction::ScaleDeploymentAction(const std::string& ns, const std::string& deployment, std::int32_t delta, std::int32_t min_replicas, std::int32_t max_replicas)
        : m_namespace { ns }, m_deployment { deployment }, m_delta { delta }, m_min { min_replicas }, m_max { max_replicas }
    {

    }

    std::string ScaleDeploymentAction::type() const
    {

        return "scale_deployment";

    }

    ActionResult ScaleDeploymentAction::execute(const ActionContext& ctx)
    {

        std::string target { std::format("deployments/{}/{}", m_namespace, m_deployment) };
        if (ctx.m_k8s == nullptr)
            return ActionResult { "skipped", target, "no k8s client", 0, false };

        std::string scale_path { std::format("/apis/apps/v1/namespaces/{}/deployments/{}/scale", m_namespace, m_deployment) };

        if (ctx.m_k8s->is_dry_run())
        {
            std::println("[runbook] scale_deployment DRY-RUN {} delta={}", target, m_delta);
            return ActionResult { "dry_run", target, "", 0, true };
        }

        // step 1: GET the current scale subresource to read spec.replicas
        auto get_resp { ctx.m_k8s->get(scale_path) };
        if (get_resp.m_status_code < 200 || get_resp.m_status_code >= 300)
            return ActionResult { "failed", target, std::format("get scale failed: {}", get_resp.m_error), static_cast<int>(get_resp.m_status_code), false };

        ::nlohmann::json scale_body { };
        try { scale_body = ::nlohmann::json::parse(get_resp.m_body); }
        catch (const std::exception& e) { return ActionResult { "failed", target, std::format("scale parse: {}", e.what()), static_cast<int>(get_resp.m_status_code), false }; }

        std::int32_t current { scale_body.value("/spec/replicas"_json_pointer, std::int32_t { 0 }) };
        std::int32_t desired { current + m_delta };
        if (desired < m_min) desired = m_min;
        if (desired > m_max) desired = m_max;
        if (desired == current)
            return ActionResult { "skipped", target, std::format("already at {} replicas (clamp hit)", current), 0, true };

        // step 2: PATCH spec.replicas via merge-patch — small, idempotent body
        ::nlohmann::json patch_body { };
        patch_body["spec"]["replicas"] = desired;
        auto patch_resp { ctx.m_k8s->patch(scale_path, patch_body.dump(), "application/merge-patch+json") };
        bool ok { patch_resp.m_status_code >= 200 && patch_resp.m_status_code < 300 };
        std::println("[runbook] scale_deployment {}: {} -> {} (http {})", target, current, desired, patch_resp.m_status_code);
        return ActionResult { ok ? "success" : "failed", std::format("{}: {} -> {}", target, current, desired), patch_resp.m_error, static_cast<int>(patch_resp.m_status_code), ok };

    }

}
