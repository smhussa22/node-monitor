// related headers

// c sys headers

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <format>
#include <memory>
#include <print>
#include <string>
#include <thread>

// 3rd party headers

// project headers
#include "Action.hh"
#include "AlertEngine.hh"
#include "CollectorServer.hh"
#include "K8sClient.hh"
#include "MetricCache.hh"
#include "MetricStore.hh"
#include "NetflowReceiver.hh"
#include "Rule.hh"
#include "RunbookEngine.hh"
#include "Scheduler.hh"
#include "ThreadPool.hh"

namespace nm = NodeMonitor;

int main()
{

    // force line buffering on stdout so log lines flush per-line under docker / k8s / piped redirection,
    // which would otherwise switch libc to 4 KiB block buffering and swallow the heartbeat output
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    // construct the shared cache and worker pool used by the collector
    auto cache { std::make_shared<nm::MetricCache>() };
    auto pool { std::make_shared<nm::ThreadPool>(4uz) };

    // construct the optional persistent store; only created when POSTGRES_HOST is set in the environment
    std::shared_ptr<nm::MetricStore> store { };
    if (const char* pg_host { std::getenv("POSTGRES_HOST") }; pg_host != nullptr)
    {
        const char* pg_port { std::getenv("POSTGRES_PORT") };
        const char* pg_user { std::getenv("POSTGRES_USER") };
        const char* pg_pass { std::getenv("POSTGRES_PASSWORD") };
        const char* pg_db { std::getenv("POSTGRES_DB") };
        std::string dsn { std::format("postgresql://{}:{}@{}:{}/{}", pg_user != nullptr ? pg_user : "postgres", pg_pass != nullptr ? pg_pass : "", pg_host, pg_port != nullptr ? pg_port : "5432", pg_db != nullptr ? pg_db : "postgres") };
        try
        {
            store = std::make_shared<nm::MetricStore>(dsn, 4uz);
        }
        catch (const std::exception& e)
        {
            std::println("warning: metric store init failed, running without persistence: {}", e.what());
            store.reset();
        }
    }

    // construct the collector server bound to a default port
    nm::CollectorServer server { cache, store, pool, std::uint16_t { 8000 } };

    // construct the netflow receiver bound to the standard netflow v5/v9 port
    nm::NetflowReceiver netflow { std::uint16_t { 2055 }, store };

    // construct the scheduler that will drive periodic display tasks
    nm::Scheduler scheduler { };

    // detect kubernetes credentials (dry-run when not in-cluster); shared with every Action via ActionContext
    std::shared_ptr<nm::K8sClient> k8s { nm::K8sClient::create_from_environment() };

    // construct the self-healing engine and register runbooks; each runbook binds one rule to an action list
    auto runbooks { std::make_shared<nm::RunbookEngine>(k8s, store) };
    using namespace std::chrono_literals;

    // device_offline: log + notify; for cisco hosts, also attempt to restart the parent simulator pod
    {
        nm::Runbook book { };
        book.m_name = "rb_device_offline";
        book.m_rule_name = "device_offline";
        book.m_cooldown = 5min;
        book.m_max_per_hour = 30;
        book.m_actions.push_back(std::make_unique<nm::LogOnlyAction>("device ${hostname} offline; restarting backing pod"));
        book.m_actions.push_back(std::make_unique<nm::WebhookNotifyAction>(""));
        book.m_actions.push_back(std::make_unique<nm::RestartPodAction>("default", "app=simulator"));
        runbooks->register_runbook(std::move(book));
    }

    // high_cpu on the collector: scale up by 1 replica, capped at 5
    {
        nm::Runbook book { };
        book.m_name = "rb_high_cpu";
        book.m_rule_name = "high_cpu";
        book.m_cooldown = 2min;
        book.m_max_per_hour = 20;
        book.m_actions.push_back(std::make_unique<nm::ScaleDeploymentAction>("default", "collector", 1, 1, 5));
        runbooks->register_runbook(std::move(book));
    }

    // ips_storm: security alert, no auto-remediation, notify only so humans triage
    {
        nm::Runbook book { };
        book.m_name = "rb_ips_storm";
        book.m_rule_name = "ips_storm";
        book.m_cooldown = 30s;
        book.m_max_per_hour = 100;
        book.m_actions.push_back(std::make_unique<nm::LogOnlyAction>("ips storm on ${hostname}; escalating to security oncall"));
        book.m_actions.push_back(std::make_unique<nm::WebhookNotifyAction>(""));
        runbooks->register_runbook(std::move(book));
    }

    // health_down: log + notify; this is a soft restart trigger so we also try to recycle the pod
    {
        nm::Runbook book { };
        book.m_name = "rb_health_down";
        book.m_rule_name = "health_down";
        book.m_cooldown = 3min;
        book.m_max_per_hour = 30;
        book.m_actions.push_back(std::make_unique<nm::LogOnlyAction>("${hostname} reported health_status=down; recycling pod"));
        book.m_actions.push_back(std::make_unique<nm::RestartPodAction>("default", "app=simulator"));
        runbooks->register_runbook(std::move(book));
    }

    // construct the alert engine and register a vendor-aware rule set; rules referencing
    // payload fields use json pointer syntax so any nested telemetry field is reachable
    auto alerts { std::make_shared<nm::AlertEngine>(cache, store, runbooks) };
    alerts->register_rule(std::make_unique<nm::ThresholdRule>("high_cpu",        "cpu",                       ">", 90.0,   5min, "critical"));
    alerts->register_rule(std::make_unique<nm::ThresholdRule>("high_memory",     "memory",                    ">", 85.0,   5min, "warning"));
    alerts->register_rule(std::make_unique<nm::ThresholdRule>("bgp_loss",        "/bgp_peers",                "<", 1.0,    60s,  "critical", "cisco"));
    alerts->register_rule(std::make_unique<nm::ThresholdRule>("ospf_loss",       "/ospf_neighbors",           "<", 1.0,    60s,  "critical", "cisco"));
    alerts->register_rule(std::make_unique<nm::ThresholdRule>("vpn_partial",     "/vpn_tunnels_up",           "<", 2.0,    60s,  "critical", "juniper"));
    alerts->register_rule(std::make_unique<nm::ThresholdRule>("session_flood",   "/active_firewall_sessions", ">", 4500.0, 2min, "warning",  "juniper"));
    alerts->register_rule(std::make_unique<nm::ThresholdRule>("ips_storm",       "/ips_alerts",               ">", 40.0,   0s,   "critical", "paloalto"));
    alerts->register_rule(std::make_unique<nm::ThresholdRule>("url_block_surge", "/blocked_urls",             ">", 2000.0, 5min, "warning",  "paloalto"));
    alerts->register_rule(std::make_unique<nm::ThresholdRule>("firewall_ddos",   "/blocked_connections",      ">", 150.0,  60s,  "critical", "paloalto"));
    alerts->register_rule(std::make_unique<nm::OfflineRule>(   "device_offline",  60s,                                "critical"));
    alerts->register_rule(std::make_unique<nm::StateChangeRule>("health_degraded", "degraded",                30s,    "warning"));
    alerts->register_rule(std::make_unique<nm::StateChangeRule>("health_down",     "down",                    0s,     "critical"));
    alerts->register_rule(std::make_unique<nm::RateOfChangeRule>("cpu_spike",      "cpu",     40.0, 30s, "warning"));
    alerts->register_rule(std::make_unique<nm::RateOfChangeRule>("memory_jump",    "memory",  25.0, 60s, "info"));
    alerts->register_rule(std::make_unique<nm::FlappingRule>(   "health_flapping", 3u, 5min, "warning"));

    // schedule a periodic snapshot of the cache and print one line per device
    scheduler.schedule([cache]
    {
        auto metrics { cache->get_all() };
        if (metrics.empty()) return;
        std::println("--- {} devices ---", metrics.size());
        for (const auto& m : metrics)
            std::println("[{}] {} cpu {:.1f} memory {:.1f}", m.m_vendor, m.m_hostname, m.m_cpu, m.m_memory);
    }, std::chrono::milliseconds { 5000 });

    // run the alert engine every 10s; rules with sustained windows still need many ticks before they fire
    scheduler.schedule([alerts] { alerts->evaluate(); }, std::chrono::milliseconds { 10000 });

    // start the collector and scheduler, then idle until shutdown is requested
    server.start();
    scheduler.start();
    netflow.start();
    std::println("node-monitor collector running on port 8000");
    std::this_thread::sleep_for(std::chrono::hours { 1 });

    // graceful shutdown in reverse start order
    scheduler.stop();
    netflow.stop();
    server.stop();
    pool->shutdown();

    return 0;

}
