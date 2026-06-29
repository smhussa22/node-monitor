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
#include "AclEngine.hh"
#include "AclRateRule.hh"
#include "AclRule.hh"
#include "Action.hh"
#include "AlertEngine.hh"
#include "CollectorServer.hh"
#include "DhcpExhaustionRule.hh"
#include "DhcpPacket.hh"
#include "DhcpPool.hh"
#include "DhcpServer.hh"
#include "DnsNxdomainRule.hh"
#include "DnsServer.hh"
#include "DnsZone.hh"
#include "PortScanRule.hh"
#include "SnmpPoller.hh"
#include "SnmpTrapReceiver.hh"
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

    // construct the acl engine and register a baseline rule set; the cisco simulator emits flows with src
    // in 10.0.0.0/24 and dst in 8.8.0.0/16 with a mix of well-known + ephemeral dst ports, so the rules
    // below produce a healthy permit/deny split that the dashboard can chart
    auto acl { std::make_shared<nm::AclEngine>() };
    acl->register_rule(std::make_unique<nm::AclRule>(1u,  nm::AclAction::Permit, nm::AclProtocol::Tcp,  nm::parse_cidr("any"),         nm::parse_cidr("any"), nm::parse_port_range("any"), nm::parse_port_range("443"),  "permit https outbound"));
    acl->register_rule(std::make_unique<nm::AclRule>(2u,  nm::AclAction::Permit, nm::AclProtocol::Tcp,  nm::parse_cidr("any"),         nm::parse_cidr("any"), nm::parse_port_range("any"), nm::parse_port_range("80"),   "permit http outbound"));
    acl->register_rule(std::make_unique<nm::AclRule>(3u,  nm::AclAction::Permit, nm::AclProtocol::Udp,  nm::parse_cidr("any"),         nm::parse_cidr("any"), nm::parse_port_range("any"), nm::parse_port_range("53"),   "permit dns"));
    acl->register_rule(std::make_unique<nm::AclRule>(4u,  nm::AclAction::Permit, nm::AclProtocol::Tcp,  nm::parse_cidr("10.0.0.0/8"),  nm::parse_cidr("any"), nm::parse_port_range("any"), nm::parse_port_range("22"),   "permit ssh from internal"));
    acl->register_rule(std::make_unique<nm::AclRule>(5u,  nm::AclAction::Deny,   nm::AclProtocol::Tcp,  nm::parse_cidr("any"),         nm::parse_cidr("any"), nm::parse_port_range("any"), nm::parse_port_range("22"),   "deny ssh from non-internal"));
    acl->register_rule(std::make_unique<nm::AclRule>(6u,  nm::AclAction::Deny,   nm::AclProtocol::Tcp,  nm::parse_cidr("any"),         nm::parse_cidr("any"), nm::parse_port_range("any"), nm::parse_port_range("3389"), "deny rdp"));
    acl->register_rule(std::make_unique<nm::AclRule>(7u,  nm::AclAction::Deny,   nm::AclProtocol::Tcp,  nm::parse_cidr("any"),         nm::parse_cidr("any"), nm::parse_port_range("any"), nm::parse_port_range("23"),   "deny telnet"));
    acl->register_rule(std::make_unique<nm::AclRule>(8u,  nm::AclAction::Deny,   nm::AclProtocol::Icmp, nm::parse_cidr("any"),         nm::parse_cidr("any"), nm::parse_port_range("any"), nm::parse_port_range("any"),  "deny icmp"));

    // construct the dhcp server with a /16 pool (~65k usable ips) and 1h leases. on kubernetes we run
    // unicast — simulators are configured at deploy time with this server's clusterip — so we don't need
    // an L2 broadcast domain. server identifier 10.42.0.1 doubles as the gateway in option 3, and our
    // future DnsServer is announced as 10.42.0.2 via option 6
    const std::uint32_t k_pool_network { (10u << 24) | (42u << 16) };          // 10.42.0.0
    const std::uint32_t k_pool_gateway { k_pool_network | 1u };                // 10.42.0.1
    const std::uint32_t k_pool_dns     { k_pool_network | 2u };                // 10.42.0.2
    auto dhcp_pool { std::make_unique<nm::DhcpPool>(k_pool_network, 16u, k_pool_gateway, k_pool_dns, std::chrono::seconds { 3600 }) };

    // dhcp server defaults to udp/67 (RFC 2131); allow override via env so local dev can avoid privileged
    // ports without needing NET_BIND_SERVICE. the kubernetes deployment grants that capability
    std::uint16_t dhcp_port { 67 };
    if (const char* dp { std::getenv("DHCP_PORT") }; dp != nullptr)
    {
        try { dhcp_port = static_cast<std::uint16_t>(std::stoi(dp)); }
        catch (...) { /* keep default */ }
    }
    // dns zone shared between the dhcp server (which populates it on ACK) and the dns server (which
    // serves A + PTR queries against it). hardcode a "collector" entry pointing at the pool's gateway
    // so simulators can resolve "collector.node-monitor.local" before they push any data
    auto dns_zone { std::make_shared<nm::DnsZone>("node-monitor.local") };
    dns_zone->bind("collector", k_pool_gateway, "static");

    auto dhcp { std::make_shared<nm::DhcpServer>(dhcp_port, std::move(dhcp_pool), store, k_pool_gateway, dns_zone) };

    // dns server defaults to udp/53; same env override pattern as dhcp for local dev without privileged ports
    std::uint16_t dns_port { 53 };
    if (const char* dp { std::getenv("DNS_PORT") }; dp != nullptr)
    {
        try { dns_port = static_cast<std::uint16_t>(std::stoi(dp)); }
        catch (...) { /* keep default */ }
    }
    auto dns { std::make_shared<nm::DnsServer>(dns_port, dns_zone) };

    // snmp poller: seeds its target list from SNMP_TARGETS (comma-separated host[:port] entries). when
    // unset the poller still runs but does nothing — wired this way so local dev without simulator agents
    // doesn't waste resources. community is read once from SNMP_COMMUNITY; defaults to "public" per v2c
    // snmp trap receiver on udp/162; agents may emit notification PDUs when simulated events fire.
    // SNMP_TRAP_PORT env overrides the default for local dev without privileged ports
    std::uint16_t trap_port { 162 };
    if (const char* tp { std::getenv("SNMP_TRAP_PORT") }; tp != nullptr)
    {
        try { trap_port = static_cast<std::uint16_t>(std::stoi(tp)); }
        catch (...) { /* keep default */ }
    }
    auto snmp_traps { std::make_shared<nm::SnmpTrapReceiver>(trap_port, 500uz) };

    auto snmp { std::make_shared<nm::SnmpPoller>(cache, store, std::chrono::seconds { 30 }, std::chrono::milliseconds { 2000 }) };
    {
        std::string community { "public" };
        if (const char* c { std::getenv("SNMP_COMMUNITY") }; c != nullptr) community = c;
        if (const char* raw { std::getenv("SNMP_TARGETS") }; raw != nullptr)
        {
            std::string s { raw };
            std::size_t start { 0uz };
            for (std::size_t i { 0uz }; i <= s.size(); ++i)
            {
                if (i == s.size() || s[i] == ',')
                {
                    if (i > start)
                    {
                        std::string entry { s.substr(start, i - start) };
                        std::uint16_t port { 161 };
                        std::string host { entry };
                        auto colon { entry.find(':') };
                        if (colon != std::string::npos)
                        {
                            host = entry.substr(0uz, colon);
                            try { port = static_cast<std::uint16_t>(std::stoi(entry.substr(colon + 1uz))); } catch (...) { port = 161; }
                        }
                        snmp->add_target(host, port, community);
                        std::println("snmp poller static target {}:{}", host, port);
                    }
                    start = i + 1uz;
                }
            }
        }
    }

    // construct the collector server bound to a default port; acl + dhcp + dns + snmp + snmp_traps are
    // shared so the /acl/rules, /dhcp/leases, /dns/zone, /snmp/agents, /snmp/traps endpoints all return
    // live state from the same engines that handle real traffic
    nm::CollectorServer server { cache, store, pool, std::uint16_t { 8000 }, acl, dhcp, dns, dns_zone, snmp, snmp_traps };

    // construct the netflow receiver bound to the standard netflow v5/v9 port
    nm::NetflowReceiver netflow { std::uint16_t { 2055 }, store, acl };

    // construct the scheduler that will drive periodic display tasks
    nm::Scheduler scheduler { };

    // detect kubernetes credentials (dry-run when not in-cluster); shared with every Action via ActionContext
    std::shared_ptr<nm::K8sClient> k8s { nm::K8sClient::create_from_environment() };

    // when running in-cluster, turn on k8s-API-based discovery so the snmp poller picks up simulator
    // pods automatically instead of relying only on the static SNMP_TARGETS env. dry-run mode (docker
    // compose / local dev) silently no-ops and the static targets remain authoritative
    if (k8s && !k8s->is_dry_run())
    {
        std::string label { "app=simulator" };
        if (const char* l { std::getenv("SNMP_DISCOVERY_LABEL") }; l != nullptr) label = l;
        std::string ns { "default" };
        if (const char* n { std::getenv("SNMP_DISCOVERY_NAMESPACE") }; n != nullptr) ns = n;
        std::string community { "public" };
        if (const char* c { std::getenv("SNMP_COMMUNITY") }; c != nullptr) community = c;
        snmp->enable_k8s_discovery(k8s, ns, label, 161u, community);
        std::println("snmp poller k8s discovery enabled: ns={} selector='{}'", ns, label);
    }

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

    // security signal: fires when the acl engine is denying flows above a sustained rate; sampled between
    // ticks of the alert engine (10s cadence) so the threshold is denies-per-second, not denies-per-tick
    alerts->register_rule(std::make_unique<nm::AclRateRule>("acl_deny_storm", 50.0, 30s, "warning", acl));

    // operational signal: fires when fewer than 10% of the dhcp pool's addresses are free; gives an
    // operator advance warning before clients start failing to bind
    alerts->register_rule(std::make_unique<nm::DhcpExhaustionRule>("dhcp_pool_exhaustion", 0.10, 60s, "warning", dhcp));

    // operational + security signal: nxdomain bursts often indicate either a misconfigured client or a
    // zone-enumeration scan against our DnsServer; threshold is per-second
    alerts->register_rule(std::make_unique<nm::DnsNxdomainRule>("dns_nxdomain_storm", 10.0, 30s, "warning", dns));

    // security signal: classic horizontal scan fingerprint — one src_ip hitting many distinct dst_ports
    // in a short window. queries the flows table which is already populated by NetflowReceiver
    alerts->register_rule(std::make_unique<nm::PortScanRule>("port_scan_detected", 50u, 60s, 0s, "warning"));

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
    dhcp->start();
    dns->start();
    snmp->start();
    snmp_traps->start();
    std::println("node-monitor collector running on port 8000");
    std::this_thread::sleep_for(std::chrono::hours { 1 });

    // graceful shutdown in reverse start order
    scheduler.stop();
    snmp_traps->stop();
    snmp->stop();
    dns->stop();
    dhcp->stop();
    netflow.stop();
    server.stop();
    pool->shutdown();

    return 0;

}
