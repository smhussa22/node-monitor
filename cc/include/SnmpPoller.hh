#ifndef NODE_MONITOR_SNMP_POLLER_HH
#define NODE_MONITOR_SNMP_POLLER_HH

// related headers
#include "AsnBer.hh"
#include "K8sClient.hh"
#include "MetricCache.hh"
#include "MetricStore.hh"
#include "SnmpMessage.hh"

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // one row of the IF-MIB ifTable; assembled by grouping a GETNEXT-driven walk's varbinds by index
    struct SnmpIfRow
    {

        std::uint32_t m_index { 0 };          // ifIndex (column 1)
        std::string m_descr { };              // ifDescr (column 2)
        std::uint32_t m_admin_status { 0 };   // ifAdminStatus (column 7); 1=up 2=down 3=testing
        std::uint32_t m_oper_status { 0 };    // ifOperStatus (column 8); same enum
        std::uint64_t m_in_octets { 0 };      // ifInOctets (column 10)
        std::uint64_t m_out_octets { 0 };     // ifOutOctets (column 16)

    };

    // per-target wire counters + the last decoded values for the dashboard. all rolled together rather
    // than split into per-counter atomics because the poller mutates everything under m_mutex anyway
    struct SnmpTargetState
    {

        std::string m_host { };                               // dotted ip or hostname the poller resolves
        std::uint16_t m_port { 161 };                         // udp port; standard 161
        std::string m_community { "public" };                 // shared secret for v2c
        std::uint64_t m_queries { 0 };                        // total polls attempted
        std::uint64_t m_successes { 0 };                      // polls with a parseable Response
        std::uint64_t m_timeouts { 0 };                       // polls that exceeded the recv deadline
        std::uint64_t m_errors { 0 };                         // polls with a malformed Response
        std::chrono::system_clock::time_point m_last_poll { }; // wall clock at the last poll attempt
        std::uint32_t m_last_latency_ms { 0 };                 // round trip of the last successful poll
        std::string m_last_sys_name { };                      // most recent sysName.0 (1.3.6.1.2.1.1.5.0)
        std::uint32_t m_last_uptime_ticks { 0 };              // most recent sysUpTime.0 in hundredths of a sec
        std::uint32_t m_last_cpu { 0 };                       // enterprise OID cpu percent (last value)
        std::uint32_t m_last_memory { 0 };                    // enterprise OID memory percent

        std::vector<SnmpIfRow> m_interfaces { };              // ifTable rows from the last successful walk
        std::uint32_t m_last_walk_steps { 0 };                // number of GETNEXTs the last walk took

    };

    // periodically polls a fixed set of SNMP v2c agents and feeds responses into the existing MetricCache
    // + MetricStore. one background thread; one UDP socket per request (simpler than tracking outstanding
    // requests by id). targets are seeded at construction from an env-driven list and not currently
    // discovered dynamically; that's the next iteration
    class SnmpPoller
    {

    public:

        SnmpPoller() = delete;
        SnmpPoller(std::shared_ptr<MetricCache> cache, std::shared_ptr<MetricStore> store, std::chrono::seconds interval, std::chrono::milliseconds per_target_timeout);
        ~SnmpPoller();

        SnmpPoller(const SnmpPoller&) = delete;
        SnmpPoller& operator=(const SnmpPoller&) = delete;
        SnmpPoller(SnmpPoller&&) = delete;
        SnmpPoller& operator=(SnmpPoller&&) = delete;

        // register one polling target; safe to call before start(). duplicates by host are deduplicated
        void add_target(const std::string& host, std::uint16_t port, const std::string& community);

        // turn on dynamic target discovery via the kubernetes API. on each sweep the poller calls
        // discover_pods(client, namespace, label_selector), adds any new pod IPs as targets, and removes
        // targets whose pods have disappeared. static add_target() registrations are preserved alongside
        // discovered ones. only useful in real (in-cluster) mode; dry-run K8sClients short-circuit
        void enable_k8s_discovery(std::shared_ptr<K8sClient> client, const std::string& namespace_, const std::string& label_selector, std::uint16_t snmp_port, const std::string& community);

        // current discovery mode for the dashboard: "static" or "k8s+static"
        std::string discovery_mode() const;

        // spawn the polling thread
        void start();

        // stop the polling thread; safe to call multiple times
        void stop();

        bool is_running() const noexcept;

        std::uint64_t total_polls() const noexcept;
        std::uint64_t total_successes() const noexcept;
        std::uint64_t total_timeouts() const noexcept;
        std::uint64_t total_errors() const noexcept;

        std::vector<SnmpTargetState> snapshot() const;

    private:

        // body of the polling thread; sleeps interval between sweeps; one poll per target per sweep
        void run();

        // poll one target with a single GetRequest carrying 4 varbinds: sysName, sysUpTime, enterprise cpu,
        // enterprise memory. updates state in-place and returns true on a parseable Response
        bool poll_target(SnmpTargetState& state);

        // walk one subtree via successive GETNEXT requests. stops at endOfMibView, on the first OID that
        // leaves the subtree, or after max_steps. used to enumerate ifTable rows. on success, fills out_vbs
        // with every (OID, value) pair returned during the walk; returns true if at least one row came back
        bool walk_subtree(SnmpTargetState& state, const AsnBer::Oid& root_oid, std::vector<SnmpVarbind>& out_vbs, int max_steps);

        // bulk-walk one subtree via GetBulkRequest (RFC 3416 4.2.3): each request gets back up to
        // max_repetitions varbinds in a single round trip, which is what every real SNMP manager uses
        // for table walks. behavior matches walk_subtree (terminates on endOfMibView, on the first OID
        // outside root_oid's subtree, or after max_rounds requests) — just an order of magnitude
        // fewer datagrams when the table is large
        bool bulk_subtree(SnmpTargetState& state, const AsnBer::Oid& root_oid, std::vector<SnmpVarbind>& out_vbs, std::uint32_t max_repetitions, int max_rounds);

        std::shared_ptr<MetricCache> m_cache { };                              // existing metric path
        std::shared_ptr<MetricStore> m_store { };                              // optional postgres sink
        std::chrono::seconds m_interval { 30 };                                // seconds between sweeps
        std::chrono::milliseconds m_per_target_timeout { 2000 };               // per-poll recv timeout

        std::unordered_map<std::string, SnmpTargetState> m_targets { };        // host -> state
        std::unordered_set<std::string> m_static_hosts { };                    // hosts registered via add_target; never expired
        mutable std::mutex m_mutex { };                                        // guards m_targets + m_static_hosts

        // k8s discovery config; only populated when enable_k8s_discovery() has been called
        std::shared_ptr<K8sClient> m_k8s_client { };                           // shared client; null disables discovery
        std::string m_k8s_namespace { "default" };                             // namespace to list pods in
        std::string m_k8s_label_selector { };                                  // SelectorSyntax string
        std::uint16_t m_k8s_snmp_port { 161 };                                 // udp port to register discovered pods on
        std::string m_k8s_community { "public" };                              // community to use for discovered pods

        std::thread m_thread { };                                              // polling loop thread
        std::atomic<bool> m_running { false };                                 // shared running flag
        std::condition_variable m_cv { };                                      // wakes the thread for stop()
        std::mutex m_cv_mutex { };                                             // pairs with m_cv

        std::atomic<std::uint64_t> m_total_polls { 0 };
        std::atomic<std::uint64_t> m_total_successes { 0 };
        std::atomic<std::uint64_t> m_total_timeouts { 0 };
        std::atomic<std::uint64_t> m_total_errors { 0 };

    };

}

#endif // NODE_MONITOR_SNMP_POLLER_HH
