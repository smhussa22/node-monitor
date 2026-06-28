#ifndef NODE_MONITOR_SNMP_POLLER_HH
#define NODE_MONITOR_SNMP_POLLER_HH

// related headers
#include "MetricCache.hh"
#include "MetricStore.hh"

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
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

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

        std::shared_ptr<MetricCache> m_cache { };                              // existing metric path
        std::shared_ptr<MetricStore> m_store { };                              // optional postgres sink
        std::chrono::seconds m_interval { 30 };                                // seconds between sweeps
        std::chrono::milliseconds m_per_target_timeout { 2000 };               // per-poll recv timeout

        std::unordered_map<std::string, SnmpTargetState> m_targets { };        // host -> state
        mutable std::mutex m_mutex { };                                        // guards m_targets

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
