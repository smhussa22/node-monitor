#ifndef NODE_MONITOR_METRIC_STORE_HH
#define NODE_MONITOR_METRIC_STORE_HH

// related headers
#include "Metric.hh"

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// 3rd party headers
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

// project headers

namespace NodeMonitor
{

    // persists Metric records to postgres and supports time-range queries
    class MetricStore
    {

    public:

        MetricStore() = delete;
        MetricStore(const std::string& connection_string, std::size_t pool_size);
        ~MetricStore();

        MetricStore(const MetricStore&) = delete;
        MetricStore& operator=(const MetricStore&) = delete;
        MetricStore(MetricStore&&) = delete;
        MetricStore& operator=(MetricStore&&) = delete;

        // append one metric to the metrics table
        void persist(const Metric& metric);

        // fetch every row for the given host within [start, end], newest first
        std::vector<Metric> query(const std::string& hostname, std::chrono::system_clock::time_point start, std::chrono::system_clock::time_point end);

        // create a row in the incidents table for a newly fired alert
        void record_incident(const std::string& rule_name, const std::string& hostname, const std::string& severity, std::chrono::system_clock::time_point fired_at, const ::nlohmann::json& details);

        // mark the active (unresolved) incident for this (rule, host) as resolved at the given time
        void resolve_incident(const std::string& rule_name, const std::string& hostname, std::chrono::system_clock::time_point resolved_at);

        // total rows ever persisted via this process (useful for smoke tests)
        std::uint64_t insert_count() const noexcept;

    private:

        // run CREATE TABLE / CREATE INDEX statements on the first available connection
        void ensure_schema();

        // borrow a connection from the pool, blocking if none are free
        std::unique_ptr<::pqxx::connection> acquire_connection();

        // return a connection to the pool and notify one waiter
        void release_connection(std::unique_ptr<::pqxx::connection> conn);

        std::string m_connection_string { }; // libpqxx-style postgresql connection uri
        std::vector<std::unique_ptr<::pqxx::connection>> m_pool { }; // free-list of open connections
        mutable std::mutex m_mutex { }; // protects m_pool
        std::condition_variable m_condition { }; // signals waiters when a connection is returned
        std::atomic<std::uint64_t> m_insert_count { 0 }; // monotonic count of successful inserts

    };

}

#endif // NODE_MONITOR_METRIC_STORE_HH
