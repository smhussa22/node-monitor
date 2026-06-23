#ifndef NODE_MONITOR_METRIC_CACHE_HH
#define NODE_MONITOR_METRIC_CACHE_HH

// related headers
#include "Metric.hh"

// c sys headers

// cpp stdlib headers
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // thread-safe in-memory store of the latest metric per device
    class MetricCache
    {

    public:

        MetricCache();
        ~MetricCache();

        MetricCache(const MetricCache&) = delete;
        MetricCache& operator=(const MetricCache&) = delete;

        MetricCache(MetricCache&&) = delete;
        MetricCache& operator=(MetricCache&&) = delete;
        
        // insert or replace the metric record for the metric's hostname
        void update(const Metric& metric);

        // fetch the most recent metric for the given hostname, if any
        std::optional<Metric> get(const std::string& hostname) const;

        // snapshot every metric currently in the cache
        std::vector<Metric> get_all() const;

        // number of distinct hostnames currently cached
        std::size_t size() const;

        // remove all cached metrics
        void clear();

    private:

        std::unordered_map<std::string, Metric> m_metrics { }; // hostname to latest metric record
        mutable std::mutex m_mutex { }; // protects m_metrics from concurrent access

    };

}

#endif // NODE_MONITOR_METRIC_CACHE_HH
