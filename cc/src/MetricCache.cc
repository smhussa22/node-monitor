// related headers
#include "MetricCache.hh"

// c sys headers

// cpp stdlib headers

// 3rd party headers

// project headers

namespace NodeMonitor
{

    void MetricCache::update(const Metric& metric)
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        m_metrics[metric.m_hostname] = metric;

    }

    std::optional<Metric> MetricCache::get(const std::string& hostname) const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        auto iter { m_metrics.find(hostname) };
        if (iter == m_metrics.end()) return std::nullopt;
        return iter->second;

    }

    std::vector<Metric> MetricCache::get_all() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        std::vector<Metric> snapshot { };
        snapshot.reserve(m_metrics.size());
        for (const auto& [hostname, metric] : m_metrics) snapshot.push_back(metric);
        return snapshot;

    }

    std::size_t MetricCache::size() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        return m_metrics.size();

    }

    void MetricCache::clear()
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        m_metrics.clear();

    }

}
