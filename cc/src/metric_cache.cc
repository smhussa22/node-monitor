// related headers
#include "metric_cache.hh"

// c sys headers

// cpp stdlib headers

// 3rd party headers

// project headers

namespace NodeMonitor
{

    MetricCache::MetricCache()
    {

    }

    MetricCache::~MetricCache()
    {

    }

    void MetricCache::update(const Metric& metric)
    {

    }

    std::optional<Metric> MetricCache::get(const std::string& hostname) const
    {

        return std::nullopt;

    }

    std::vector<Metric> MetricCache::get_all() const
    {

        return { };

    }

    std::size_t MetricCache::size() const
    {

        return std::size_t { 0 };

    }

    void MetricCache::clear()
    {

    }

}
