// related headers
#include "collector_server.hh"

// c sys headers

// cpp stdlib headers

// 3rd party headers

// project headers

namespace NodeMonitor
{

    CollectorServer::CollectorServer(std::shared_ptr<MetricCache> cache, std::shared_ptr<ThreadPool> pool, std::uint16_t port)
    {

    }

    CollectorServer::~CollectorServer()
    {

    }

    void CollectorServer::start()
    {

    }

    void CollectorServer::stop()
    {

    }

    std::uint16_t CollectorServer::port() const
    {

        return std::uint16_t { 0 };

    }

    bool CollectorServer::is_running() const
    {

        return false;

    }

    void CollectorServer::accept_loop()
    {

    }

    void CollectorServer::handle_request(const std::string& raw_request)
    {

    }

}
