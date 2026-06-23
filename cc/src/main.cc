// related headers

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <print>
#include <thread>

// 3rd party headers

// project headers
#include "CollectorServer.hh"
#include "MetricCache.hh"
#include "Scheduler.hh"
#include "ThreadPool.hh"

namespace nm = NodeMonitor;

int main()
{

    // construct the shared cache and worker pool used by the collector
    auto cache { std::make_shared<nm::MetricCache>() };
    auto pool { std::make_shared<nm::ThreadPool>(std::size_t { 4 }) };

    // construct the collector server bound to a default port
    nm::CollectorServer server { cache, pool, std::uint16_t { 8000 } };

    // construct the scheduler that will drive periodic display tasks
    nm::Scheduler scheduler { };

    // start the collector and scheduler, then idle until shutdown is requested
    server.start();
    scheduler.start();
    std::println("node-monitor collector running on port 8000");
    std::this_thread::sleep_for(std::chrono::hours { 1 });

    // graceful shutdown in reverse start order
    scheduler.stop();
    server.stop();
    pool->shutdown();

    return 0;

}
