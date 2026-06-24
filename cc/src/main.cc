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
#include "NetflowReceiver.hh"
#include "Scheduler.hh"
#include "ThreadPool.hh"

namespace nm = NodeMonitor;

int main()
{

    // construct the shared cache and worker pool used by the collector
    auto cache { std::make_shared<nm::MetricCache>() };
    auto pool { std::make_shared<nm::ThreadPool>(4uz) };

    // construct the collector server bound to a default port
    nm::CollectorServer server { cache, pool, std::uint16_t { 8000 } };

    // construct the netflow receiver bound to the standard netflow v5/v9 port
    nm::NetflowReceiver netflow { std::uint16_t { 2055 } };

    // construct the scheduler that will drive periodic display tasks
    nm::Scheduler scheduler { };

    // schedule a periodic snapshot of the cache and print one line per device
    scheduler.schedule([cache]
    {
        auto metrics { cache->get_all() };
        if (metrics.empty()) return;
        std::println("--- {} devices ---", metrics.size());
        for (const auto& m : metrics)
            std::println("[{}] {} cpu {:.1f} memory {:.1f}", m.m_vendor, m.m_hostname, m.m_cpu, m.m_memory);
    }, std::chrono::milliseconds { 5000 });

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
