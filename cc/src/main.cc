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
#include "CollectorServer.hh"
#include "MetricCache.hh"
#include "MetricStore.hh"
#include "NetflowReceiver.hh"
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

    // construct the collector server bound to a default port
    nm::CollectorServer server { cache, store, pool, std::uint16_t { 8000 } };

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
