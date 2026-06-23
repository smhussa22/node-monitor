#ifndef NODE_MONITOR_COLLECTOR_SERVER_HH
#define NODE_MONITOR_COLLECTOR_SERVER_HH

// related headers
#include "MetricCache.hh"
#include "SocketFd.hh"
#include "ThreadPool.hh"

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // http server that accepts metric pushes from simulated devices and dispatches them to the cache
    class CollectorServer
    {

    public:

        CollectorServer() = delete;
        CollectorServer(std::shared_ptr<MetricCache> cache, std::shared_ptr<ThreadPool> pool, std::uint16_t port);
        ~CollectorServer();

        CollectorServer(const CollectorServer&) = delete;
        CollectorServer& operator=(const CollectorServer&) = delete;

        CollectorServer(CollectorServer&&) = delete;
        CollectorServer& operator=(CollectorServer&&) = delete;

        // begin listening for connections on the configured port
        void start();

        // close the listening socket and join the accept thread
        void stop();

        // port the server is bound to
        std::uint16_t port() const;

        // whether the accept loop is currently running
        bool is_running() const;

    private:

        // body of the accept thread; waits for connections and dispatches work
        void accept_loop();

        // parse an incoming http request and update the metric cache
        void handle_request(const std::string& raw_request);

        std::shared_ptr<MetricCache> m_cache { }; // shared cache for storing incoming metrics
        std::shared_ptr<ThreadPool> m_pool { }; // worker pool used to process requests off the accept thread
        std::uint16_t m_port { 0 }; // tcp port the server listens on
        SocketFd m_listen_socket { }; // raii owned listening socket file descriptor
        std::thread m_accept_thread { }; // thread that accepts new connections
        std::atomic<bool> m_running { false }; // whether the accept loop is currently active

    };

}

#endif // NODE_MONITOR_COLLECTOR_SERVER_HH
