#ifndef NODE_MONITOR_COLLECTOR_SERVER_HH
#define NODE_MONITOR_COLLECTOR_SERVER_HH

// related headers
#include "AclEngine.hh"
#include "DhcpServer.hh"
#include "DnsServer.hh"
#include "DnsZone.hh"
#include "MetricCache.hh"
#include "MetricStore.hh"
#include "SnmpPoller.hh"
#include "SnmpTrapReceiver.hh"
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
        CollectorServer(std::shared_ptr<MetricCache> cache, std::shared_ptr<MetricStore> store, std::shared_ptr<ThreadPool> pool, std::uint16_t port, std::shared_ptr<AclEngine> acl = nullptr, std::shared_ptr<DhcpServer> dhcp = nullptr, std::shared_ptr<DnsServer> dns = nullptr, std::shared_ptr<DnsZone> dns_zone = nullptr, std::shared_ptr<SnmpPoller> snmp = nullptr, std::shared_ptr<SnmpTrapReceiver> traps = nullptr);
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

        // dispatch one raw http request and return the full http response (status line + headers + body)
        std::string handle_request(const std::string& raw_request);

        // build a json snapshot of the acl engine's rules and totals; used by GET /acl/rules
        std::string acl_snapshot_json() const;

        // build a json snapshot of the dhcp server's totals and live leases; used by GET /dhcp/leases
        std::string dhcp_snapshot_json() const;

        // build a json snapshot of the dns zone + server counters; used by GET /dns/zone
        std::string dns_snapshot_json() const;

        // build a json snapshot of the snmp poller's per-target state; used by GET /snmp/agents
        std::string snmp_snapshot_json() const;

        // build a json snapshot of the recent traps received; used by GET /snmp/traps
        std::string snmp_traps_json() const;

        std::shared_ptr<MetricCache> m_cache { }; // shared cache for storing incoming metrics
        std::shared_ptr<MetricStore> m_store { }; // optional postgres-backed persistent store; null when disabled
        std::shared_ptr<ThreadPool> m_pool { }; // worker pool used to process requests off the accept thread
        std::shared_ptr<AclEngine> m_acl { }; // optional acl engine; exposed via GET /acl/rules
        std::shared_ptr<DhcpServer> m_dhcp { }; // optional dhcp server; exposed via GET /dhcp/leases
        std::shared_ptr<DnsServer> m_dns { }; // optional dns server; counter source for GET /dns/zone
        std::shared_ptr<DnsZone> m_dns_zone { }; // optional dns zone; entry source for GET /dns/zone
        std::shared_ptr<SnmpPoller> m_snmp { }; // optional snmp poller; exposed via GET /snmp/agents
        std::shared_ptr<SnmpTrapReceiver> m_snmp_traps { }; // optional trap receiver; exposed via GET /snmp/traps
        std::uint16_t m_port { 0 }; // tcp port the server listens on
        SocketFd m_listen_socket { }; // raii owned listening socket file descriptor
        std::thread m_accept_thread { }; // thread that accepts new connections
        std::atomic<bool> m_running { false }; // whether the accept loop is currently active

    };

}

#endif // NODE_MONITOR_COLLECTOR_SERVER_HH
