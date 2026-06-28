#ifndef NODE_MONITOR_DNS_SERVER_HH
#define NODE_MONITOR_DNS_SERVER_HH

// related headers
#include "DnsPacket.hh"
#include "DnsZone.hh"
#include "SocketFd.hh"

// c sys headers
#include <netinet/in.h>

// cpp stdlib headers
#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // tiny authoritative DNS server bound to UDP/53. answers A queries for names in our zone, PTR queries
    // for in-addr.arpa names that map to known ips, and REFUSED for anything outside the zone. recursion
    // is not implemented because we are not a resolver — we are the authoritative bottom of the hierarchy
    // for a single fake zone. queries with RD set are answered with RA cleared, which is honest
    class DnsServer
    {

    public:

        DnsServer() = delete;
        DnsServer(std::uint16_t port, std::shared_ptr<DnsZone> zone);
        ~DnsServer();

        DnsServer(const DnsServer&) = delete;
        DnsServer& operator=(const DnsServer&) = delete;
        DnsServer(DnsServer&&) = delete;
        DnsServer& operator=(DnsServer&&) = delete;

        void start();
        void stop();

        std::uint16_t port() const noexcept;
        bool is_running() const noexcept;

        std::uint64_t query_count() const noexcept;
        std::uint64_t noerror_count() const noexcept;
        std::uint64_t nxdomain_count() const noexcept;
        std::uint64_t refused_count() const noexcept;
        std::uint64_t notimpl_count() const noexcept;
        std::uint64_t formerr_count() const noexcept;

    private:

        // body of the receive thread; pulls datagrams, decodes, dispatches by query type
        void receive_loop();

        // build a response packet from an incoming query; mutates counters as it picks an rcode
        DnsPacket build_response(const DnsPacket& query);

        // emit one encoded packet back to the peer; logs on failure
        void send_packet(const DnsPacket& pkt, const ::sockaddr_in& to);

        std::uint16_t m_port { 53 };           // udp port the server listens on
        SocketFd m_socket { };                 // raii owned udp socket
        std::thread m_thread { };              // receive loop thread
        std::atomic<bool> m_running { false }; // shared running flag

        std::shared_ptr<DnsZone> m_zone { };   // the zone we serve

        std::atomic<std::uint64_t> m_queries { 0 };
        std::atomic<std::uint64_t> m_noerror { 0 };
        std::atomic<std::uint64_t> m_nxdomain { 0 };
        std::atomic<std::uint64_t> m_refused { 0 };
        std::atomic<std::uint64_t> m_notimpl { 0 };
        std::atomic<std::uint64_t> m_formerr { 0 };

    };

}

#endif // NODE_MONITOR_DNS_SERVER_HH
