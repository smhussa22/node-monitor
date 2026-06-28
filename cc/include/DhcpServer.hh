#ifndef NODE_MONITOR_DHCP_SERVER_HH
#define NODE_MONITOR_DHCP_SERVER_HH

// related headers
#include "DhcpLease.hh"
#include "DhcpPacket.hh"
#include "DhcpPool.hh"
#include "MetricStore.hh"
#include "SocketFd.hh"

// c sys headers
#include <netinet/in.h>

// cpp stdlib headers
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // udp dhcp server that speaks RFC 2131-shaped packets and walks every client through the DORA exchange.
    // designed for unicast operation on a kubernetes overlay where layer-2 broadcast doesn't reach across
    // pods; clients are configured at deploy time with the server's address rather than discovering it.
    // a single mutex guards both the lease map and the pool, so all state changes are sequenced cleanly
    class DhcpServer
    {

    public:

        DhcpServer() = delete;
        DhcpServer(std::uint16_t port, std::unique_ptr<DhcpPool> pool, std::shared_ptr<MetricStore> store, std::uint32_t server_id);
        ~DhcpServer();

        DhcpServer(const DhcpServer&) = delete;
        DhcpServer& operator=(const DhcpServer&) = delete;
        DhcpServer(DhcpServer&&) = delete;
        DhcpServer& operator=(DhcpServer&&) = delete;

        // open the udp socket, bind, and spawn the receive + reaper threads
        void start();

        // stop the receive loop and reaper, then close the socket
        void stop();

        std::uint16_t port() const noexcept;
        bool is_running() const noexcept;

        // monotonic counters useful for the dashboard and smoke tests
        std::uint64_t discover_count() const noexcept;
        std::uint64_t offer_count() const noexcept;
        std::uint64_t request_count() const noexcept;
        std::uint64_t ack_count() const noexcept;
        std::uint64_t nak_count() const noexcept;
        std::uint64_t release_count() const noexcept;
        std::uint64_t expired_count() const noexcept;

        // snapshot the lease table for dashboard rendering; copies under the lock so the engine
        // is free to keep mutating after the snapshot is returned
        std::vector<DhcpLease> lease_snapshot() const;

        std::size_t free_count() const;
        std::size_t in_use_count() const;
        std::size_t total_count() const;

    private:

        // body of the receive thread; reads datagrams, decodes, and dispatches by message type
        void receive_loop();

        // body of the reaper thread; periodically walks the lease map expiring everything past its deadline
        void reaper_loop();

        // dispatchers; each takes its own lock as needed and may emit a reply on the socket
        void handle_discover(const DhcpPacket& pkt, const ::sockaddr_in& from);
        void handle_request(const DhcpPacket& pkt, const ::sockaddr_in& from);
        void handle_release(const DhcpPacket& pkt);

        // construct an OFFER / ACK / NAK in reply to an incoming client message; do not send
        DhcpPacket build_offer(const DhcpPacket& discover, std::uint32_t offered_ip) const;
        DhcpPacket build_ack(const DhcpPacket& request, std::uint32_t ack_ip) const;
        DhcpPacket build_nak(const DhcpPacket& request) const;

        // send one packet to the given peer over the udp socket; logs and drops on failure
        void send_packet(const DhcpPacket& pkt, const ::sockaddr_in& to);

        std::uint16_t m_port { 67 };                    // udp port the server listens on; defaults to RFC 2131
        SocketFd m_socket { };                          // raii owned udp socket
        std::thread m_receive_thread { };               // receive loop thread
        std::thread m_reaper_thread { };                // expiry sweeper thread
        std::atomic<bool> m_running { false };          // shared running flag for both threads

        std::condition_variable m_reaper_cv { };        // wakes the reaper for shutdown without waiting the full tick
        std::mutex m_reaper_mutex { };                  // pairs with m_reaper_cv; only used for the wait/notify

        std::unique_ptr<DhcpPool> m_pool { };           // address pool owned by this server
        std::unordered_map<std::uint64_t, DhcpLease> m_leases { }; // packed-mac -> lease record
        mutable std::mutex m_mutex { };                 // single lock guarding m_pool + m_leases together

        std::uint32_t m_server_id { 0 };                // server identifier sent in option 54; host byte order

        std::shared_ptr<MetricStore> m_store { };       // optional postgres persistence; null when disabled

        std::atomic<std::uint64_t> m_discover_count { 0 };
        std::atomic<std::uint64_t> m_offer_count { 0 };
        std::atomic<std::uint64_t> m_request_count { 0 };
        std::atomic<std::uint64_t> m_ack_count { 0 };
        std::atomic<std::uint64_t> m_nak_count { 0 };
        std::atomic<std::uint64_t> m_release_count { 0 };
        std::atomic<std::uint64_t> m_expired_count { 0 };

    };

}

#endif // NODE_MONITOR_DHCP_SERVER_HH
