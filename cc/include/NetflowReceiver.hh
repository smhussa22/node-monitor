#ifndef NODE_MONITOR_NETFLOW_RECEIVER_HH
#define NODE_MONITOR_NETFLOW_RECEIVER_HH

// related headers
#include "SocketFd.hh"

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // udp listener that ingests json netflow records emitted by simulated devices
    class NetflowReceiver
    {

    public:

        NetflowReceiver() = delete;
        explicit NetflowReceiver(std::uint16_t port);
        ~NetflowReceiver();

        NetflowReceiver(const NetflowReceiver&) = delete;
        NetflowReceiver& operator=(const NetflowReceiver&) = delete;

        NetflowReceiver(NetflowReceiver&&) = delete;
        NetflowReceiver& operator=(NetflowReceiver&&) = delete;

        // begin receiving netflow datagrams on the configured port
        void start();

        // shutdown the socket and join the receive thread
        void stop();

        // port the receiver is bound to
        std::uint16_t port() const;

        // whether the receive loop is currently running
        bool is_running() const;

        // total number of flow records successfully parsed
        std::uint64_t flow_count() const;

        // number of flow records received for a particular source hostname
        std::uint64_t flow_count_for(const std::string& hostname) const;

    private:

        // body of the receive thread; binds the socket and pulls datagrams
        void receive_loop();

        std::uint16_t m_port { 0 }; // udp port the receiver listens on
        SocketFd m_socket { }; // raii owned udp socket file descriptor
        std::thread m_thread { }; // thread that runs the receive loop
        std::atomic<bool> m_running { false }; // whether the receive loop is currently active
        std::atomic<std::uint64_t> m_total_flows { 0 }; // total flow records successfully parsed
        std::unordered_map<std::string, std::uint64_t> m_per_host_flows { }; // per source hostname flow counts
        mutable std::mutex m_mutex { }; // protects the per host flow count map

    };

}

#endif // NODE_MONITOR_NETFLOW_RECEIVER_HH
