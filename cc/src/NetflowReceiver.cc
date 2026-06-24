// related headers
#include "NetflowReceiver.hh"

// c sys headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// cpp stdlib headers
#include <cstring>
#include <print>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers

namespace NodeMonitor
{

    NetflowReceiver::NetflowReceiver(std::uint16_t port)
        : m_port { port }
    {

    }

    NetflowReceiver::~NetflowReceiver()
    {

        if (m_running.load()) stop();

    }

    void NetflowReceiver::start()
    {

        if (m_running.exchange(true)) return;
        m_thread = std::thread { [this] { receive_loop(); } };

    }

    void NetflowReceiver::stop()
    {

        m_running.store(false);

        // shutdown the udp socket to unblock the pending recvfrom() call so the receive thread can exit
        if (m_socket.is_valid()) ::shutdown(m_socket.get(), SHUT_RDWR);
        if (m_thread.joinable()) m_thread.join();
        m_socket.reset();

    }

    std::uint16_t NetflowReceiver::port() const
    {

        return m_port;

    }

    bool NetflowReceiver::is_running() const
    {

        return m_running.load();

    }

    std::uint64_t NetflowReceiver::flow_count() const
    {

        return m_total_flows.load();

    }

    std::uint64_t NetflowReceiver::flow_count_for(const std::string& hostname) const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        auto it { m_per_host_flows.find(hostname) };
        if (it == m_per_host_flows.end()) return 0uz;
        return it->second;

    }

    void NetflowReceiver::receive_loop()
    {

        // create, configure, and bind the udp socket
        int sock_fd { ::socket(AF_INET, SOCK_DGRAM, 0) };
        if (sock_fd < 0)
        {
            std::println("error: failed to create netflow udp socket");
            m_running.store(false);
            return;
        }

        int opt { 1 };
        ::setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        ::sockaddr_in addr { };
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ::htonl(INADDR_ANY);
        addr.sin_port = ::htons(m_port);

        if (::bind(sock_fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            std::println("error: failed to bind netflow receiver to port {}", m_port);
            ::close(sock_fd);
            m_running.store(false);
            return;
        }

        m_socket.reset(sock_fd);
        std::println("netflow receiver listening on udp port {}", m_port);

        // pull datagrams until shutdown; parse each as json and tally per host counters
        std::uint64_t parse_errors { 0 };
        char buffer[2048] { };
        while (m_running.load())
        {

            ::sockaddr_in client_addr { };
            ::socklen_t addr_len { sizeof(client_addr) };
            ::ssize_t n { ::recvfrom(sock_fd, buffer, sizeof(buffer) - 1, 0, reinterpret_cast<::sockaddr*>(&client_addr), &addr_len) };
            if (n <= 0)
            {
                if (m_running.load()) std::println("error: netflow recvfrom failed");
                continue;
            }
            buffer[n] = '\0';

            // declare-then-assign avoids nlohmann's initializer_list ctor wrapping a single value in an array
            try
            {
                ::nlohmann::json parsed { };
                parsed = ::nlohmann::json::parse(buffer);
                if (!parsed.is_object())
                {
                    ++parse_errors;
                    continue;
                }
                std::string hostname { parsed.value("hostname", std::string { }) };
                std::uint64_t total { m_total_flows.fetch_add(1uz) + 1uz };
                std::size_t unique_hosts { 0uz };
                {
                    std::lock_guard<std::mutex> lock { m_mutex };
                    ++m_per_host_flows[hostname];
                    unique_hosts = m_per_host_flows.size();
                }

                // heartbeat every 100 flows so the log does not get spammed
                if (total % 100uz == 0uz) std::println("[netflow] total={} unique_hosts={}", total, unique_hosts);
            }
            catch (const ::nlohmann::json::exception& e)
            {
                ++parse_errors;
                std::println("error: failed to parse netflow json: {}", e.what());
            }

        }

    }

}
