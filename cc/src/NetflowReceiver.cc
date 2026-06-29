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
#include "NetflowV5Packet.hh"

namespace NodeMonitor
{

    NetflowReceiver::NetflowReceiver(std::uint16_t port, std::shared_ptr<MetricStore> store, std::shared_ptr<AclEngine> acl)
        : m_port { port }, m_store { std::move(store) }, m_acl { std::move(acl) }
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

        // pull datagrams until shutdown; parse each as a binary NetFlow v5 packet (24-byte header + N
        // fixed 48-byte records). per-record we build a json document matching the existing flows-table
        // schema, run it through the AclEngine, and persist it. malformed packets are counted, not crashed
        std::uint64_t parse_errors { 0 };
        std::uint8_t buffer[2048] { };
        while (m_running.load())
        {

            ::sockaddr_in client_addr { };
            ::socklen_t addr_len { sizeof(client_addr) };
            ::ssize_t n { ::recvfrom(sock_fd, buffer, sizeof(buffer), 0, reinterpret_cast<::sockaddr*>(&client_addr), &addr_len) };
            if (n <= 0)
            {
                if (m_running.load()) std::println("error: netflow recvfrom failed");
                continue;
            }

            auto decoded { decode_netflow_v5(buffer, static_cast<std::size_t>(n)) };
            if (!decoded.has_value())
            {
                ++parse_errors;
                continue;
            }

            // hostname isn't carried in v5 wire format; we use the sender's source ip dotted form as the
            // "hostname" tag for the existing per-host counters and flows-table column. dashboards that
            // want a friendlier name should join against the dhcp lease / dns zone tables
            char src_ip_buf[INET_ADDRSTRLEN] { };
            ::inet_ntop(AF_INET, &client_addr.sin_addr, src_ip_buf, sizeof(src_ip_buf));
            std::string hostname { src_ip_buf };

            for (const auto& rec : decoded->m_records)
            {

                std::uint64_t total { m_total_flows.fetch_add(1uz) + 1uz };
                std::size_t unique_hosts { 0uz };
                {
                    std::lock_guard<std::mutex> lock { m_mutex };
                    ++m_per_host_flows[hostname];
                    unique_hosts = m_per_host_flows.size();
                }

                // shape one record into the json schema the rest of the project already consumes
                ::nlohmann::json flow_json { };
                flow_json["src_ip"]   = netflow_ipv4_to_dotted(rec.m_src_addr);
                flow_json["dst_ip"]   = netflow_ipv4_to_dotted(rec.m_dst_addr);
                flow_json["src_port"] = rec.m_src_port;
                flow_json["dst_port"] = rec.m_dst_port;
                flow_json["protocol"] = netflow_protocol_name(rec.m_protocol);
                flow_json["bytes"]    = rec.m_octets;
                flow_json["duration"] = (rec.m_last_ms >= rec.m_first_ms) ? (rec.m_last_ms - rec.m_first_ms) / 1000u : 0u;
                flow_json["hostname"] = hostname;

                AclVerdict verdict { m_acl ? m_acl->evaluate(flow_json) : AclVerdict { AclAction::Permit, -1 } };

                if (total % 100uz == 0uz)
                {
                    std::uint64_t permits { m_acl ? m_acl->total_permits() : 0uz };
                    std::uint64_t denies { m_acl ? m_acl->total_denies() : 0uz };
                    std::uint64_t implicit { m_acl ? m_acl->implicit_denies() : 0uz };
                    std::println("[netflow] total={} unique_hosts={} acl_permit={} acl_deny={} acl_implicit={} parse_errors={}", total, unique_hosts, permits, denies, implicit, parse_errors);
                }

                if (m_store) m_store->persist_flow(flow_json, verdict);

            }

        }

    }

}
