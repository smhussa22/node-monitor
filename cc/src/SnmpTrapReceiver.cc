// related headers
#include "SnmpTrapReceiver.hh"

// c sys headers
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// cpp stdlib headers
#include <cstdint>
#include <cstring>
#include <format>
#include <mutex>
#include <print>
#include <string>
#include <utility>
#include <variant>
#include <vector>

// 3rd party headers

// project headers
#include "SnmpMessage.hh"

namespace NodeMonitor
{

    namespace
    {

        // mandatory v2 trap head varbind: sysUpTime.0 (1.3.6.1.2.1.1.3.0)
        const AsnBer::Oid k_oid_sys_uptime { 1u, 3u, 6u, 1u, 2u, 1u, 1u, 3u, 0u };

        // mandatory v2 trap head varbind: snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0); its value names the event
        const AsnBer::Oid k_oid_snmp_trap_oid { 1u, 3u, 6u, 1u, 6u, 3u, 1u, 1u, 4u, 1u, 0u };

        // render an SnmpVarbind value as a short string for the dashboard's "extras" column
        std::string vb_value_str(const SnmpVarbind& vb)
        {

            switch (vb.m_value_tag)
            {
                case AsnBer::k_tag_integer:
                    return std::holds_alternative<std::int64_t>(vb.m_value) ? std::to_string(std::get<std::int64_t>(vb.m_value)) : std::string { };
                case AsnBer::k_tag_octet_string:
                    return std::holds_alternative<std::string>(vb.m_value) ? std::get<std::string>(vb.m_value) : std::string { };
                case AsnBer::k_tag_oid:
                    return std::holds_alternative<AsnBer::Oid>(vb.m_value) ? AsnBer::oid_to_string(std::get<AsnBer::Oid>(vb.m_value)) : std::string { };
                case AsnBer::k_tag_counter32:
                case AsnBer::k_tag_gauge32:
                case AsnBer::k_tag_time_ticks:
                case AsnBer::k_tag_ip_address:
                    return std::holds_alternative<std::uint32_t>(vb.m_value) ? std::to_string(std::get<std::uint32_t>(vb.m_value)) : std::string { };
                default:
                    return std::string { "?" };
            }

        }

    }

    SnmpTrapReceiver::SnmpTrapReceiver(std::uint16_t port, std::size_t ring_capacity)
        : m_port { port }, m_ring_capacity { ring_capacity }
    {

    }

    SnmpTrapReceiver::~SnmpTrapReceiver()
    {

        if (m_running.load()) stop();

    }

    void SnmpTrapReceiver::start()
    {

        if (m_running.exchange(true)) return;

        // bind the udp socket synchronously before spawning the receive thread so stop() can always
        // ::shutdown() m_socket to unblock recvfrom; otherwise a quick start/stop would race the
        // late socket assignment and leak the worker
        int fd { ::socket(AF_INET, SOCK_DGRAM, 0) };
        if (fd < 0)
        {
            std::println("error: failed to create snmp trap udp socket");
            m_running.store(false);
            return;
        }

        int reuse { 1 };
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        ::sockaddr_in addr { };
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ::htonl(INADDR_ANY);
        addr.sin_port = ::htons(m_port);

        if (::bind(fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            std::println("error: failed to bind snmp trap socket to port {}", m_port);
            ::close(fd);
            m_running.store(false);
            return;
        }

        m_socket.reset(fd);
        std::println("snmp trap receiver listening on udp port {}", m_port);

        m_thread = std::thread { [this] { receive_loop(); } };

    }

    void SnmpTrapReceiver::stop()
    {

        m_running.store(false);
        if (m_socket.is_valid()) ::shutdown(m_socket.get(), SHUT_RDWR);
        if (m_thread.joinable()) m_thread.join();
        m_socket.reset();

    }

    std::uint16_t SnmpTrapReceiver::port() const noexcept
    {

        return m_port;

    }

    bool SnmpTrapReceiver::is_running() const noexcept
    {

        return m_running.load();

    }

    std::uint64_t SnmpTrapReceiver::received_count() const noexcept
    {

        return m_received.load(std::memory_order_relaxed);

    }

    std::uint64_t SnmpTrapReceiver::dropped_count() const noexcept
    {

        return m_dropped.load(std::memory_order_relaxed);

    }

    std::vector<SnmpTrapRecord> SnmpTrapReceiver::snapshot() const
    {

        std::vector<SnmpTrapRecord> out { };
        std::lock_guard<std::mutex> lock { m_mutex };
        out.reserve(m_ring.size());
        // newest-first
        for (auto it { m_ring.rbegin() }; it != m_ring.rend(); ++it) out.push_back(*it);
        return out;

    }

    void SnmpTrapReceiver::receive_loop()
    {

        // socket bind is done in start() so stop() can always shutdown() it cleanly
        int fd { m_socket.get() };
        if (fd < 0) return;

        std::uint8_t buffer[4096] { };
        while (m_running.load())
        {

            ::sockaddr_in from { };
            ::socklen_t from_len { sizeof(from) };
            ::ssize_t n { ::recvfrom(fd, buffer, sizeof(buffer), 0, reinterpret_cast<::sockaddr*>(&from), &from_len) };
            if (n <= 0)
            {
                if (m_running.load()) std::println("warn: snmp trap recvfrom returned {}", n);
                continue;
            }

            auto decoded { decode_snmp(buffer, static_cast<std::size_t>(n)) };
            if (!decoded.has_value() || decoded->m_pdu.m_pdu_tag != AsnBer::k_tag_trap_v2)
            {
                m_dropped.fetch_add(1uz, std::memory_order_relaxed);
                continue;
            }

            SnmpTrapRecord rec { };
            rec.m_received_at = std::chrono::system_clock::now();

            char ip_buf[32] { };
            ::inet_ntop(AF_INET, &from.sin_addr, ip_buf, sizeof(ip_buf));
            rec.m_source_ip = ip_buf;

            rec.m_community = decoded->m_community;

            std::string extras_joined { };
            for (const auto& vb : decoded->m_pdu.m_varbinds)
            {
                if (AsnBer::compare_oids(vb.m_oid, k_oid_sys_uptime) == 0 && vb.m_value_tag == AsnBer::k_tag_time_ticks)
                {
                    if (std::holds_alternative<std::uint32_t>(vb.m_value)) rec.m_uptime_ticks = std::get<std::uint32_t>(vb.m_value);
                }
                else if (AsnBer::compare_oids(vb.m_oid, k_oid_snmp_trap_oid) == 0 && vb.m_value_tag == AsnBer::k_tag_oid)
                {
                    if (std::holds_alternative<AsnBer::Oid>(vb.m_value)) rec.m_event_oid = AsnBer::oid_to_string(std::get<AsnBer::Oid>(vb.m_value));
                }
                else
                {
                    if (!extras_joined.empty()) extras_joined.append("; ");
                    extras_joined.append(std::format("{}={}", AsnBer::oid_to_string(vb.m_oid), vb_value_str(vb)));
                }
            }
            rec.m_extras_str = std::move(extras_joined);

            {
                std::lock_guard<std::mutex> lock { m_mutex };
                m_ring.push_back(std::move(rec));
                while (m_ring.size() > m_ring_capacity) m_ring.pop_front();
            }
            m_received.fetch_add(1uz, std::memory_order_relaxed);

        }

    }

}
