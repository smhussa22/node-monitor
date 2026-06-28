// related headers
#include "DhcpServer.hh"

// c sys headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <cstring>
#include <format>
#include <mutex>
#include <print>
#include <string>
#include <utility>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // local helpers; kept anonymous so they don't leak into the public api
    namespace
    {

        // encode a 4-byte host-byte-order ipv4 into a 4-byte big-endian option value
        std::vector<std::uint8_t> ip_option(std::uint32_t ip)
        {

            return {
                static_cast<std::uint8_t>((ip >> 24) & 0xFFu),
                static_cast<std::uint8_t>((ip >> 16) & 0xFFu),
                static_cast<std::uint8_t>((ip >> 8) & 0xFFu),
                static_cast<std::uint8_t>(ip & 0xFFu),
            };

        }

        // encode a 4-byte unsigned host-order value as 4 bytes big-endian; used for lease / T1 / T2
        std::vector<std::uint8_t> u32_option(std::uint32_t v)
        {

            return ip_option(v);

        }

        // pull a 4-byte option payload back to a host-byte-order uint32; returns 0 on malformed input
        std::uint32_t decode_ip_option(const std::vector<std::uint8_t>& v)
        {

            if (v.size() != 4uz) return 0u;
            return (static_cast<std::uint32_t>(v[0]) << 24)
                 | (static_cast<std::uint32_t>(v[1]) << 16)
                 | (static_cast<std::uint32_t>(v[2]) << 8)
                 |  static_cast<std::uint32_t>(v[3]);

        }

    }

    DhcpServer::DhcpServer(std::uint16_t port, std::unique_ptr<DhcpPool> pool, std::shared_ptr<MetricStore> store, std::uint32_t server_id, std::shared_ptr<DnsZone> zone)
        : m_port { port }, m_pool { std::move(pool) }, m_server_id { server_id }, m_store { std::move(store) }, m_dns_zone { std::move(zone) }
    {

    }

    DhcpServer::~DhcpServer()
    {

        if (m_running.load()) stop();

    }

    void DhcpServer::start()
    {

        if (m_running.exchange(true)) return;
        m_receive_thread = std::thread { [this] { receive_loop(); } };
        m_reaper_thread = std::thread { [this] { reaper_loop(); } };

    }

    void DhcpServer::stop()
    {

        m_running.store(false);

        // wake the reaper out of its sleep so it can observe the stopped flag
        {
            std::lock_guard<std::mutex> lock { m_reaper_mutex };
            m_reaper_cv.notify_all();
        }

        // unblock the receive thread by shutting the socket
        if (m_socket.is_valid()) ::shutdown(m_socket.get(), SHUT_RDWR);

        if (m_receive_thread.joinable()) m_receive_thread.join();
        if (m_reaper_thread.joinable()) m_reaper_thread.join();
        m_socket.reset();

    }

    std::uint16_t DhcpServer::port() const noexcept
    {

        return m_port;

    }

    bool DhcpServer::is_running() const noexcept
    {

        return m_running.load();

    }

    std::uint64_t DhcpServer::discover_count() const noexcept
    {

        return m_discover_count.load(std::memory_order_relaxed);

    }

    std::uint64_t DhcpServer::offer_count() const noexcept
    {

        return m_offer_count.load(std::memory_order_relaxed);

    }

    std::uint64_t DhcpServer::request_count() const noexcept
    {

        return m_request_count.load(std::memory_order_relaxed);

    }

    std::uint64_t DhcpServer::ack_count() const noexcept
    {

        return m_ack_count.load(std::memory_order_relaxed);

    }

    std::uint64_t DhcpServer::nak_count() const noexcept
    {

        return m_nak_count.load(std::memory_order_relaxed);

    }

    std::uint64_t DhcpServer::release_count() const noexcept
    {

        return m_release_count.load(std::memory_order_relaxed);

    }

    std::uint64_t DhcpServer::expired_count() const noexcept
    {

        return m_expired_count.load(std::memory_order_relaxed);

    }

    std::vector<DhcpLease> DhcpServer::lease_snapshot() const
    {

        std::vector<DhcpLease> out { };
        std::lock_guard<std::mutex> lock { m_mutex };
        out.reserve(m_leases.size());
        for (const auto& [mac, lease] : m_leases) out.push_back(lease);
        return out;

    }

    std::size_t DhcpServer::free_count() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        return m_pool ? m_pool->free_count() : 0uz;

    }

    std::size_t DhcpServer::in_use_count() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        return m_pool ? m_pool->in_use_count() : 0uz;

    }

    std::size_t DhcpServer::total_count() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        return m_pool ? m_pool->total_count() : 0uz;

    }

    void DhcpServer::receive_loop()
    {

        // create + bind the udp socket; we listen on all interfaces because the unicast destination
        // will be our pod's clusterip and we don't want to enumerate that here
        int fd { ::socket(AF_INET, SOCK_DGRAM, 0) };
        if (fd < 0)
        {
            std::println("error: failed to create dhcp udp socket");
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
            std::println("error: failed to bind dhcp socket to port {}", m_port);
            ::close(fd);
            m_running.store(false);
            return;
        }

        m_socket.reset(fd);
        std::println("dhcp server listening on udp port {}", m_port);

        // dhcp packets are tiny; a 2 kib buffer is comfortable for the 300-ish-byte typical packet
        std::uint8_t buffer[2048] { };
        while (m_running.load())
        {

            ::sockaddr_in from { };
            ::socklen_t from_len { sizeof(from) };
            ::ssize_t n { ::recvfrom(fd, buffer, sizeof(buffer), 0, reinterpret_cast<::sockaddr*>(&from), &from_len) };
            if (n <= 0)
            {
                if (m_running.load()) std::println("warn: dhcp recvfrom returned {}", n);
                continue;
            }

            auto decoded { decode_dhcp(buffer, static_cast<std::size_t>(n)) };
            if (!decoded.has_value())
            {
                std::println("warn: dropped malformed dhcp packet of {} bytes", n);
                continue;
            }

            // accept only requests from clients; ignore replies that some misconfigured client could echo
            if (decoded->m_op != k_bootp_request) continue;

            auto mtype { get_message_type(*decoded) };
            if (!mtype.has_value()) continue;

            switch (*mtype)
            {
                case DhcpMessageType::Discover: handle_discover(*decoded, from); break;
                case DhcpMessageType::Request:  handle_request(*decoded, from); break;
                case DhcpMessageType::Release:  handle_release(*decoded); break;
                default: break;
            }

        }

    }

    void DhcpServer::reaper_loop()
    {

        // tick once a second; on each tick walk the lease table and expire anything past its deadline
        while (m_running.load())
        {

            {
                std::unique_lock<std::mutex> lock { m_reaper_mutex };
                m_reaper_cv.wait_for(lock, std::chrono::seconds { 1 }, [this] { return !m_running.load(); });
            }
            if (!m_running.load()) break;

            auto now { std::chrono::system_clock::now() };

            std::lock_guard<std::mutex> lock { m_mutex };
            for (auto it { m_leases.begin() }; it != m_leases.end(); )
            {

                if (it->second.m_state == DhcpLeaseState::Bound && now >= it->second.m_expires_at)
                {

                    std::println("[dhcp] lease expired mac={} ip={}", mac_to_string(it->first), ipv4_to_dotted(it->second.m_ip));
                    if (m_pool) m_pool->release(it->second.m_ip);
                    it->second.m_state = DhcpLeaseState::Expired;
                    m_expired_count.fetch_add(1uz, std::memory_order_relaxed);
                    if (m_store) m_store->record_dhcp_lease(it->second);
                    if (m_dns_zone)
                    {
                        std::string label { it->second.m_hostname };
                        if (label.empty()) label = std::format("mac-{:012x}", it->first);
                        m_dns_zone->unbind(label);
                    }

                    // keep the expired record around briefly so dashboard observers see it before we
                    // drop it; for now we remove immediately to keep memory bounded
                    it = m_leases.erase(it);

                }
                else
                {
                    ++it;
                }

            }

        }

    }

    void DhcpServer::handle_discover(const DhcpPacket& pkt, const ::sockaddr_in& from)
    {

        m_discover_count.fetch_add(1uz, std::memory_order_relaxed);

        std::uint64_t mac { mac_pack(pkt.m_chaddr) };

        // honor option 50 (requested ip) when present; the pool will validate and fall back if it's taken
        std::uint32_t requested { 0u };
        if (auto opt { get_option(pkt, DhcpOptionCode::RequestedIp) }; opt.has_value()) requested = decode_ip_option(*opt);

        std::uint32_t offered_ip { 0u };
        {
            std::lock_guard<std::mutex> lock { m_mutex };

            // if this mac already has a lease (offered or bound) reuse its ip; clients often retry DISCOVER
            auto existing { m_leases.find(mac) };
            if (existing != m_leases.end()) offered_ip = existing->second.m_ip;
            else offered_ip = m_pool ? m_pool->allocate(requested) : 0u;

            if (offered_ip == 0u)
            {
                std::println("warn: dhcp pool exhausted; no OFFER for mac={}", mac_to_string(mac));
                return;
            }

            DhcpLease lease { };
            lease.m_mac = mac;
            lease.m_ip = offered_ip;
            lease.m_state = DhcpLeaseState::Offered;
            lease.m_granted_at = std::chrono::system_clock::now();
            lease.m_expires_at = lease.m_granted_at + (m_pool ? m_pool->lease_duration() : std::chrono::seconds { 3600 });
            if (auto hn { get_option(pkt, DhcpOptionCode::Hostname) }; hn.has_value())
                lease.m_hostname = std::string { hn->begin(), hn->end() };

            m_leases[mac] = lease;
            if (m_store) m_store->record_dhcp_lease(lease);
        }

        auto offer { build_offer(pkt, offered_ip) };
        send_packet(offer, from);
        m_offer_count.fetch_add(1uz, std::memory_order_relaxed);
        std::println("[dhcp] OFFER mac={} ip={}", mac_to_string(mac), ipv4_to_dotted(offered_ip));

    }

    void DhcpServer::handle_request(const DhcpPacket& pkt, const ::sockaddr_in& from)
    {

        m_request_count.fetch_add(1uz, std::memory_order_relaxed);

        std::uint64_t mac { mac_pack(pkt.m_chaddr) };

        // a REQUEST carries the ip the client wants to bind. it may be in option 50 (selecting state)
        // or in m_ciaddr (renewing / rebinding state). we accept either
        std::uint32_t requested { 0u };
        if (auto opt { get_option(pkt, DhcpOptionCode::RequestedIp) }; opt.has_value()) requested = decode_ip_option(*opt);
        if (requested == 0u) requested = pkt.m_ciaddr;

        DhcpLease bound { };
        bool ok { false };
        {
            std::lock_guard<std::mutex> lock { m_mutex };
            auto it { m_leases.find(mac) };

            // happy path: this mac has a matching lease record; flip Offered -> Bound and refresh expiry
            if (it != m_leases.end() && (requested == 0u || it->second.m_ip == requested))
            {
                it->second.m_state = DhcpLeaseState::Bound;
                it->second.m_granted_at = std::chrono::system_clock::now();
                it->second.m_expires_at = it->second.m_granted_at + (m_pool ? m_pool->lease_duration() : std::chrono::seconds { 3600 });
                bound = it->second;
                ok = true;
                if (m_store) m_store->record_dhcp_lease(it->second);
            }
        }

        if (!ok)
        {

            auto nak { build_nak(pkt) };
            send_packet(nak, from);
            m_nak_count.fetch_add(1uz, std::memory_order_relaxed);
            std::println("[dhcp] NAK mac={} requested={}", mac_to_string(mac), ipv4_to_dotted(requested));
            return;

        }

        auto ack { build_ack(pkt, bound.m_ip) };
        send_packet(ack, from);
        m_ack_count.fetch_add(1uz, std::memory_order_relaxed);
        std::println("[dhcp] ACK mac={} ip={} lease={}s", mac_to_string(mac), ipv4_to_dotted(bound.m_ip), m_pool ? m_pool->lease_duration().count() : 3600);

        // populate the DNS zone so other clients can resolve this host by name. we bind the lease's
        // hostname (from option 12) when present; otherwise we fall back to a "mac-aabbcc" short label
        if (m_dns_zone)
        {
            std::string label { bound.m_hostname };
            if (label.empty()) label = std::format("mac-{:012x}", mac);
            m_dns_zone->bind(label, bound.m_ip, "dhcp");
        }

    }

    void DhcpServer::handle_release(const DhcpPacket& pkt)
    {

        m_release_count.fetch_add(1uz, std::memory_order_relaxed);

        std::uint64_t mac { mac_pack(pkt.m_chaddr) };

        std::lock_guard<std::mutex> lock { m_mutex };
        auto it { m_leases.find(mac) };
        if (it == m_leases.end()) return;

        std::println("[dhcp] RELEASE mac={} ip={}", mac_to_string(mac), ipv4_to_dotted(it->second.m_ip));
        if (m_pool) m_pool->release(it->second.m_ip);
        it->second.m_state = DhcpLeaseState::Released;
        if (m_store) m_store->record_dhcp_lease(it->second);
        if (m_dns_zone)
        {
            std::string label { it->second.m_hostname };
            if (label.empty()) label = std::format("mac-{:012x}", mac);
            m_dns_zone->unbind(label);
        }
        m_leases.erase(it);

    }

    DhcpPacket DhcpServer::build_offer(const DhcpPacket& discover, std::uint32_t offered_ip) const
    {

        // start by echoing the BOOTP header so xid / chaddr / flags / giaddr line up with the client
        DhcpPacket out { discover };
        out.m_op = k_bootp_reply;
        out.m_ciaddr = 0u;
        out.m_yiaddr = offered_ip;
        out.m_siaddr = m_server_id;
        out.m_options.clear();

        // mandatory DHCP options for an OFFER per RFC 2131 section 4.3.1
        out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::MessageType), std::vector<std::uint8_t> { static_cast<std::uint8_t>(DhcpMessageType::Offer) });
        out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::ServerId),    ip_option(m_server_id));

        std::uint32_t lease_secs { static_cast<std::uint32_t>(m_pool ? m_pool->lease_duration().count() : 3600) };
        out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::LeaseTime),     u32_option(lease_secs));
        out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::RenewalTime),   u32_option(lease_secs / 2u));
        out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::RebindingTime), u32_option((lease_secs * 7u) / 8u));

        if (m_pool)
        {
            out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::SubnetMask), ip_option(m_pool->subnet_mask()));
            if (m_pool->gateway() != 0u) out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::Router),    ip_option(m_pool->gateway()));
            if (m_pool->dns() != 0u)     out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::DnsServer), ip_option(m_pool->dns()));
        }

        return out;

    }

    DhcpPacket DhcpServer::build_ack(const DhcpPacket& request, std::uint32_t ack_ip) const
    {

        // ACK options mirror OFFER almost exactly; only the message type changes
        auto out { build_offer(request, ack_ip) };
        if (!out.m_options.empty()) out.m_options[0uz].second[0uz] = static_cast<std::uint8_t>(DhcpMessageType::Ack);
        return out;

    }

    DhcpPacket DhcpServer::build_nak(const DhcpPacket& request) const
    {

        // NAK is minimal: just enough header to let the client correlate by xid + chaddr
        DhcpPacket out { request };
        out.m_op = k_bootp_reply;
        out.m_ciaddr = 0u;
        out.m_yiaddr = 0u;
        out.m_siaddr = 0u;
        out.m_options.clear();
        out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::MessageType), std::vector<std::uint8_t> { static_cast<std::uint8_t>(DhcpMessageType::Nak) });
        out.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::ServerId),    ip_option(m_server_id));
        return out;

    }

    void DhcpServer::send_packet(const DhcpPacket& pkt, const ::sockaddr_in& to)
    {

        if (!m_socket.is_valid()) return;

        auto bytes { encode_dhcp(pkt) };

        // honor the BROADCAST flag (bit 15 of m_flags); some embedded clients can't accept unicast
        // because they don't have an ip yet. for our unicast-only deployment this stays clear, but we
        // still respect it if a client sets it
        ::sockaddr_in dest { to };
        if ((pkt.m_flags & 0x8000u) != 0u) dest.sin_addr.s_addr = ::htonl(INADDR_BROADCAST);

        // many clients expect replies on port 68 even when their ephemeral source port differs; the
        // unicast-no-broadcast deployment model lets us reply to whatever port the request came from,
        // which is what `to` already carries. so we use it as-is

        ::ssize_t sent { ::sendto(m_socket.get(), bytes.data(), bytes.size(), 0, reinterpret_cast<const ::sockaddr*>(&dest), sizeof(dest)) };
        if (sent < 0) std::println("warn: dhcp sendto failed");

    }

}
