// related headers

// c sys headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

// cpp stdlib headers
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <print>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// 3rd party headers

// project headers
#include "DhcpPacket.hh"
#include "DhcpPool.hh"
#include "DhcpServer.hh"

namespace
{

    // build one DhcpPacket of the requested message type for a given mac + xid
    ::NodeMonitor::DhcpPacket make_packet(std::uint32_t xid, const std::array<std::uint8_t, 6>& mac, ::NodeMonitor::DhcpMessageType type)
    {

        using namespace ::NodeMonitor;
        DhcpPacket pkt { };
        pkt.m_op = k_bootp_request;
        pkt.m_htype = k_htype_ethernet;
        pkt.m_hlen = k_hlen_ethernet;
        pkt.m_xid = xid;
        for (std::size_t i { 0uz }; i < 6uz; ++i) pkt.m_chaddr[i] = mac[i];
        pkt.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::MessageType), std::vector<std::uint8_t> { static_cast<std::uint8_t>(type) });
        return pkt;

    }

}

int main(int argc, char** argv)
{

    using namespace ::NodeMonitor;

    std::size_t n_exchanges { 5000uz };
    if (argc >= 2)
    {
        try { n_exchanges = std::stoull(argv[1]); }
        catch (...) { std::println("usage: dhcp_bench_wire [n_exchanges]"); return 1; }
    }

    // bring up a real DhcpServer on a non-privileged loopback port (so the bench doesn't need
    // NET_BIND_SERVICE). 10.42.0.0/16 pool gives us 65k usable ips — well above the bench size
    const std::uint16_t port { 16767u };
    auto pool { std::make_unique<DhcpPool>((10u << 24) | (42u << 16), 16u, ((10u << 24) | (42u << 16)) | 1u, ((10u << 24) | (42u << 16)) | 2u, std::chrono::seconds { 3600 }) };
    std::println("starting DhcpServer on udp port {} (pool 10.42.0.0/16, ~65k usable)", port);
    DhcpServer server { port, std::move(pool), nullptr, ((10u << 24) | (42u << 16)) | 1u };
    server.start();

    std::this_thread::sleep_for(std::chrono::milliseconds { 100 });

    // sender socket on loopback with a small recv timeout. each exchange is two round trips (DORA)
    int fd { ::socket(AF_INET, SOCK_DGRAM, 0) };
    if (fd < 0) { std::println("error: failed to create sender socket"); return 1; }
    ::timeval tv { };
    tv.tv_sec = 0;
    tv.tv_usec = 500000;  // 500ms — loopback DORA is comfortably under this
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ::sockaddr_in dest { };
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    dest.sin_port = ::htons(port);

    // pre-encode the DISCOVER and REQUEST packets so the timing loop measures only kernel + server cost
    std::println("pre-encoding {} DORA exchanges", n_exchanges);
    struct Pair { std::vector<std::uint8_t> m_discover; std::vector<std::uint8_t> m_request; };
    std::vector<Pair> pairs { };
    pairs.reserve(n_exchanges);
    std::mt19937 rng { 1812u };
    std::uniform_int_distribution<int> mac_byte { 0, 255 };
    for (std::size_t i { 0uz }; i < n_exchanges; ++i)
    {
        std::array<std::uint8_t, 6> mac { };
        mac[0] = static_cast<std::uint8_t>((mac_byte(rng) & 0xFE) | 0x02);
        for (std::size_t b { 1uz }; b < 6uz; ++b) mac[b] = static_cast<std::uint8_t>(mac_byte(rng));
        std::uint32_t xid { static_cast<std::uint32_t>(rng()) };
        Pair p { };
        p.m_discover = encode_dhcp(make_packet(xid, mac, DhcpMessageType::Discover));
        p.m_request  = encode_dhcp(make_packet(xid, mac, DhcpMessageType::Request));
        pairs.push_back(std::move(p));
    }

    // warmup: 200 DORAs so the receive thread and pool allocator are jit-resident
    std::println("warmup pass (200 DORA exchanges)");
    std::uint8_t recv_buf[2048] { };
    for (std::size_t i { 0uz }; i < 200uz && i < pairs.size(); ++i)
    {
        ::sendto(fd, pairs[i].m_discover.data(), pairs[i].m_discover.size(), 0, reinterpret_cast<::sockaddr*>(&dest), sizeof(dest));
        ::recvfrom(fd, recv_buf, sizeof(recv_buf), 0, nullptr, nullptr);
        ::sendto(fd, pairs[i].m_request.data(), pairs[i].m_request.size(), 0, reinterpret_cast<::sockaddr*>(&dest), sizeof(dest));
        ::recvfrom(fd, recv_buf, sizeof(recv_buf), 0, nullptr, nullptr);
    }

    // measurement: each lease = 4 syscalls (sendto discover, recvfrom offer, sendto request, recvfrom ack)
    std::println("running benchmark (real UDP DORA on 127.0.0.1)");
    std::size_t bound { 0uz };
    std::size_t dropped { 0uz };
    auto t_start { std::chrono::steady_clock::now() };
    for (const auto& p : pairs)
    {

        // DISCOVER -> OFFER
        if (::sendto(fd, p.m_discover.data(), p.m_discover.size(), 0, reinterpret_cast<::sockaddr*>(&dest), sizeof(dest)) < 0) { ++dropped; continue; }
        ::ssize_t n1 { ::recvfrom(fd, recv_buf, sizeof(recv_buf), 0, nullptr, nullptr) };
        if (n1 <= 0) { ++dropped; continue; }

        // REQUEST -> ACK
        if (::sendto(fd, p.m_request.data(), p.m_request.size(), 0, reinterpret_cast<::sockaddr*>(&dest), sizeof(dest)) < 0) { ++dropped; continue; }
        ::ssize_t n2 { ::recvfrom(fd, recv_buf, sizeof(recv_buf), 0, nullptr, nullptr) };
        if (n2 <= 0) { ++dropped; continue; }

        ++bound;

    }
    auto t_end { std::chrono::steady_clock::now() };

    ::close(fd);
    server.stop();

    double elapsed_sec { std::chrono::duration<double>(t_end - t_start).count() };
    double per_sec { static_cast<double>(bound) / elapsed_sec };
    double us_per { (elapsed_sec * 1e6) / static_cast<double>(bound) };

    std::println("--- results (over-the-wire) ---");
    std::println("DORA exchanges sent : {}", n_exchanges);
    std::println("leases bound        : {}", bound);
    std::println("dropped / timeout   : {}", dropped);
    std::println("elapsed             : {:.3f} sec", elapsed_sec);
    std::println("throughput          : {:.0f} leases/sec", per_sec);
    std::println("avg latency         : {:.1f} us/lease (= 4 syscalls + server processing)", us_per);
    std::println("note                : real UDP through the kernel on 127.0.0.1. each lease = 2 round trips = 4 syscalls minimum.");

    return 0;

}
