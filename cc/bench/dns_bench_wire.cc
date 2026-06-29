// related headers

// c sys headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <memory>
#include <print>
#include <random>
#include <string>
#include <thread>
#include <vector>

// 3rd party headers

// project headers
#include "DnsPacket.hh"
#include "DnsServer.hh"
#include "DnsZone.hh"

namespace
{

    // a pre-built query packet ready to drop into sendto(). expected_class lets us tally rcode mix
    // after the fact without parsing every response
    struct SyntheticQuery
    {

        std::vector<std::uint8_t> m_bytes { };
        std::uint8_t m_expected_class { 0u };  // 0=noerror 1=nxdomain 2=refused

    };

    // build a single A / AAAA / PTR query packet for fqdn against the running server
    std::vector<std::uint8_t> build_query(std::uint16_t id, const std::string& fqdn, ::NodeMonitor::DnsType qtype)
    {

        using namespace ::NodeMonitor;
        DnsPacket pkt { };
        pkt.m_header.m_id = id;
        set_qr(pkt.m_header, false);
        set_rd(pkt.m_header, true);
        DnsQuestion q { };
        q.m_name = fqdn;
        q.m_qtype = qtype;
        q.m_qclass = DnsClass::IN;
        pkt.m_questions.push_back(std::move(q));
        return encode_dns(pkt);

    }

}

int main(int argc, char** argv)
{

    using namespace ::NodeMonitor;

    std::size_t n_queries { 50'000uz };
    if (argc >= 2)
    {
        try { n_queries = std::stoull(argv[1]); }
        catch (...) { std::println("usage: dns_bench_wire [n_queries]"); return 1; }
    }

    // populate a zone the running DnsServer can answer from
    std::println("populating zone with 1000 synthetic hostnames");
    auto zone { std::make_shared<DnsZone>("node-monitor.local") };
    for (std::uint32_t i { 1u }; i <= 1000u; ++i)
    {
        std::uint32_t ip { (10u << 24) | (42u << 16) | i };
        zone->bind(std::format("host-{}", i), ip, "bench");
    }

    // pick a high random-ish port and bring the real DnsServer up on it. binding 0.0.0.0 means our
    // sender on 127.0.0.1 will still hit the listener through the loopback adapter
    const std::uint16_t port { 15353u };
    std::println("starting DnsServer on udp port {}", port);
    DnsServer server { port, zone };
    server.start();

    // give the receive thread a moment to bind + start the recvfrom loop
    std::this_thread::sleep_for(std::chrono::milliseconds { 100 });

    // open a sender socket on the same loopback interface with a small recv timeout so a single dropped
    // packet doesn't stall the whole bench
    int fd { ::socket(AF_INET, SOCK_DGRAM, 0) };
    if (fd < 0) { std::println("error: failed to create sender socket"); return 1; }

    ::timeval tv { };
    tv.tv_sec = 0;
    tv.tv_usec = 200000;  // 200ms — generous on loopback
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ::sockaddr_in dest { };
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    dest.sin_port = ::htons(port);

    // generate the same 60/15/10/10/5 query mix the in-process bench uses, so the two numbers compare
    std::println("generating {} queries (60% A-hit / 15% AAAA-hit / 10% PTR-hit / 10% NXDOMAIN / 5% REFUSED)", n_queries);
    std::vector<SyntheticQuery> queries { };
    queries.reserve(n_queries);
    std::mt19937 rng { 1729u };
    std::uniform_int_distribution<int> mix { 0, 99 };
    std::uniform_int_distribution<int> host_pick { 1, 1000 };

    for (std::size_t i { 0uz }; i < n_queries; ++i)
    {
        int k { mix(rng) };
        std::uint16_t id { static_cast<std::uint16_t>(rng() & 0xFFFFu) };
        SyntheticQuery sq { };
        if (k < 60)        { sq.m_bytes = build_query(id, std::format("host-{}.node-monitor.local", host_pick(rng)), DnsType::A); }
        else if (k < 75)   { sq.m_bytes = build_query(id, std::format("host-{}.node-monitor.local", host_pick(rng)), DnsType::AAAA); }
        else if (k < 85)   { std::uint32_t ip { (10u<<24)|(42u<<16)|static_cast<std::uint32_t>(host_pick(rng)) }; sq.m_bytes = build_query(id, ipv4_to_arpa(ip), DnsType::PTR); }
        else if (k < 95)   { sq.m_expected_class = 1u; sq.m_bytes = build_query(id, std::format("missing-{}.node-monitor.local", rng() & 0xFFFFFu), DnsType::A); }
        else               { sq.m_expected_class = 2u; sq.m_bytes = build_query(id, std::format("host{}.example.com", host_pick(rng)), DnsType::A); }
        queries.push_back(std::move(sq));
    }

    // warmup so the loopback path, scheduler, and any first-touch allocations are settled
    std::println("warmup pass (1000 queries)");
    std::uint8_t recv_buf[2048] { };
    std::size_t warm { queries.size() < 1000uz ? queries.size() : 1000uz };
    for (std::size_t i { 0uz }; i < warm; ++i)
    {
        ::sendto(fd, queries[i].m_bytes.data(), queries[i].m_bytes.size(), 0, reinterpret_cast<::sockaddr*>(&dest), sizeof(dest));
        ::recvfrom(fd, recv_buf, sizeof(recv_buf), 0, nullptr, nullptr);
    }

    // measurement: every query round-trips through the kernel. the elapsed time captures send + recv
    // syscalls + scheduler wakeups + the server's UDP receive thread cost
    std::println("running benchmark (real UDP round trips on 127.0.0.1)");
    std::size_t completed { 0uz };
    std::size_t dropped { 0uz };
    auto t_start { std::chrono::steady_clock::now() };
    for (const auto& q : queries)
    {
        ::ssize_t sent { ::sendto(fd, q.m_bytes.data(), q.m_bytes.size(), 0, reinterpret_cast<::sockaddr*>(&dest), sizeof(dest)) };
        if (sent < 0) { ++dropped; continue; }
        ::ssize_t got { ::recvfrom(fd, recv_buf, sizeof(recv_buf), 0, nullptr, nullptr) };
        if (got <= 0) { ++dropped; continue; }
        ++completed;
    }
    auto t_end { std::chrono::steady_clock::now() };

    ::close(fd);
    server.stop();

    double elapsed_sec { std::chrono::duration<double>(t_end - t_start).count() };
    double qps { static_cast<double>(completed) / elapsed_sec };
    double ns_per { (elapsed_sec * 1e9) / static_cast<double>(completed) };

    std::println("--- results (over-the-wire) ---");
    std::println("queries sent      : {}", n_queries);
    std::println("queries completed : {}", completed);
    std::println("dropped / timeout : {}", dropped);
    std::println("elapsed           : {:.3f} sec", elapsed_sec);
    std::println("throughput        : {:.0f} queries/sec", qps);
    std::println("avg latency       : {:.1f} us/query (round trip)", ns_per / 1000.0);
    std::println("note              : real UDP through the kernel on 127.0.0.1. includes sendto + recvfrom syscalls + scheduler wakeups + the server's receive thread cost.");

    return 0;

}
