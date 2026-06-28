// related headers

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <print>
#include <random>
#include <string>
#include <vector>

// 3rd party headers

// project headers
#include "AclEngine.hh"
#include "AclRule.hh"

namespace
{

    // pack 4 bytes into a host-byte-order ipv4 the matcher expects
    std::uint32_t make_ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d)
    {

        return (static_cast<std::uint32_t>(a) << 24) | (static_cast<std::uint32_t>(b) << 16) | (static_cast<std::uint32_t>(c) << 8) | static_cast<std::uint32_t>(d);

    }

    // register the same 8-rule baseline main.cc uses so the bench measures realistic match cost
    void register_baseline(::NodeMonitor::AclEngine& engine)
    {

        using namespace ::NodeMonitor;
        engine.register_rule(std::make_unique<AclRule>(1u, AclAction::Permit, AclProtocol::Tcp,  parse_cidr("any"),        parse_cidr("any"), parse_port_range("any"), parse_port_range("443"),  "permit https"));
        engine.register_rule(std::make_unique<AclRule>(2u, AclAction::Permit, AclProtocol::Tcp,  parse_cidr("any"),        parse_cidr("any"), parse_port_range("any"), parse_port_range("80"),   "permit http"));
        engine.register_rule(std::make_unique<AclRule>(3u, AclAction::Permit, AclProtocol::Udp,  parse_cidr("any"),        parse_cidr("any"), parse_port_range("any"), parse_port_range("53"),   "permit dns"));
        engine.register_rule(std::make_unique<AclRule>(4u, AclAction::Permit, AclProtocol::Tcp,  parse_cidr("10.0.0.0/8"), parse_cidr("any"), parse_port_range("any"), parse_port_range("22"),   "permit ssh from internal"));
        engine.register_rule(std::make_unique<AclRule>(5u, AclAction::Deny,   AclProtocol::Tcp,  parse_cidr("any"),        parse_cidr("any"), parse_port_range("any"), parse_port_range("22"),   "deny ssh from external"));
        engine.register_rule(std::make_unique<AclRule>(6u, AclAction::Deny,   AclProtocol::Tcp,  parse_cidr("any"),        parse_cidr("any"), parse_port_range("any"), parse_port_range("3389"), "deny rdp"));
        engine.register_rule(std::make_unique<AclRule>(7u, AclAction::Deny,   AclProtocol::Tcp,  parse_cidr("any"),        parse_cidr("any"), parse_port_range("any"), parse_port_range("23"),   "deny telnet"));
        engine.register_rule(std::make_unique<AclRule>(8u, AclAction::Deny,   AclProtocol::Icmp, parse_cidr("any"),        parse_cidr("any"), parse_port_range("any"), parse_port_range("any"),  "deny icmp"));

    }

    // one synthetic flow tuple matching the cisco simulator's record shape
    struct SyntheticFlow
    {

        std::uint32_t m_src_ip { 0 };
        std::uint32_t m_dst_ip { 0 };
        std::uint16_t m_src_port { 0 };
        std::uint16_t m_dst_port { 0 };
        ::NodeMonitor::AclProtocol m_protocol { ::NodeMonitor::AclProtocol::Tcp };

    };

    // generate a representative mix of flows; same port + protocol distribution the cisco simulator uses
    std::vector<SyntheticFlow> generate_flows(std::size_t n, std::uint32_t seed)
    {

        std::mt19937 rng { seed };
        std::uniform_int_distribution<int> src_last { 1, 254 };
        std::uniform_int_distribution<int> dst_b { 0, 255 };
        std::uniform_int_distribution<int> dst_c { 0, 255 };
        std::uniform_int_distribution<int> dst_d { 1, 254 };
        std::uniform_int_distribution<int> src_port { 1024, 65535 };
        std::uniform_int_distribution<int> ephemeral_port { 1024, 65535 };
        std::uniform_int_distribution<int> well_known_pick { 0, 6 };
        std::uniform_int_distribution<int> proto_pick { 0, 9 };

        std::vector<SyntheticFlow> flows { };
        flows.reserve(n);

        for (std::size_t i { 0uz }; i < n; ++i)
        {

            SyntheticFlow f { };
            f.m_src_ip = make_ipv4(10, 0, 0, static_cast<std::uint8_t>(src_last(rng)));
            f.m_dst_ip = make_ipv4(8, static_cast<std::uint8_t>(dst_b(rng)), static_cast<std::uint8_t>(dst_c(rng)), static_cast<std::uint8_t>(dst_d(rng)));
            f.m_src_port = static_cast<std::uint16_t>(src_port(rng));

            // match the cisco simulator's port choice: 80, 443, 22, 53, 3389, 8080, random ephemeral
            switch (well_known_pick(rng))
            {
                case 0: f.m_dst_port = 80; break;
                case 1: f.m_dst_port = 443; break;
                case 2: f.m_dst_port = 22; break;
                case 3: f.m_dst_port = 53; break;
                case 4: f.m_dst_port = 3389; break;
                case 5: f.m_dst_port = 8080; break;
                default: f.m_dst_port = static_cast<std::uint16_t>(ephemeral_port(rng)); break;
            }

            // 70/20/10 split tcp/udp/icmp
            int p { proto_pick(rng) };
            if (p < 7) f.m_protocol = ::NodeMonitor::AclProtocol::Tcp;
            else if (p < 9) f.m_protocol = ::NodeMonitor::AclProtocol::Udp;
            else f.m_protocol = ::NodeMonitor::AclProtocol::Icmp;

            flows.push_back(f);

        }

        return flows;

    }

}

int main(int argc, char** argv)
{

    // accept --flows N to override the default sample size; useful when scaling the run on bigger hardware
    std::size_t flow_count { 1'000'000uz };
    if (argc >= 2)
    {
        try { flow_count = std::stoull(argv[1]); }
        catch (...) { std::println("usage: acl_bench [flow_count]"); return 1; }
    }

    ::NodeMonitor::AclEngine engine { };
    register_baseline(engine);

    std::println("generating {} synthetic flows", flow_count);
    auto flows { generate_flows(flow_count, 42u) };

    // warm the cache lines and force every code path to be jit-resident before we time anything
    std::println("warmup pass (10k flows)");
    std::size_t warm_count { flows.size() < 10'000uz ? flows.size() : 10'000uz };
    for (std::size_t i { 0uz }; i < warm_count; ++i)
    {
        const auto& f { flows[i] };
        engine.evaluate(f.m_src_ip, f.m_dst_ip, f.m_src_port, f.m_dst_port, f.m_protocol);
    }

    // main measurement: walk the entire generated set and time the evaluate calls only (generation excluded)
    std::println("running benchmark");
    auto t_start { std::chrono::steady_clock::now() };
    std::uint64_t permits { 0uz };
    std::uint64_t denies { 0uz };
    std::uint64_t implicit { 0uz };
    for (const auto& f : flows)
    {
        auto verdict { engine.evaluate(f.m_src_ip, f.m_dst_ip, f.m_src_port, f.m_dst_port, f.m_protocol) };
        if (verdict.m_action == ::NodeMonitor::AclAction::Permit) ++permits;
        else if (verdict.m_rule_id < 0) ++implicit;
        else ++denies;
    }
    auto t_end { std::chrono::steady_clock::now() };

    double elapsed_sec { std::chrono::duration<double>(t_end - t_start).count() };
    double flows_per_sec { static_cast<double>(flow_count) / elapsed_sec };
    double ns_per_flow { (elapsed_sec * 1e9) / static_cast<double>(flow_count) };

    std::println("--- results ---");
    std::println("flows evaluated : {}", flow_count);
    std::println("elapsed         : {:.3f} sec", elapsed_sec);
    std::println("throughput      : {:.0f} flows/sec", flows_per_sec);
    std::println("avg latency     : {:.0f} ns/flow", ns_per_flow);
    std::println("verdict mix     : permit={} explicit_deny={} implicit_deny={}", permits, denies, implicit);

    std::println("--- per-rule hit counts ---");
    for (const auto& snap : engine.snapshot())
        std::println("[#{}] {:<7} {:<4} -> {:<5} {:<28} hits={}", snap.m_id, snap.m_action, snap.m_protocol, snap.m_dst_ports, snap.m_description, snap.m_hits);

    return 0;

}
