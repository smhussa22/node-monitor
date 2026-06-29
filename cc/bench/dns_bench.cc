// related headers

// c sys headers

// cpp stdlib headers
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <memory>
#include <print>
#include <random>
#include <string>
#include <vector>

// 3rd party headers

// project headers
#include "AsnBer.hh"   // for the OID lex compare helpers — not strictly used here but pulls the build target
#include "DnsPacket.hh"
#include "DnsZone.hh"

namespace
{

    // one pre-encoded DNS query packet; we also store the expected qtype so the bench can report a
    // rcode mix at the end (NoError / NXDOMAIN / Refused) without re-parsing the response
    struct SyntheticQuery
    {

        std::vector<std::uint8_t> m_bytes { };  // wire-format query, ready to feed decode_dns
        std::uint8_t m_expected_class { 0u };   // 0 = noerror (in-zone known), 1 = nxdomain (in-zone unknown), 2 = refused (out of zone)
        ::NodeMonitor::DnsType m_qtype { ::NodeMonitor::DnsType::A };

    };

    // build a wire-format query packet for (qname, qtype) using the project's own codec
    std::vector<std::uint8_t> build_query(std::uint16_t id, const std::string& qname, ::NodeMonitor::DnsType qtype)
    {

        using namespace ::NodeMonitor;
        DnsPacket pkt { };
        pkt.m_header.m_id = id;
        // QR=0 (query), Opcode=0 (standard), RD=1 (recursion desired)
        set_qr(pkt.m_header, false);
        set_rd(pkt.m_header, true);
        DnsQuestion q { };
        q.m_name = qname;
        q.m_qtype = qtype;
        q.m_qclass = DnsClass::IN;
        pkt.m_questions.push_back(std::move(q));
        return encode_dns(pkt);

    }

    // ad-hoc replay of DnsServer::build_response without dragging the socket layer in. we use the zone
    // directly: A / AAAA / PTR / outside-zone get distinct rcodes, so the bench output mirrors what the
    // real server would do at the wire level
    ::NodeMonitor::DnsRcode answer_query(const ::NodeMonitor::DnsPacket& query, const ::NodeMonitor::DnsZone& zone, ::NodeMonitor::DnsPacket& out)
    {

        using namespace ::NodeMonitor;

        out.m_header.m_id = query.m_header.m_id;
        set_qr(out.m_header, true);
        set_opcode(out.m_header, get_opcode(query.m_header));
        set_rd(out.m_header, get_rd(query.m_header));
        set_ra(out.m_header, false);
        if (query.m_questions.empty())
        {
            set_rcode(out.m_header, DnsRcode::FormErr);
            return DnsRcode::FormErr;
        }
        const auto& question { query.m_questions.front() };
        out.m_questions.push_back(question);

        if (!zone.covers(question.m_name))
        {
            set_rcode(out.m_header, DnsRcode::Refused);
            return DnsRcode::Refused;
        }
        set_aa(out.m_header, true);

        switch (question.m_qtype)
        {
            case DnsType::A:
            {
                auto ip { zone.lookup_a(question.m_name) };
                if (!ip.has_value()) { set_rcode(out.m_header, DnsRcode::NxDomain); return DnsRcode::NxDomain; }
                DnsRR ans { };
                ans.m_name = question.m_name;
                ans.m_type = DnsType::A;
                ans.m_class = DnsClass::IN;
                ans.m_ttl = 60u;
                ans.m_rdata = encode_a_rdata(*ip);
                out.m_answers.push_back(std::move(ans));
                set_rcode(out.m_header, DnsRcode::NoError);
                return DnsRcode::NoError;
            }
            case DnsType::AAAA:
            {
                auto rdata { zone.lookup_aaaa(question.m_name) };
                if (!rdata.has_value()) { set_rcode(out.m_header, DnsRcode::NxDomain); return DnsRcode::NxDomain; }
                DnsRR ans { };
                ans.m_name = question.m_name;
                ans.m_type = DnsType::AAAA;
                ans.m_class = DnsClass::IN;
                ans.m_ttl = 60u;
                ans.m_rdata = std::move(*rdata);
                out.m_answers.push_back(std::move(ans));
                set_rcode(out.m_header, DnsRcode::NoError);
                return DnsRcode::NoError;
            }
            case DnsType::PTR:
            {
                auto name { zone.lookup_ptr(question.m_name) };
                if (!name.has_value()) { set_rcode(out.m_header, DnsRcode::NxDomain); return DnsRcode::NxDomain; }
                DnsRR ans { };
                ans.m_name = question.m_name;
                ans.m_type = DnsType::PTR;
                ans.m_class = DnsClass::IN;
                ans.m_ttl = 60u;
                ans.m_rdata = encode_name_uncompressed(*name);
                out.m_answers.push_back(std::move(ans));
                set_rcode(out.m_header, DnsRcode::NoError);
                return DnsRcode::NoError;
            }
            default:
                set_rcode(out.m_header, DnsRcode::NotImpl);
                return DnsRcode::NotImpl;
        }

    }

}

int main(int argc, char** argv)
{

    using namespace ::NodeMonitor;

    std::size_t n_queries { 500'000uz };
    if (argc >= 2)
    {
        try { n_queries = std::stoull(argv[1]); }
        catch (...) { std::println("usage: dns_bench [n_queries]"); return 1; }
    }

    // build the zone with ~1000 fake hostnames; reverse + AAAA derive automatically
    std::println("populating zone with 1000 synthetic hostnames");
    auto zone { std::make_shared<DnsZone>("node-monitor.local") };
    for (std::uint32_t i { 1u }; i <= 1000u; ++i)
    {
        std::uint32_t ip { (10u << 24) | (42u << 16) | i };
        zone->bind(std::format("host-{}", i), ip, "bench");
    }

    // generate the query mix: 60% A in-zone hits, 15% AAAA in-zone hits, 10% PTR in-zone hits,
    // 10% A in-zone unknown (NXDOMAIN), 5% A outside-zone (REFUSED). gives every response code a
    // representative sample so the bench output is honest about each rcode's cost
    std::println("generating {} queries (60% A-hit / 15% AAAA-hit / 10% PTR-hit / 10% NXDOMAIN / 5% REFUSED)", n_queries);
    std::vector<SyntheticQuery> queries { };
    queries.reserve(n_queries);
    std::mt19937 rng { 4242u };
    std::uniform_int_distribution<int> mix { 0, 99 };
    std::uniform_int_distribution<int> host_pick { 1, 1000 };
    std::uniform_int_distribution<int> ip_octet { 1, 254 };

    for (std::size_t i { 0uz }; i < n_queries; ++i)
    {
        int kind { mix(rng) };
        std::uint16_t id { static_cast<std::uint16_t>(rng() & 0xFFFFu) };
        SyntheticQuery q { };

        if (kind < 60)
        {
            // A hit
            q.m_qtype = DnsType::A;
            q.m_expected_class = 0u;
            std::string name { std::format("host-{}.node-monitor.local", host_pick(rng)) };
            q.m_bytes = build_query(id, name, DnsType::A);
        }
        else if (kind < 75)
        {
            // AAAA hit
            q.m_qtype = DnsType::AAAA;
            q.m_expected_class = 0u;
            std::string name { std::format("host-{}.node-monitor.local", host_pick(rng)) };
            q.m_bytes = build_query(id, name, DnsType::AAAA);
        }
        else if (kind < 85)
        {
            // PTR hit
            q.m_qtype = DnsType::PTR;
            q.m_expected_class = 0u;
            std::uint32_t which { static_cast<std::uint32_t>(host_pick(rng)) };
            std::uint32_t ip { (10u << 24) | (42u << 16) | which };
            q.m_bytes = build_query(id, ipv4_to_arpa(ip), DnsType::PTR);
        }
        else if (kind < 95)
        {
            // NXDOMAIN (in-zone unknown)
            q.m_qtype = DnsType::A;
            q.m_expected_class = 1u;
            std::string name { std::format("missing-{}.node-monitor.local", rng() & 0xFFFFFu) };
            q.m_bytes = build_query(id, name, DnsType::A);
        }
        else
        {
            // REFUSED (outside zone)
            q.m_qtype = DnsType::A;
            q.m_expected_class = 2u;
            std::string name { std::format("host{}.example.com", host_pick(rng)) };
            q.m_bytes = build_query(id, name, DnsType::A);
        }

        queries.push_back(std::move(q));
    }

    // warmup pass to make sure decode + answer + encode are jit/cache-resident
    std::println("warmup pass (min(10k, n))");
    std::size_t warm { queries.size() < 10000uz ? queries.size() : 10000uz };
    for (std::size_t i { 0uz }; i < warm; ++i)
    {
        auto decoded { decode_dns(queries[i].m_bytes.data(), queries[i].m_bytes.size()) };
        if (!decoded.has_value()) continue;
        DnsPacket reply { };
        answer_query(*decoded, *zone, reply);
        auto enc { encode_dns(reply) };
        (void)enc;
    }

    // measurement: every query goes through decode -> answer -> encode so the bench reports the full
    // server cost a real udp datagram would incur minus the kernel + syscall overhead
    std::println("running benchmark");
    std::size_t noerror { 0uz };
    std::size_t nxdomain { 0uz };
    std::size_t refused { 0uz };
    std::size_t notimpl { 0uz };
    std::size_t formerr { 0uz };

    auto t_start { std::chrono::steady_clock::now() };
    for (const auto& q : queries)
    {
        auto decoded { decode_dns(q.m_bytes.data(), q.m_bytes.size()) };
        if (!decoded.has_value()) { ++formerr; continue; }
        DnsPacket reply { };
        DnsRcode rc { answer_query(*decoded, *zone, reply) };
        auto enc { encode_dns(reply) };
        (void)enc;

        switch (rc)
        {
            case DnsRcode::NoError:  ++noerror;  break;
            case DnsRcode::NxDomain: ++nxdomain; break;
            case DnsRcode::Refused:  ++refused;  break;
            case DnsRcode::NotImpl:  ++notimpl;  break;
            case DnsRcode::FormErr:  ++formerr;  break;
            default: break;
        }
    }
    auto t_end { std::chrono::steady_clock::now() };

    double elapsed_sec { std::chrono::duration<double>(t_end - t_start).count() };
    double qps { static_cast<double>(n_queries) / elapsed_sec };
    double ns_per { (elapsed_sec * 1e9) / static_cast<double>(n_queries) };

    std::println("--- results ---");
    std::println("queries         : {}", n_queries);
    std::println("zone size       : {} entries", zone->entry_count());
    std::println("elapsed         : {:.3f} sec", elapsed_sec);
    std::println("throughput      : {:.0f} queries/sec", qps);
    std::println("avg latency     : {:.0f} ns/query ({:.2f} us/query)", ns_per, ns_per / 1000.0);
    std::println("rcode mix       : NoError={} NXDOMAIN={} Refused={} NotImpl={} FormErr={}", noerror, nxdomain, refused, notimpl, formerr);
    std::println("note            : in-process (no kernel UDP). real over-the-wire QPS will be 10-30x lower due to syscall + scheduling overhead.");

    return 0;

}
