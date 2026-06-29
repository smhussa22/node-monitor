// related headers
#include "DnsServer.hh"

// c sys headers
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// cpp stdlib headers
#include <cstdint>
#include <cstring>
#include <print>
#include <string>
#include <utility>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    DnsServer::DnsServer(std::uint16_t port, std::shared_ptr<DnsZone> zone)
        : m_port { port }, m_zone { std::move(zone) }
    {

    }

    DnsServer::~DnsServer()
    {

        if (m_running.load()) stop();

    }

    void DnsServer::start()
    {

        if (m_running.exchange(true)) return;
        m_thread = std::thread { [this] { receive_loop(); } };

    }

    void DnsServer::stop()
    {

        m_running.store(false);
        if (m_socket.is_valid()) ::shutdown(m_socket.get(), SHUT_RDWR);
        if (m_thread.joinable()) m_thread.join();
        m_socket.reset();

    }

    std::uint16_t DnsServer::port() const noexcept
    {

        return m_port;

    }

    bool DnsServer::is_running() const noexcept
    {

        return m_running.load();

    }

    std::uint64_t DnsServer::query_count() const noexcept
    {

        return m_queries.load(std::memory_order_relaxed);

    }

    std::uint64_t DnsServer::noerror_count() const noexcept
    {

        return m_noerror.load(std::memory_order_relaxed);

    }

    std::uint64_t DnsServer::nxdomain_count() const noexcept
    {

        return m_nxdomain.load(std::memory_order_relaxed);

    }

    std::uint64_t DnsServer::refused_count() const noexcept
    {

        return m_refused.load(std::memory_order_relaxed);

    }

    std::uint64_t DnsServer::notimpl_count() const noexcept
    {

        return m_notimpl.load(std::memory_order_relaxed);

    }

    std::uint64_t DnsServer::formerr_count() const noexcept
    {

        return m_formerr.load(std::memory_order_relaxed);

    }

    void DnsServer::receive_loop()
    {

        // create + bind the udp socket; listen on all interfaces so any source ip reaches us
        int fd { ::socket(AF_INET, SOCK_DGRAM, 0) };
        if (fd < 0)
        {
            std::println("error: failed to create dns udp socket");
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
            std::println("error: failed to bind dns socket to port {}", m_port);
            ::close(fd);
            m_running.store(false);
            return;
        }

        m_socket.reset(fd);
        std::println("dns server listening on udp port {} (zone {})", m_port, m_zone ? m_zone->suffix() : std::string { "<none>" });

        std::uint8_t buffer[2048] { };
        while (m_running.load())
        {

            ::sockaddr_in from { };
            ::socklen_t from_len { sizeof(from) };
            ::ssize_t n { ::recvfrom(fd, buffer, sizeof(buffer), 0, reinterpret_cast<::sockaddr*>(&from), &from_len) };
            if (n <= 0)
            {
                if (m_running.load()) std::println("warn: dns recvfrom returned {}", n);
                continue;
            }

            auto decoded { decode_dns(buffer, static_cast<std::size_t>(n)) };
            if (!decoded.has_value())
            {
                std::println("warn: dropped malformed dns packet of {} bytes", n);
                m_formerr.fetch_add(1uz, std::memory_order_relaxed);
                continue;
            }

            // ignore replies (other servers' responses) and only handle standard queries with at least one question
            if (get_qr(decoded->m_header)) continue;
            if (decoded->m_questions.empty()) continue;

            m_queries.fetch_add(1uz, std::memory_order_relaxed);
            auto response { build_response(*decoded) };
            send_packet(response, from);

        }

    }

    DnsPacket DnsServer::build_response(const DnsPacket& query)
    {

        DnsPacket out { };

        // mirror the query's id, opcode, and RD so the client can correlate
        out.m_header.m_id = query.m_header.m_id;
        set_qr(out.m_header, true);
        set_opcode(out.m_header, get_opcode(query.m_header));
        set_rd(out.m_header, get_rd(query.m_header));
        set_ra(out.m_header, false); // honest: we don't recurse

        // echo the first question; behaviorally we only answer the first question even when multiple are
        // present, which matches what nearly every real DNS server does (per RFC 1035 ambiguity)
        out.m_questions.push_back(query.m_questions.front());
        const auto& question { out.m_questions.front() };

        // we only implement Query opcode and IN class; everything else is NotImpl / Refused
        if (get_opcode(query.m_header) != DnsOpcode::Query)
        {
            set_rcode(out.m_header, DnsRcode::NotImpl);
            m_notimpl.fetch_add(1uz, std::memory_order_relaxed);
            return out;
        }
        if (question.m_qclass != DnsClass::IN)
        {
            set_rcode(out.m_header, DnsRcode::NotImpl);
            m_notimpl.fetch_add(1uz, std::memory_order_relaxed);
            return out;
        }

        // outside our zone -> REFUSED. this is the authoritative-only behavior; we are not a resolver
        if (!m_zone || !m_zone->covers(question.m_name))
        {
            set_rcode(out.m_header, DnsRcode::Refused);
            m_refused.fetch_add(1uz, std::memory_order_relaxed);
            return out;
        }

        // we're authoritative for what we cover
        set_aa(out.m_header, true);

        switch (question.m_qtype)
        {

            case DnsType::A:
            {

                auto ip { m_zone->lookup_a(question.m_name) };
                if (!ip.has_value())
                {
                    set_rcode(out.m_header, DnsRcode::NxDomain);
                    m_nxdomain.fetch_add(1uz, std::memory_order_relaxed);
                    return out;
                }

                DnsRR ans { };
                ans.m_name = question.m_name;
                ans.m_type = DnsType::A;
                ans.m_class = DnsClass::IN;
                ans.m_ttl = 60u;
                ans.m_rdata = encode_a_rdata(*ip);
                out.m_answers.push_back(std::move(ans));
                set_rcode(out.m_header, DnsRcode::NoError);
                m_noerror.fetch_add(1uz, std::memory_order_relaxed);
                return out;

            }
            case DnsType::AAAA:
            {

                auto rdata { m_zone->lookup_aaaa(question.m_name) };
                if (!rdata.has_value())
                {
                    set_rcode(out.m_header, DnsRcode::NxDomain);
                    m_nxdomain.fetch_add(1uz, std::memory_order_relaxed);
                    return out;
                }

                DnsRR ans { };
                ans.m_name = question.m_name;
                ans.m_type = DnsType::AAAA;
                ans.m_class = DnsClass::IN;
                ans.m_ttl = 60u;
                ans.m_rdata = std::move(*rdata);
                out.m_answers.push_back(std::move(ans));
                set_rcode(out.m_header, DnsRcode::NoError);
                m_noerror.fetch_add(1uz, std::memory_order_relaxed);
                return out;

            }
            case DnsType::PTR:
            {

                auto name { m_zone->lookup_ptr(question.m_name) };
                if (!name.has_value())
                {
                    set_rcode(out.m_header, DnsRcode::NxDomain);
                    m_nxdomain.fetch_add(1uz, std::memory_order_relaxed);
                    return out;
                }

                DnsRR ans { };
                ans.m_name = question.m_name;
                ans.m_type = DnsType::PTR;
                ans.m_class = DnsClass::IN;
                ans.m_ttl = 60u;
                ans.m_rdata = encode_name_uncompressed(*name);
                out.m_answers.push_back(std::move(ans));
                set_rcode(out.m_header, DnsRcode::NoError);
                m_noerror.fetch_add(1uz, std::memory_order_relaxed);
                return out;

            }
            default:
            {

                // any other type within our zone: report NotImpl rather than lying with NoError + empty answer
                set_rcode(out.m_header, DnsRcode::NotImpl);
                m_notimpl.fetch_add(1uz, std::memory_order_relaxed);
                return out;

            }

        }

    }

    void DnsServer::send_packet(const DnsPacket& pkt, const ::sockaddr_in& to)
    {

        if (!m_socket.is_valid()) return;

        auto bytes { encode_dns(pkt) };
        ::ssize_t sent { ::sendto(m_socket.get(), bytes.data(), bytes.size(), 0, reinterpret_cast<const ::sockaddr*>(&to), sizeof(to)) };
        if (sent < 0) std::println("warn: dns sendto failed");

    }

}
