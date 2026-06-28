// related headers
#include "SnmpPoller.hh"

// c sys headers
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <print>
#include <string>
#include <utility>
#include <variant>
#include <vector>

// 3rd party headers

// project headers
#include "AsnBer.hh"
#include "Metric.hh"
#include "SnmpMessage.hh"

namespace NodeMonitor
{

    namespace
    {

        // OIDs we poll on every target — kept in one place so the response decoder can match by OID
        const AsnBer::Oid k_oid_sys_name { 1u, 3u, 6u, 1u, 2u, 1u, 1u, 5u, 0u };
        const AsnBer::Oid k_oid_sys_uptime { 1u, 3u, 6u, 1u, 2u, 1u, 1u, 3u, 0u };
        const AsnBer::Oid k_oid_cpu     { 1u, 3u, 6u, 1u, 4u, 1u, 99999u, 2u, 0u };
        const AsnBer::Oid k_oid_memory  { 1u, 3u, 6u, 1u, 4u, 1u, 99999u, 3u, 0u };

        // resolve `host` to a sockaddr_in; supports both dotted-quad and hostname inputs via getaddrinfo
        bool resolve_host(const std::string& host, std::uint16_t port, ::sockaddr_in& out)
        {

            ::addrinfo hints { };
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            ::addrinfo* res { nullptr };
            if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) return false;
            out = *reinterpret_cast<::sockaddr_in*>(res->ai_addr);
            out.sin_port = ::htons(port);
            ::freeaddrinfo(res);
            return true;

        }

    }

    SnmpPoller::SnmpPoller(std::shared_ptr<MetricCache> cache, std::shared_ptr<MetricStore> store, std::chrono::seconds interval, std::chrono::milliseconds per_target_timeout)
        : m_cache { std::move(cache) }, m_store { std::move(store) }, m_interval { interval }, m_per_target_timeout { per_target_timeout }
    {

    }

    SnmpPoller::~SnmpPoller()
    {

        if (m_running.load()) stop();

    }

    void SnmpPoller::add_target(const std::string& host, std::uint16_t port, const std::string& community)
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        if (m_targets.contains(host)) return;
        SnmpTargetState s { };
        s.m_host = host;
        s.m_port = port;
        s.m_community = community;
        m_targets.emplace(host, std::move(s));

    }

    void SnmpPoller::start()
    {

        if (m_running.exchange(true)) return;
        m_thread = std::thread { [this] { run(); } };

    }

    void SnmpPoller::stop()
    {

        m_running.store(false);
        {
            std::lock_guard<std::mutex> lock { m_cv_mutex };
            m_cv.notify_all();
        }
        if (m_thread.joinable()) m_thread.join();

    }

    bool SnmpPoller::is_running() const noexcept
    {

        return m_running.load();

    }

    std::uint64_t SnmpPoller::total_polls() const noexcept
    {

        return m_total_polls.load(std::memory_order_relaxed);

    }

    std::uint64_t SnmpPoller::total_successes() const noexcept
    {

        return m_total_successes.load(std::memory_order_relaxed);

    }

    std::uint64_t SnmpPoller::total_timeouts() const noexcept
    {

        return m_total_timeouts.load(std::memory_order_relaxed);

    }

    std::uint64_t SnmpPoller::total_errors() const noexcept
    {

        return m_total_errors.load(std::memory_order_relaxed);

    }

    std::vector<SnmpTargetState> SnmpPoller::snapshot() const
    {

        std::vector<SnmpTargetState> out { };
        std::lock_guard<std::mutex> lock { m_mutex };
        out.reserve(m_targets.size());
        for (const auto& [host, state] : m_targets) out.push_back(state);
        return out;

    }

    void SnmpPoller::run()
    {

        std::println("snmp poller running; interval={}s timeout={}ms", m_interval.count(), m_per_target_timeout.count());

        while (m_running.load())
        {

            // grab a snapshot list of hosts under the lock; poll each without holding the lock so the
            // sweep can take seconds without blocking add_target / snapshot calls
            std::vector<std::string> hosts { };
            {
                std::lock_guard<std::mutex> lock { m_mutex };
                hosts.reserve(m_targets.size());
                for (const auto& [host, _] : m_targets) hosts.push_back(host);
            }

            for (const auto& host : hosts)
            {

                if (!m_running.load()) break;

                SnmpTargetState working { };
                {
                    std::lock_guard<std::mutex> lock { m_mutex };
                    auto it { m_targets.find(host) };
                    if (it == m_targets.end()) continue;
                    working = it->second;
                }

                m_total_polls.fetch_add(1uz, std::memory_order_relaxed);
                bool ok { poll_target(working) };
                if (ok) m_total_successes.fetch_add(1uz, std::memory_order_relaxed);

                {
                    std::lock_guard<std::mutex> lock { m_mutex };
                    auto it { m_targets.find(host) };
                    if (it != m_targets.end()) it->second = std::move(working);
                }

            }

            // sleep until the next sweep, but be interruptible via stop()
            std::unique_lock<std::mutex> cv_lock { m_cv_mutex };
            m_cv.wait_for(cv_lock, m_interval, [this] { return !m_running.load(); });

        }

    }

    bool SnmpPoller::poll_target(SnmpTargetState& state)
    {

        ::sockaddr_in dest { };
        if (!resolve_host(state.m_host, state.m_port, dest))
        {
            ++state.m_errors;
            m_total_errors.fetch_add(1uz, std::memory_order_relaxed);
            return false;
        }

        // build a GetRequest for our 4 baseline OIDs in a single request
        SnmpMessage msg { };
        msg.m_version = 1; // v2c
        msg.m_community = state.m_community;
        msg.m_pdu.m_pdu_tag = AsnBer::k_tag_get_request;

        // simple unique-enough request id from the wall clock; the response correlation only checks
        // that the id we sent comes back, so monotonic-ish is fine
        static std::atomic<std::int32_t> s_next_rid { 1 };
        msg.m_pdu.m_request_id = s_next_rid.fetch_add(1, std::memory_order_relaxed);

        for (const auto& oid : { k_oid_sys_name, k_oid_sys_uptime, k_oid_cpu, k_oid_memory })
        {
            SnmpVarbind vb { };
            vb.m_oid = oid;
            vb.m_value_tag = AsnBer::k_tag_null;
            msg.m_pdu.m_varbinds.push_back(std::move(vb));
        }

        auto encoded { encode_snmp(msg) };

        // open udp socket with a recv timeout matching m_per_target_timeout
        int fd { ::socket(AF_INET, SOCK_DGRAM, 0) };
        if (fd < 0)
        {
            ++state.m_errors;
            m_total_errors.fetch_add(1uz, std::memory_order_relaxed);
            return false;
        }

        ::timeval tv { };
        tv.tv_sec = static_cast<long>(m_per_target_timeout.count() / 1000);
        tv.tv_usec = static_cast<long>((m_per_target_timeout.count() % 1000) * 1000);
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        auto t_start { std::chrono::steady_clock::now() };
        state.m_last_poll = std::chrono::system_clock::now();
        ++state.m_queries;

        if (::sendto(fd, encoded.data(), encoded.size(), 0, reinterpret_cast<::sockaddr*>(&dest), sizeof(dest)) < 0)
        {
            ::close(fd);
            ++state.m_errors;
            m_total_errors.fetch_add(1uz, std::memory_order_relaxed);
            return false;
        }

        std::uint8_t buffer[4096] { };
        ::ssize_t n { ::recvfrom(fd, buffer, sizeof(buffer), 0, nullptr, nullptr) };
        ::close(fd);

        if (n <= 0)
        {
            ++state.m_timeouts;
            m_total_timeouts.fetch_add(1uz, std::memory_order_relaxed);
            return false;
        }

        auto decoded { decode_snmp(buffer, static_cast<std::size_t>(n)) };
        if (!decoded.has_value() || decoded->m_pdu.m_request_id != msg.m_pdu.m_request_id)
        {
            ++state.m_errors;
            m_total_errors.fetch_add(1uz, std::memory_order_relaxed);
            return false;
        }

        // walk the response varbinds and route each value into the state struct by matching its OID
        for (const auto& vb : decoded->m_pdu.m_varbinds)
        {
            if (AsnBer::compare_oids(vb.m_oid, k_oid_sys_name) == 0 && vb.m_value_tag == AsnBer::k_tag_octet_string)
            {
                if (std::holds_alternative<std::string>(vb.m_value)) state.m_last_sys_name = std::get<std::string>(vb.m_value);
            }
            else if (AsnBer::compare_oids(vb.m_oid, k_oid_sys_uptime) == 0 && vb.m_value_tag == AsnBer::k_tag_time_ticks)
            {
                if (std::holds_alternative<std::uint32_t>(vb.m_value)) state.m_last_uptime_ticks = std::get<std::uint32_t>(vb.m_value);
            }
            else if (AsnBer::compare_oids(vb.m_oid, k_oid_cpu) == 0 && vb.m_value_tag == AsnBer::k_tag_gauge32)
            {
                if (std::holds_alternative<std::uint32_t>(vb.m_value)) state.m_last_cpu = std::get<std::uint32_t>(vb.m_value);
            }
            else if (AsnBer::compare_oids(vb.m_oid, k_oid_memory) == 0 && vb.m_value_tag == AsnBer::k_tag_gauge32)
            {
                if (std::holds_alternative<std::uint32_t>(vb.m_value)) state.m_last_memory = std::get<std::uint32_t>(vb.m_value);
            }
        }

        auto t_end { std::chrono::steady_clock::now() };
        state.m_last_latency_ms = static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count());
        ++state.m_successes;

        // feed the existing telemetry pipeline so dashboards and alert rules see the snmp-sourced values
        // without caring how they were obtained. the payload also gets the raw uptime ticks for visibility
        if (!state.m_last_sys_name.empty() && m_cache)
        {
            Metric m { };
            m.m_hostname = state.m_last_sys_name;
            m.m_vendor = "snmp";
            m.m_cpu = static_cast<double>(state.m_last_cpu);
            m.m_memory = static_cast<double>(state.m_last_memory);
            m.m_timestamp = state.m_last_poll;
            m.m_payload = {
                { "source", "snmp" },
                { "uptime_ticks", state.m_last_uptime_ticks },
                { "snmp_target", state.m_host },
            };
            m_cache->update(m);
            if (m_store) m_store->persist(m);
        }

        return true;

    }

}
