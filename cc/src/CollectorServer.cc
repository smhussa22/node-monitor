// related headers
#include "CollectorServer.hh"

// c sys headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// cpp stdlib headers
#include <cstring>
#include <format>
#include <print>
#include <string>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers
#include "DhcpPacket.hh"
#include "DnsPacket.hh"
#include "Metric.hh"

namespace NodeMonitor
{

    CollectorServer::CollectorServer(std::shared_ptr<MetricCache> cache, std::shared_ptr<MetricStore> store, std::shared_ptr<ThreadPool> pool, std::uint16_t port, std::shared_ptr<AclEngine> acl, std::shared_ptr<DhcpServer> dhcp, std::shared_ptr<DnsServer> dns, std::shared_ptr<DnsZone> dns_zone, std::shared_ptr<SnmpPoller> snmp, std::shared_ptr<SnmpTrapReceiver> traps)
        : m_cache { cache }, m_store { store }, m_pool { pool }, m_acl { std::move(acl) }, m_dhcp { std::move(dhcp) }, m_dns { std::move(dns) }, m_dns_zone { std::move(dns_zone) }, m_snmp { std::move(snmp) }, m_snmp_traps { std::move(traps) }, m_port { port }
    {

    }

    CollectorServer::~CollectorServer()
    {

        if (m_running.load()) stop();

    }

    void CollectorServer::start()
    {

        if (m_running.exchange(true)) return;
        m_accept_thread = std::thread { [this] { accept_loop(); } };

    }

    void CollectorServer::stop()
    {

        m_running.store(false);

        // shutdown the listen socket to unblock the pending accept() call so the accept thread can exit
        if (m_listen_socket.is_valid()) ::shutdown(m_listen_socket.get(), SHUT_RDWR);
        if (m_accept_thread.joinable()) m_accept_thread.join();
        m_listen_socket.reset();

    }

    std::uint16_t CollectorServer::port() const
    {

        return m_port;

    }

    bool CollectorServer::is_running() const
    {

        return m_running.load();

    }

    void CollectorServer::accept_loop()
    {

        // create, configure, bind, and listen on the tcp socket
        int listen_fd { ::socket(AF_INET, SOCK_STREAM, 0) };
        if (listen_fd < 0)
        {
            std::println("error: failed to create listening socket");
            m_running.store(false);
            return;
        }

        int opt { 1 };
        ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        ::sockaddr_in addr { };
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ::htonl(INADDR_ANY);
        addr.sin_port = ::htons(m_port);

        if (::bind(listen_fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            std::println("error: failed to bind to port {}", m_port);
            ::close(listen_fd);
            m_running.store(false);
            return;
        }

        if (::listen(listen_fd, SOMAXCONN) < 0)
        {
            std::println("error: failed to listen on socket");
            ::close(listen_fd);
            m_running.store(false);
            return;
        }

        m_listen_socket.reset(listen_fd);
        std::println("collector listening on port {}", m_port);

        // accept connections and dispatch each read+parse to the worker pool
        while (m_running.load())
        {

            ::sockaddr_in client_addr { };
            ::socklen_t addr_len { sizeof(client_addr) };
            int client_fd { ::accept(listen_fd, reinterpret_cast<::sockaddr*>(&client_addr), &addr_len) };
            if (client_fd < 0)
            {
                if (m_running.load()) std::println("error: accept failed");
                continue;
            }

            m_pool->enqueue([this, client_fd]
            {

                // accumulate reads until we have the full http request (headers + content-length body)
                std::string request { };
                char chunk[4096] { };
                std::size_t body_start { std::string::npos };
                std::size_t content_length { 0 };
                while (true)
                {
                    ::ssize_t n { ::read(client_fd, chunk, sizeof(chunk)) };
                    if (n <= 0) break;
                    request.append(chunk, static_cast<std::size_t>(n));

                    // once we see the end-of-headers marker, parse content-length from the headers
                    if (body_start == std::string::npos)
                    {
                        auto idx { request.find("\r\n\r\n") };
                        if (idx != std::string::npos)
                        {
                            body_start = idx + 4;
                            std::string headers { request.substr(0, idx) };
                            auto cl_pos { headers.find("Content-Length:") };
                            if (cl_pos == std::string::npos) cl_pos = headers.find("content-length:");
                            if (cl_pos != std::string::npos)
                            {
                                auto val_start { cl_pos + std::string { "Content-Length:" }.size() };
                                while (val_start < headers.size() && headers[val_start] == ' ') ++val_start;
                                auto val_end { headers.find("\r\n", val_start) };
                                if (val_end == std::string::npos) val_end = headers.size();
                                content_length = std::stoul(headers.substr(val_start, val_end - val_start));
                            }
                        }
                    }

                    // exit once we've buffered the full body
                    if (body_start != std::string::npos && request.size() >= body_start + content_length) break;
                }

                // build the full http response (the dispatcher decides what to put in the body) and write it back
                std::string response { request.empty() ? std::string { "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" } : handle_request(request) };
                ::write(client_fd, response.data(), response.size());
                ::close(client_fd);

            });

        }

    }

    // small helper for building a complete http response with proper content-length
    namespace
    {

        std::string build_response(int status_code, const std::string& reason, const std::string& content_type, const std::string& body)
        {

            return std::format("HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status_code, reason, content_type, body.size(), body);

        }

    }

    std::string CollectorServer::handle_request(const std::string& raw_request)
    {

        // parse the request line so we can dispatch by method and path
        auto first_line_end { raw_request.find("\r\n") };
        std::string request_line { raw_request.substr(0, first_line_end == std::string::npos ? raw_request.size() : first_line_end) };
        auto sp1 { request_line.find(' ') };
        auto sp2 { sp1 == std::string::npos ? std::string::npos : request_line.find(' ', sp1 + 1) };
        std::string method { sp1 == std::string::npos ? std::string { } : request_line.substr(0, sp1) };
        std::string path { (sp1 == std::string::npos || sp2 == std::string::npos) ? std::string { } : request_line.substr(sp1 + 1, sp2 - sp1 - 1) };

        // GET /acl/rules returns a json snapshot of the acl engine
        if (method == "GET" && path == "/acl/rules") return build_response(200, "OK", "application/json", acl_snapshot_json());

        // GET /dhcp/leases returns a json snapshot of the dhcp server's totals + live lease table
        if (method == "GET" && path == "/dhcp/leases") return build_response(200, "OK", "application/json", dhcp_snapshot_json());

        // GET /dns/zone returns the dns server's counters + current zone entries
        if (method == "GET" && path == "/dns/zone") return build_response(200, "OK", "application/json", dns_snapshot_json());

        // GET /snmp/agents returns the snmp poller's per-target state
        if (method == "GET" && path == "/snmp/agents") return build_response(200, "OK", "application/json", snmp_snapshot_json());

        // GET /snmp/traps returns recent notification PDUs received on udp/162
        if (method == "GET" && path == "/snmp/traps") return build_response(200, "OK", "application/json", snmp_traps_json());

        // GET /healthz is a cheap liveness probe; no db touch, no acl touch
        if (method == "GET" && path == "/healthz") return build_response(200, "OK", "application/json", "{\"ok\":true}");

        // everything else is treated as the legacy metric push path; isolate the body and feed the cache
        auto header_end { raw_request.find("\r\n\r\n") };
        if (header_end == std::string::npos) return build_response(200, "OK", "text/plain", "");
        std::string body { raw_request.substr(header_end + 4) };
        if (body.empty()) return build_response(200, "OK", "text/plain", "");

        try
        {
            // declare-then-assign avoids nlohmann's initializer_list ctor wrapping a single value in an array
            ::nlohmann::json parsed { };
            parsed = ::nlohmann::json::parse(body);
            if (!parsed.is_object()) return build_response(400, "Bad Request", "text/plain", "expected json object");
            Metric metric { };
            metric.m_hostname = parsed.value("hostname", std::string { });
            metric.m_vendor = parsed.value("vendor", std::string { });
            metric.m_cpu = parsed.value("cpu", 0.0);
            metric.m_memory = parsed.value("memory", 0.0);
            metric.m_timestamp = std::chrono::system_clock::now();
            metric.m_payload = parsed;
            m_cache->update(metric);
            if (m_store) m_store->persist(metric);
        }
        catch (const ::nlohmann::json::exception& e)
        {
            std::println("error: failed to parse json: {}", e.what());
            return build_response(400, "Bad Request", "text/plain", "invalid json");
        }

        return build_response(200, "OK", "text/plain", "");

    }

    std::string CollectorServer::acl_snapshot_json() const
    {

        // when no engine is wired, return a well-formed empty payload so the dashboard can render an empty state
        if (!m_acl) return std::string { "{\"totals\":{\"evaluations\":0,\"permits\":0,\"denies\":0,\"implicit_denies\":0},\"rules\":[]}" };

        ::nlohmann::json out { };
        out["totals"]["evaluations"] = m_acl->total_evaluations();
        out["totals"]["permits"] = m_acl->total_permits();
        out["totals"]["denies"] = m_acl->total_denies();
        out["totals"]["implicit_denies"] = m_acl->implicit_denies();

        // direct copy-assignment (not brace-init) so nlohmann doesn't wrap the empty array in another array
        // via its initializer_list ctor
        ::nlohmann::json rules_arr = ::nlohmann::json::array();
        for (const auto& rule : m_acl->snapshot())
        {
            ::nlohmann::json r { };
            r["id"] = rule.m_id;
            r["action"] = rule.m_action;
            r["protocol"] = rule.m_protocol;
            r["src_cidr"] = rule.m_src_cidr;
            r["dst_cidr"] = rule.m_dst_cidr;
            r["src_ports"] = rule.m_src_ports;
            r["dst_ports"] = rule.m_dst_ports;
            r["description"] = rule.m_description;
            r["hits"] = rule.m_hits;
            rules_arr.push_back(r);
        }
        out["rules"] = rules_arr;
        return out.dump();

    }

    std::string CollectorServer::dhcp_snapshot_json() const
    {

        // empty payload when no server is wired so the dashboard renders cleanly during cold start
        if (!m_dhcp)
            return std::string { "{\"totals\":{\"discovers\":0,\"offers\":0,\"requests\":0,\"acks\":0,\"naks\":0,\"releases\":0,\"expired\":0,\"pool_total\":0,\"pool_free\":0,\"pool_in_use\":0},\"leases\":[]}" };

        ::nlohmann::json out { };
        out["totals"]["discovers"] = m_dhcp->discover_count();
        out["totals"]["offers"]    = m_dhcp->offer_count();
        out["totals"]["requests"]  = m_dhcp->request_count();
        out["totals"]["acks"]      = m_dhcp->ack_count();
        out["totals"]["naks"]      = m_dhcp->nak_count();
        out["totals"]["releases"]  = m_dhcp->release_count();
        out["totals"]["expired"]   = m_dhcp->expired_count();
        out["totals"]["pool_total"]  = m_dhcp->total_count();
        out["totals"]["pool_free"]   = m_dhcp->free_count();
        out["totals"]["pool_in_use"] = m_dhcp->in_use_count();

        // emit timestamps as epoch seconds so the dashboard can format them locally without parsing iso strings
        // direct copy-assignment so nlohmann's initializer_list ctor doesn't wrap the empty array
        ::nlohmann::json leases_arr = ::nlohmann::json::array();
        for (const auto& lease : m_dhcp->lease_snapshot())
        {
            ::nlohmann::json l { };
            l["mac"] = mac_to_string(lease.m_mac);
            l["ip"] = ipv4_to_dotted(lease.m_ip);
            l["state"] = to_string(lease.m_state);
            l["hostname"] = lease.m_hostname;
            l["granted_at"] = std::chrono::duration<double>(lease.m_granted_at.time_since_epoch()).count();
            l["expires_at"] = std::chrono::duration<double>(lease.m_expires_at.time_since_epoch()).count();
            leases_arr.push_back(l);
        }
        out["leases"] = leases_arr;
        return out.dump();

    }

    std::string CollectorServer::dns_snapshot_json() const
    {

        if (!m_dns && !m_dns_zone)
            return std::string { "{\"totals\":{\"queries\":0,\"noerror\":0,\"nxdomain\":0,\"refused\":0,\"notimpl\":0,\"formerr\":0},\"zone\":\"\",\"entries\":[]}" };

        ::nlohmann::json out { };
        if (m_dns)
        {
            out["totals"]["queries"]  = m_dns->query_count();
            out["totals"]["noerror"]  = m_dns->noerror_count();
            out["totals"]["nxdomain"] = m_dns->nxdomain_count();
            out["totals"]["refused"]  = m_dns->refused_count();
            out["totals"]["notimpl"]  = m_dns->notimpl_count();
            out["totals"]["formerr"]  = m_dns->formerr_count();
        }
        else
        {
            out["totals"]["queries"]  = 0;
            out["totals"]["noerror"]  = 0;
            out["totals"]["nxdomain"] = 0;
            out["totals"]["refused"]  = 0;
            out["totals"]["notimpl"]  = 0;
            out["totals"]["formerr"]  = 0;
        }

        out["zone"] = m_dns_zone ? m_dns_zone->suffix() : std::string { };

        ::nlohmann::json entries_arr = ::nlohmann::json::array();
        if (m_dns_zone)
        {
            for (const auto& e : m_dns_zone->snapshot())
            {
                ::nlohmann::json item { };
                item["fqdn"] = e.m_fqdn;
                item["ip"] = ipv4_to_dotted(e.m_ip);
                item["source"] = e.m_source;
                entries_arr.push_back(item);
            }
        }
        out["entries"] = entries_arr;

        return out.dump();

    }

    std::string CollectorServer::snmp_snapshot_json() const
    {

        if (!m_snmp)
            return std::string { "{\"totals\":{\"polls\":0,\"successes\":0,\"timeouts\":0,\"errors\":0},\"agents\":[]}" };

        ::nlohmann::json out { };
        out["totals"]["polls"]     = m_snmp->total_polls();
        out["totals"]["successes"] = m_snmp->total_successes();
        out["totals"]["timeouts"]  = m_snmp->total_timeouts();
        out["totals"]["errors"]    = m_snmp->total_errors();
        out["discovery_mode"]      = m_snmp->discovery_mode();

        ::nlohmann::json agents_arr = ::nlohmann::json::array();
        for (const auto& s : m_snmp->snapshot())
        {
            ::nlohmann::json a { };
            a["host"] = s.m_host;
            a["port"] = s.m_port;
            a["queries"] = s.m_queries;
            a["successes"] = s.m_successes;
            a["timeouts"] = s.m_timeouts;
            a["errors"] = s.m_errors;
            a["last_poll_epoch"] = std::chrono::duration<double>(s.m_last_poll.time_since_epoch()).count();
            a["last_latency_ms"] = s.m_last_latency_ms;
            a["sys_name"] = s.m_last_sys_name;
            a["uptime_ticks"] = s.m_last_uptime_ticks;
            a["cpu"] = s.m_last_cpu;
            a["memory"] = s.m_last_memory;
            a["walk_steps"] = s.m_last_walk_steps;

            ::nlohmann::json ifs_arr = ::nlohmann::json::array();
            for (const auto& row : s.m_interfaces)
            {
                ::nlohmann::json r { };
                r["ifIndex"] = row.m_index;
                r["ifDescr"] = row.m_descr;
                r["ifAdminStatus"] = row.m_admin_status;
                r["ifOperStatus"] = row.m_oper_status;
                r["ifInOctets"] = row.m_in_octets;
                r["ifOutOctets"] = row.m_out_octets;
                ifs_arr.push_back(r);
            }
            a["interfaces"] = ifs_arr;

            agents_arr.push_back(a);
        }
        out["agents"] = agents_arr;

        return out.dump();

    }

    std::string CollectorServer::snmp_traps_json() const
    {

        if (!m_snmp_traps)
            return std::string { "{\"totals\":{\"received\":0,\"dropped\":0},\"traps\":[]}" };

        ::nlohmann::json out { };
        out["totals"]["received"] = m_snmp_traps->received_count();
        out["totals"]["dropped"]  = m_snmp_traps->dropped_count();

        ::nlohmann::json traps_arr = ::nlohmann::json::array();
        for (const auto& t : m_snmp_traps->snapshot())
        {
            ::nlohmann::json r { };
            r["received_epoch"] = std::chrono::duration<double>(t.m_received_at.time_since_epoch()).count();
            r["source_ip"] = t.m_source_ip;
            r["community"] = t.m_community;
            r["uptime_ticks"] = t.m_uptime_ticks;
            r["event_oid"] = t.m_event_oid;
            r["extras"] = t.m_extras_str;
            traps_arr.push_back(r);
        }
        out["traps"] = traps_arr;

        return out.dump();

    }

}
