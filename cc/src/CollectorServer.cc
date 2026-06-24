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
#include <print>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers
#include "Metric.hh"

namespace NodeMonitor
{

    CollectorServer::CollectorServer(std::shared_ptr<MetricCache> cache, std::shared_ptr<MetricStore> store, std::shared_ptr<ThreadPool> pool, std::uint16_t port)
        : m_cache { cache }, m_store { store }, m_pool { pool }, m_port { port }
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

                if (!request.empty()) handle_request(request);

                // send a minimal http 200 response so requests.post() returns cleanly on the python side
                const char* response { "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" };
                ::write(client_fd, response, ::strlen(response));
                ::close(client_fd);

            });

        }

    }

    void CollectorServer::handle_request(const std::string& raw_request)
    {

        // skip http headers and isolate the json body
        auto header_end { raw_request.find("\r\n\r\n") };
        if (header_end == std::string::npos) return;
        std::string body { raw_request.substr(header_end + 4) };
        if (body.empty()) return;

        // parse the json body and build a Metric snapshot for the cache
        try
        {
            // declare-then-assign avoids nlohmann's initializer_list ctor wrapping a single value in an array
            ::nlohmann::json parsed { };
            parsed = ::nlohmann::json::parse(body);
            if (!parsed.is_object()) return;
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
        }

    }

}
