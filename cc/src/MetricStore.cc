// related headers
#include "MetricStore.hh"

// c sys headers

// cpp stdlib headers
#include <print>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    MetricStore::MetricStore(const std::string& connection_string, std::size_t pool_size)
        : m_connection_string { connection_string }
    {

        // open pool_size connections eagerly so we surface configuration errors at startup, not on first request
        for (std::size_t i { 0 }; i < pool_size; ++i)
            m_pool.push_back(std::make_unique<::pqxx::connection>(m_connection_string));
        ensure_schema();
        std::println("metric store connected to postgres with pool size {}", pool_size);

    }

    MetricStore::~MetricStore()
    {

        // pqxx connections close themselves via RAII; the explicit clear just makes ordering visible
        std::lock_guard<std::mutex> lock { m_mutex };
        m_pool.clear();

    }

    void MetricStore::persist(const Metric& metric)
    {

        auto conn { acquire_connection() };
        try
        {
            ::pqxx::work tx { *conn };
            tx.exec(
                "INSERT INTO metrics (hostname, vendor, ts, cpu, memory, payload) "
                "VALUES ($1, $2, to_timestamp($3), $4, $5, $6::jsonb)",
                ::pqxx::params {
                    metric.m_hostname,
                    metric.m_vendor,
                    std::chrono::duration<double>(metric.m_timestamp.time_since_epoch()).count(),
                    metric.m_cpu,
                    metric.m_memory,
                    metric.m_payload.dump()
                }
            );
            tx.commit();
            m_insert_count.fetch_add(1uz);
        }
        catch (const ::pqxx::sql_error& e)
        {
            std::println("error: metric store insert failed: {} (sql: {})", e.what(), e.query());
        }
        catch (const std::exception& e)
        {
            std::println("error: metric store insert failed: {}", e.what());
        }
        release_connection(std::move(conn));

    }

    void MetricStore::persist_flow(const ::nlohmann::json& flow)
    {

        auto conn { acquire_connection() };
        try
        {
            ::pqxx::work tx { *conn };
            tx.exec(
                "INSERT INTO flows (src_ip, dst_ip, src_port, dst_port, protocol, bytes, duration, hostname) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                ::pqxx::params {
                    flow.value("src_ip", std::string { }),
                    flow.value("dst_ip", std::string { }),
                    flow.value("src_port", 0),
                    flow.value("dst_port", 0),
                    flow.value("protocol", std::string { }),
                    flow.value("bytes", std::int64_t { 0 }),
                    flow.value("duration", 0),
                    flow.value("hostname", std::string { })
                }
            );
            tx.commit();
            m_insert_count.fetch_add(1uz);
        }
        catch (const ::pqxx::sql_error& e)
        {
            std::println("error: flow insert failed: {} (sql: {})", e.what(), e.query());
        }
        catch (const std::exception& e)
        {
            std::println("error: flow insert failed: {}", e.what());
        }
        release_connection(std::move(conn));

    }

    std::vector<Metric> MetricStore::query(const std::string& hostname, std::chrono::system_clock::time_point start, std::chrono::system_clock::time_point end)
    {

        std::vector<Metric> results { };
        auto conn { acquire_connection() };
        try
        {
            ::pqxx::work tx { *conn };
            auto rows { tx.exec(
                "SELECT hostname, vendor, EXTRACT(EPOCH FROM ts) AS ts, cpu, memory, payload "
                "FROM metrics "
                "WHERE hostname = $1 AND ts BETWEEN to_timestamp($2) AND to_timestamp($3) "
                "ORDER BY ts DESC",
                ::pqxx::params {
                    hostname,
                    std::chrono::duration<double>(start.time_since_epoch()).count(),
                    std::chrono::duration<double>(end.time_since_epoch()).count()
                }
            ) };
            for (const auto& row : rows)
            {
                Metric m { };
                m.m_hostname = row["hostname"].as<std::string>();
                m.m_vendor = row["vendor"].as<std::string>();
                m.m_timestamp = std::chrono::system_clock::time_point { std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::duration<double> { row["ts"].as<double>() }) };
                m.m_cpu = row["cpu"].as<double>();
                m.m_memory = row["memory"].as<double>();
                m.m_payload = ::nlohmann::json::parse(row["payload"].as<std::string>());
                results.push_back(m);
            }
        }
        catch (const std::exception& e)
        {
            std::println("error: metric store query failed: {}", e.what());
        }
        release_connection(std::move(conn));
        return results;

    }

    std::uint64_t MetricStore::insert_count() const noexcept
    {

        return m_insert_count.load();

    }

    void MetricStore::record_incident(const std::string& rule_name, const std::string& hostname, const std::string& severity, std::chrono::system_clock::time_point fired_at, const ::nlohmann::json& details)
    {

        auto conn { acquire_connection() };
        try
        {
            ::pqxx::work tx { *conn };
            tx.exec(
                "INSERT INTO incidents (rule_name, hostname, severity, fired_at, details) "
                "VALUES ($1, $2, $3, to_timestamp($4), $5::jsonb)",
                ::pqxx::params {
                    rule_name,
                    hostname,
                    severity,
                    std::chrono::duration<double>(fired_at.time_since_epoch()).count(),
                    details.dump()
                }
            );
            tx.commit();
        }
        catch (const std::exception& e)
        {
            std::println("error: incident insert failed: {}", e.what());
        }
        release_connection(std::move(conn));

    }

    void MetricStore::record_action(const std::string& runbook_name, const std::string& rule_name, const std::string& hostname, const std::string& action_type, const std::string& target, const std::string& status, std::chrono::system_clock::time_point started_at, std::chrono::system_clock::time_point completed_at, const std::string& error_message, int response_code)
    {

        auto conn { acquire_connection() };
        try
        {
            ::pqxx::work tx { *conn };
            tx.exec(
                "INSERT INTO actions (runbook_name, rule_name, hostname, action_type, target, status, started_at, completed_at, error_message, response_code) "
                "VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), to_timestamp($8), $9, $10)",
                ::pqxx::params {
                    runbook_name,
                    rule_name,
                    hostname,
                    action_type,
                    target,
                    status,
                    std::chrono::duration<double>(started_at.time_since_epoch()).count(),
                    std::chrono::duration<double>(completed_at.time_since_epoch()).count(),
                    error_message,
                    response_code
                }
            );
            tx.commit();
        }
        catch (const std::exception& e)
        {
            std::println("error: action insert failed: {}", e.what());
        }
        release_connection(std::move(conn));

    }

    void MetricStore::resolve_incident(const std::string& rule_name, const std::string& hostname, std::chrono::system_clock::time_point resolved_at)
    {

        auto conn { acquire_connection() };
        try
        {
            ::pqxx::work tx { *conn };
            tx.exec(
                "UPDATE incidents SET resolved_at = to_timestamp($3) "
                "WHERE rule_name = $1 AND hostname = $2 AND resolved_at IS NULL",
                ::pqxx::params {
                    rule_name,
                    hostname,
                    std::chrono::duration<double>(resolved_at.time_since_epoch()).count()
                }
            );
            tx.commit();
        }
        catch (const std::exception& e)
        {
            std::println("error: incident resolve failed: {}", e.what());
        }
        release_connection(std::move(conn));

    }

    void MetricStore::ensure_schema()
    {

        auto conn { acquire_connection() };
        try
        {
            ::pqxx::work tx { *conn };
            tx.exec(
                "CREATE TABLE IF NOT EXISTS metrics ("
                "    id        BIGSERIAL   PRIMARY KEY,"
                "    hostname  TEXT        NOT NULL,"
                "    vendor    TEXT        NOT NULL,"
                "    ts        TIMESTAMPTZ NOT NULL,"
                "    cpu       DOUBLE PRECISION NOT NULL,"
                "    memory    DOUBLE PRECISION NOT NULL,"
                "    payload   JSONB       NOT NULL"
                ")"
            );
            tx.exec("CREATE INDEX IF NOT EXISTS idx_metrics_host_ts ON metrics (hostname, ts DESC)");
            tx.exec("CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics (ts DESC)");
            tx.exec(
                "CREATE TABLE IF NOT EXISTS incidents ("
                "    id          BIGSERIAL   PRIMARY KEY,"
                "    rule_name   TEXT        NOT NULL,"
                "    hostname    TEXT        NOT NULL,"
                "    severity    TEXT        NOT NULL,"
                "    fired_at    TIMESTAMPTZ NOT NULL,"
                "    resolved_at TIMESTAMPTZ,"
                "    details     JSONB       NOT NULL"
                ")"
            );
            tx.exec("CREATE INDEX IF NOT EXISTS idx_incidents_active ON incidents (rule_name, hostname) WHERE resolved_at IS NULL");
            tx.exec("CREATE INDEX IF NOT EXISTS idx_incidents_fired ON incidents (fired_at DESC)");
            tx.exec(
                "CREATE TABLE IF NOT EXISTS flows ("
                "    id           BIGSERIAL    PRIMARY KEY,"
                "    src_ip       TEXT         NOT NULL,"
                "    dst_ip       TEXT         NOT NULL,"
                "    src_port     INTEGER,"
                "    dst_port     INTEGER,"
                "    protocol     TEXT         NOT NULL,"
                "    bytes        BIGINT       NOT NULL,"
                "    duration     INTEGER,"
                "    hostname     TEXT         NOT NULL,"
                "    received_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()"
                ")"
            );
            tx.exec("CREATE INDEX IF NOT EXISTS idx_flows_received_at ON flows (received_at DESC)");
            tx.exec("CREATE INDEX IF NOT EXISTS idx_flows_dst_port    ON flows (dst_port)");
            tx.exec("CREATE INDEX IF NOT EXISTS idx_flows_src_dst     ON flows (src_ip, dst_ip)");
            tx.exec("CREATE INDEX IF NOT EXISTS idx_flows_hostname    ON flows (hostname)");
            tx.exec(
                "CREATE TABLE IF NOT EXISTS actions ("
                "    id            BIGSERIAL    PRIMARY KEY,"
                "    runbook_name  TEXT         NOT NULL,"
                "    rule_name     TEXT         NOT NULL,"
                "    hostname      TEXT         NOT NULL,"
                "    action_type   TEXT         NOT NULL,"
                "    target        TEXT         NOT NULL,"
                "    status        TEXT         NOT NULL,"
                "    started_at    TIMESTAMPTZ  NOT NULL,"
                "    completed_at  TIMESTAMPTZ,"
                "    error_message TEXT,"
                "    response_code INTEGER"
                ")"
            );
            tx.exec("CREATE INDEX IF NOT EXISTS idx_actions_runbook_host ON actions (runbook_name, hostname, started_at DESC)");
            tx.exec("CREATE INDEX IF NOT EXISTS idx_actions_status ON actions (status, started_at DESC)");
            tx.commit();
        }
        catch (const std::exception& e)
        {
            std::println("error: metric store schema setup failed: {}", e.what());
        }
        release_connection(std::move(conn));

    }

    std::unique_ptr<::pqxx::connection> MetricStore::acquire_connection()
    {

        std::unique_lock<std::mutex> lock { m_mutex };
        m_condition.wait(lock, [this] { return !m_pool.empty(); });
        auto conn { std::move(m_pool.back()) };
        m_pool.pop_back();
        return conn;

    }

    void MetricStore::release_connection(std::unique_ptr<::pqxx::connection> conn)
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        m_pool.push_back(std::move(conn));
        m_condition.notify_one();

    }

}
