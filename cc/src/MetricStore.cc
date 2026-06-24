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
