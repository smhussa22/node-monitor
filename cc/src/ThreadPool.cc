// related headers
#include "ThreadPool.hh"

// c sys headers

// cpp stdlib headers
#include <utility>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    ThreadPool::ThreadPool(std::size_t thread_count)
    {

        for (std::size_t i { 0 }; i < thread_count; ++i)
            m_workers.emplace_back([this] { worker_loop(); });

    }

    ThreadPool::~ThreadPool()
    {

        shutdown();

    }

    void ThreadPool::enqueue(std::function<void()> task)
    {

        {
            std::lock_guard<std::mutex> lock { m_mutex };
            m_tasks.push(std::move(task));
        }
        m_condition.notify_one();

    }

    void ThreadPool::shutdown()
    {

        {
            std::lock_guard<std::mutex> lock { m_mutex };
            m_stop.store(true);
        }
        m_condition.notify_all();
        for (auto& worker : m_workers) if (worker.joinable()) worker.join();
        m_workers.clear();

    }

    std::size_t ThreadPool::worker_count() const
    {

        return m_workers.size();

    }

    std::size_t ThreadPool::pending_count() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        return m_tasks.size();

    }

    void ThreadPool::worker_loop()
    {

        while (true)
        {

            std::function<void()> task { };
            {
                std::unique_lock<std::mutex> lock { m_mutex };
                m_condition.wait(lock, [this] { return m_stop.load() || !m_tasks.empty(); });
                if (m_stop.load() && m_tasks.empty()) return;
                task = std::move(m_tasks.front());
                m_tasks.pop();
            }
            task();

        }

    }

}
