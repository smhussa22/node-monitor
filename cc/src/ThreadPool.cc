// related headers
#include "ThreadPool.hh"

// c sys headers

// cpp stdlib headers

// 3rd party headers

// project headers

namespace NodeMonitor
{

    ThreadPool::ThreadPool(std::size_t thread_count)
    {

    }

    ThreadPool::~ThreadPool()
    {

    }

    void ThreadPool::enqueue(std::function<void()> task)
    {

    }

    void ThreadPool::shutdown()
    {

    }

    std::size_t ThreadPool::worker_count() const
    {

        return std::size_t { 0 };

    }

    std::size_t ThreadPool::pending_count() const
    {

        return std::size_t { 0 };

    }

    void ThreadPool::worker_loop()
    {

    }

}
