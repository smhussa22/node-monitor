#ifndef NODE_MONITOR_THREAD_POOL_HH
#define NODE_MONITOR_THREAD_POOL_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // fixed-size pool of worker threads that consume tasks from a shared queue
    class ThreadPool
    {

    public:

        ThreadPool() = delete;
        explicit ThreadPool(std::size_t thread_count);
        ~ThreadPool();

        ThreadPool(const ThreadPool&) = delete;
        ThreadPool& operator=(const ThreadPool&) = delete;

        ThreadPool(ThreadPool&&) = delete;
        ThreadPool& operator=(ThreadPool&&) = delete;

        // submit a task to be executed by one of the worker threads
        void enqueue(std::function<void()> task);

        // signal all workers to drain and stop, then join them
        void shutdown();

        // number of worker threads in the pool
        std::size_t worker_count() const;

        // number of tasks currently waiting to be executed
        std::size_t pending_count() const;

    private:

        // body executed by each worker thread; pulls tasks until shutdown
        void worker_loop();

        std::vector<std::thread> m_workers { }; // pool of worker threads
        std::queue<std::function<void()>> m_tasks { }; // pending task queue
        mutable std::mutex m_mutex { }; // protects m_tasks and the stop flag
        std::condition_variable m_condition { }; // wakes workers when tasks are enqueued or on shutdown
        std::atomic<bool> m_stop { false }; // set to true to request worker termination

    };

}

#endif // NODE_MONITOR_THREAD_POOL_HH
