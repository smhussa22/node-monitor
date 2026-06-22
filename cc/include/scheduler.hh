#ifndef NODE_MONITOR_SCHEDULER_HH
#define NODE_MONITOR_SCHEDULER_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // schedules and executes recurring tasks at fixed intervals on a background thread
    class Scheduler
    {

    public:

        Scheduler();
        ~Scheduler();

        Scheduler(const Scheduler&) = delete;
        Scheduler& operator=(const Scheduler&) = delete;

        // begin running scheduled tasks on a background thread
        void start();

        // stop the scheduler and join the background thread
        void stop();

        // register a recurring task to run every interval
        void schedule(std::function<void()> task, std::chrono::milliseconds interval);

        // number of registered recurring tasks
        std::size_t task_count() const;

    private:

        // a single recurring task and its cadence
        struct ScheduledTask
        {

            std::function<void()> m_callback { }; // function to execute on each tick
            std::chrono::milliseconds m_interval { }; // duration between executions
            std::chrono::steady_clock::time_point m_next_run { }; // wall time when this task should next fire

        };

        // body of the scheduler thread; sleeps and dispatches due tasks
        void run_loop();

        std::vector<ScheduledTask> m_tasks { }; // all registered recurring tasks
        std::thread m_thread { }; // background thread running the scheduler loop
        mutable std::mutex m_mutex { }; // protects m_tasks
        std::condition_variable m_condition { }; // wakes the scheduler on shutdown or when a new task is added
        std::atomic<bool> m_running { false }; // whether the loop should keep running

    };

}

#endif // NODE_MONITOR_SCHEDULER_HH
