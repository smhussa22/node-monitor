// related headers
#include "Scheduler.hh"

// c sys headers

// cpp stdlib headers

// 3rd party headers

// project headers

namespace NodeMonitor
{

    Scheduler::~Scheduler()
    {

        if (m_running.load()) stop();

    }

    void Scheduler::start()
    {

        if (m_running.exchange(true)) return;
        m_thread = std::thread { [this] { run_loop(); } };

    }

    void Scheduler::stop()
    {

        m_running.store(false);
        m_condition.notify_all();
        if (m_thread.joinable()) m_thread.join();

    }

    void Scheduler::schedule(std::function<void()> task, std::chrono::milliseconds interval)
    {

        {
            std::lock_guard<std::mutex> lock { m_mutex };
            m_tasks.push_back(ScheduledTask { task, interval, std::chrono::steady_clock::now() });
        }
        m_condition.notify_all();

    }

    std::size_t Scheduler::task_count() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        return m_tasks.size();

    }

    void Scheduler::run_loop()
    {

        while (m_running.load())
        {

            // collect callbacks due now and reschedule their next run, then release the lock before invoking them
            std::vector<std::function<void()>> due_callbacks { };
            auto next_wake { std::chrono::steady_clock::time_point::max() };
            {
                std::lock_guard<std::mutex> lock { m_mutex };
                auto now { std::chrono::steady_clock::now() };
                for (auto& task : m_tasks)
                {
                    if (task.m_next_run <= now)
                    {
                        due_callbacks.push_back(task.m_callback);
                        task.m_next_run = now + task.m_interval;
                    }
                    if (task.m_next_run < next_wake) next_wake = task.m_next_run;
                }
            }

            // invoke due callbacks outside the lock so callbacks can safely call back into the scheduler
            for (const auto& cb : due_callbacks) cb();
            if (!m_running.load()) break;

            // sleep until the soonest task is due, or until stop()/schedule() wake us
            std::unique_lock<std::mutex> lock { m_mutex };
            m_condition.wait_until(lock, next_wake, [this] { return !m_running.load(); });

        }

    }

}
