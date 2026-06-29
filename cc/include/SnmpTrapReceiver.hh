#ifndef NODE_MONITOR_SNMP_TRAP_RECEIVER_HH
#define NODE_MONITOR_SNMP_TRAP_RECEIVER_HH

// related headers
#include "AsnBer.hh"
#include "SocketFd.hh"

// c sys headers
#include <netinet/in.h>

// cpp stdlib headers
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // one decoded SNMPv2-Trap held in a bounded ring buffer for the dashboard. extras_str is a one-line
    // human-readable rendering of the trap's contextual varbinds so the dashboard doesn't have to walk
    // a typed payload to display them
    struct SnmpTrapRecord
    {

        std::chrono::system_clock::time_point m_received_at { }; // wall clock when the trap arrived
        std::string m_source_ip { };                             // dotted ip of the sender
        std::string m_community { };                             // community string the trap carried
        std::uint32_t m_uptime_ticks { 0 };                      // sysUpTime.0 carried as the first varbind
        std::string m_event_oid { };                             // snmpTrapOID.0 — what kind of trap this is
        std::string m_extras_str { };                            // joined "k=v" pairs from the remaining varbinds

    };

    // udp/162 listener that decodes incoming SNMPv2-Trap PDUs and stores the most recent N traps in a
    // ring buffer. silently drops anything that isn't a TrapV2 (unsupported PDU types or malformed input)
    class SnmpTrapReceiver
    {

    public:

        SnmpTrapReceiver() = delete;
        SnmpTrapReceiver(std::uint16_t port, std::size_t ring_capacity);
        ~SnmpTrapReceiver();

        SnmpTrapReceiver(const SnmpTrapReceiver&) = delete;
        SnmpTrapReceiver& operator=(const SnmpTrapReceiver&) = delete;
        SnmpTrapReceiver(SnmpTrapReceiver&&) = delete;
        SnmpTrapReceiver& operator=(SnmpTrapReceiver&&) = delete;

        void start();
        void stop();

        std::uint16_t port() const noexcept;
        bool is_running() const noexcept;

        std::uint64_t received_count() const noexcept;
        std::uint64_t dropped_count() const noexcept;

        // most recent traps in newest-first order
        std::vector<SnmpTrapRecord> snapshot() const;

    private:

        void receive_loop();

        std::uint16_t m_port { 162 };                       // udp port the receiver binds; standard 162
        std::size_t m_ring_capacity { 200uz };              // most-recent traps kept for the dashboard
        SocketFd m_socket { };                              // raii owned udp socket
        std::thread m_thread { };                           // receive loop thread
        std::atomic<bool> m_running { false };              // shared running flag

        mutable std::mutex m_mutex { };                     // guards m_ring
        std::deque<SnmpTrapRecord> m_ring { };              // newest at the back; drops front when full

        std::atomic<std::uint64_t> m_received { 0 };        // total decoded traps
        std::atomic<std::uint64_t> m_dropped { 0 };         // malformed / unsupported pdus

    };

}

#endif // NODE_MONITOR_SNMP_TRAP_RECEIVER_HH
