#ifndef NODE_MONITOR_DHCP_LEASE_HH
#define NODE_MONITOR_DHCP_LEASE_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // lifecycle of a single dhcp lease as tracked by the server. Released and Expired are kept distinct
    // because they represent different operator-facing situations: Released means the client said goodbye,
    // Expired means the lease timed out without a renewal
    enum class DhcpLeaseState
    {

        Offered, // server replied with OFFER; awaiting a matching REQUEST before the binding is real
        Bound,   // client accepted; the ip is owned by this client until expiry
        Released, // client sent RELEASE; ip is back in the free pool
        Expired,  // lease deadline passed without a renewal; ip is back in the free pool

    };

    // stringify for logging and the actions / dashboard tables
    std::string to_string(DhcpLeaseState state);

    // one client's lease record. m_mac is the canonical key (packed 48-bit ethernet address); everything
    // else is metadata used either by the server itself or by the dashboard / store layer
    struct DhcpLease
    {

        std::uint64_t m_mac { 0 };                                 // packed 48-bit mac key
        std::uint32_t m_ip { 0 };                                  // assigned ipv4 in host byte order
        DhcpLeaseState m_state { DhcpLeaseState::Offered };        // see above
        std::chrono::system_clock::time_point m_granted_at { };    // wall clock when OFFER / ACK was sent
        std::chrono::system_clock::time_point m_expires_at { };    // wall clock when the lease times out
        std::string m_hostname { };                                // optional option-12 client hostname

    };

}

#endif // NODE_MONITOR_DHCP_LEASE_HH
